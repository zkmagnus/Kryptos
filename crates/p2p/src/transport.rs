//! Embedded Tor client, onion service, and bounded application framing.
//!
//! Production connections use Arti streams exclusively. The explicit memory
//! network used by tests is compiled only with `test-support` or unit tests.

use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use arti_client::config::{BoolOrAuto, TorClientConfigBuilder};
use arti_client::{BootstrapBehavior, DataStream, StreamPrefs, TorClient};
use futures_util::StreamExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{OnionServiceConfig, RunningOnionService};
use tor_proto::stream::IncomingStreamRequest;
use tor_rtcompat::PreferredRuntime;

use crate::address::NetAddr;
use crate::codec::frame;
use crate::message::{Message, MAX_MESSAGE_LEN};
use crate::{Error, Result};

/// Application handshake deadline, allowing for onion circuit latency.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);
/// Deadline to establish an isolated onion connection.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(120);
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(180);
// Arti allows five minutes for descriptor upload retries and fifteen minutes
// before declaring an introduction point persistently faulty. This startup
// watchdog must let those recovery mechanisms run before restarting a service.
const SERVICE_STARTUP_TIMEOUT: Duration = Duration::from_mins(20);
const INCOMING_CAPACITY: usize = 32;
const MAX_RENDEZVOUS: usize = 32;
const MAX_ACCEPTING: usize = 8;
const SERVICE_NICKNAME: &str = "rhombus";

type Client = TorClient<PreferredRuntime>;

/// Current readiness reported by the embedded client and onion service.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TorStatus {
    /// Arti currently has enough connectivity and directory information.
    pub client_ready: bool,
    /// Reachable local service identity, available only while service is ready.
    pub onion: Option<NetAddr>,
}

/// An accepted virtual-port stream from the onion service.
#[derive(Debug)]
pub struct Incoming {
    /// Onion virtual destination port; never a local socket port.
    pub port: u16,
    /// Accepted Tor stream.
    pub stream: Stream,
}

/// The single production transport, with explicit test streams in test builds.
#[derive(Debug)]
pub enum Stream {
    /// An authenticated, encrypted Tor onion-service stream.
    Tor(Box<DataStream>),
    /// Explicit in-memory fixture, unavailable in production builds.
    #[cfg(any(test, feature = "test-support"))]
    Memory(tokio::io::DuplexStream),
    /// Local RPC test fixture, unavailable in production builds.
    #[cfg(any(test, feature = "test-support"))]
    LocalFixture(tokio::net::TcpStream),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tor(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(any(test, feature = "test-support"))]
            Self::Memory(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(any(test, feature = "test-support"))]
            Self::LocalFixture(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tor(stream) => Pin::new(stream).poll_write(cx, bytes),
            #[cfg(any(test, feature = "test-support"))]
            Self::Memory(stream) => Pin::new(stream).poll_write(cx, bytes),
            #[cfg(any(test, feature = "test-support"))]
            Self::LocalFixture(stream) => Pin::new(stream).poll_write(cx, bytes),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tor(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(any(test, feature = "test-support"))]
            Self::Memory(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(any(test, feature = "test-support"))]
            Self::LocalFixture(stream) => Pin::new(stream).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tor(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(any(test, feature = "test-support"))]
            Self::Memory(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(any(test, feature = "test-support"))]
            Self::LocalFixture(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl From<tokio::net::TcpStream> for Stream {
    fn from(value: tokio::net::TcpStream) -> Self {
        Self::LocalFixture(value)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl From<tokio::io::DuplexStream> for Stream {
    fn from(value: tokio::io::DuplexStream) -> Self {
        Self::Memory(value)
    }
}

enum Backend {
    Arti(Arc<Client>),
    #[cfg(any(test, feature = "test-support"))]
    Memory(Arc<test_support::Route>),
}

/// Shared embedded Tor instance. Dropping its last owner stops its supervisor.
pub struct TorNetwork {
    backend: Backend,
    service: bool,
    status: watch::Sender<TorStatus>,
    supervisor: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for TorNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TorNetwork")
            .field("status", &*self.status.borrow())
            .finish_non_exhaustive()
    }
}

impl Drop for TorNetwork {
    fn drop(&mut self) {
        if let Some(task) = &self.supervisor {
            task.abort();
        }
    }
}

impl TorNetwork {
    /// Creates one embedded Tor client and starts API-based bootstrap monitoring.
    /// Persistent identity and cache live under `datadir/tor`. A fixed service
    /// nickname preserves its onion identity across restarts.
    ///
    /// # Errors
    /// Rejects unsafe storage permissions, invalid ports, or invalid Arti setup.
    pub fn start(
        datadir: &Path,
        service: bool,
        ports: &[u16],
    ) -> Result<(Arc<Self>, mpsc::Receiver<Incoming>)> {
        if ports.contains(&0) {
            return Err(Error::Tor("virtual ports must be nonzero".into()));
        }
        let root = datadir.join("tor");
        let mut mistrust = fs_mistrust::Mistrust::builder();
        mistrust.ignore_environment();
        let mistrust = mistrust.build().map_err(tor_error)?;
        mistrust.make_directory(&root).map_err(tor_error)?;
        let state = root.join("state");
        let cache = root.join("cache");
        mistrust.make_directory(&state).map_err(tor_error)?;
        mistrust.make_directory(&cache).map_err(tor_error)?;
        let mut config = TorClientConfigBuilder::from_directories(state, cache);
        config.storage().permissions().ignore_environment();
        config
            .vanguards()
            .mode(tor_config::ExplicitOrAuto::Explicit(
                tor_guardmgr::VanguardMode::Full,
            ));
        let client = TorClient::builder()
            .config(config.build().map_err(tor_error)?)
            .bootstrap_behavior(BootstrapBehavior::Manual)
            .create_unbootstrapped()
            .map_err(tor_error)?;
        let (incoming, receiver) = mpsc::channel(INCOMING_CAPACITY);
        let (status, _) = watch::channel(TorStatus::default());
        let supervisor = tokio::spawn(supervise(
            Arc::clone(&client),
            service,
            ports.to_vec(),
            incoming,
            status.clone(),
        ));
        Ok((
            Arc::new(Self {
                backend: Backend::Arti(client),
                service,
                status,
                supervisor: Some(supervisor),
            }),
            receiver,
        ))
    }

    /// Follows bootstrap and service reachability without parsing log messages.
    pub fn status(&self) -> watch::Receiver<TorStatus> {
        self.status.subscribe()
    }

    /// Whether this instance is ready to initiate application streams.
    pub fn ready(&self) -> bool {
        let status = *self.status.borrow();
        status.client_ready && (!self.service || status.onion.is_some())
    }

    /// Waits for startup readiness, bounded by the bootstrap deadline.
    ///
    /// # Errors
    /// Fails if the supervisor closes or startup exceeds its deadline.
    pub async fn wait_ready(&self) -> Result<()> {
        let mut status = self.status();
        tokio::time::timeout(BOOTSTRAP_TIMEOUT, async {
            loop {
                if self.ready() {
                    return Ok(());
                }
                status.changed().await.map_err(|_| Error::Closed)?;
            }
        })
        .await
        .map_err(|_| Error::Tor("embedded Tor startup timed out; supervisor will retry".into()))?
    }

    /// Opens an onion stream with a fresh circuit-isolation group.
    ///
    /// # Errors
    /// Rejects non-onion targets, self connections, unavailable Tor, or failed dials.
    pub async fn connect(&self, target: &str) -> Result<Stream> {
        let (address, port) = NetAddr::parse_endpoint(target)?;
        if !self.ready() {
            return Err(Error::Tor("embedded Tor is not ready".into()));
        }
        if self.status.borrow().onion == Some(address) {
            return Err(Error::Misbehavior("self connection"));
        }
        match &self.backend {
            Backend::Arti(client) => {
                let mut prefs = StreamPrefs::new();
                prefs
                    .new_isolation_group()
                    .connect_to_onion_services(BoolOrAuto::Explicit(true));
                let hostname = address.to_string();
                let connect = client.connect_with_prefs((hostname.as_str(), port), &prefs);
                tokio::pin!(connect);
                let mut status = self.status();
                tokio::time::timeout(CONNECT_TIMEOUT, async {
                    loop {
                        tokio::select! {
                            result = &mut connect => return result.map(|stream| Stream::Tor(Box::new(stream))).map_err(tor_error),
                            changed = status.changed() => {
                                changed.map_err(|_| Error::Closed)?;
                                if !self.ready() { return Err(Error::Tor("Tor readiness lost during dial".into())); }
                            }
                        }
                    }
                }).await.map_err(|_| Error::HandshakeTimeout)?
            }
            #[cfg(any(test, feature = "test-support"))]
            Backend::Memory(_) => test_support::connect(address, port),
        }
    }
}

fn tor_error(error: impl std::fmt::Display) -> Error {
    Error::Tor(error.to_string())
}

async fn supervise(
    client: Arc<Client>,
    service: bool,
    ports: Vec<u16>,
    incoming: mpsc::Sender<Incoming>,
    status: watch::Sender<TorStatus>,
) {
    let mut delay = Duration::from_secs(2);
    loop {
        status.send_replace(TorStatus::default());
        match tokio::time::timeout(BOOTSTRAP_TIMEOUT, client.bootstrap()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                eprintln!(
                    "embedded Tor bootstrap failed: {error}; status: {}; retrying in {delay:?}",
                    client.bootstrap_status()
                );
                tokio::time::sleep(delay).await;
                delay = delay.saturating_mul(2).min(Duration::from_secs(60));
                continue;
            }
            Err(_) => {
                eprintln!(
                    "embedded Tor bootstrap timed out; status: {}; retrying in {delay:?}",
                    client.bootstrap_status()
                );
                tokio::time::sleep(delay).await;
                delay = delay.saturating_mul(2).min(Duration::from_secs(60));
                continue;
            }
        }
        let result = if service {
            serve(&client, &ports, &incoming, &status).await
        } else {
            monitor_client(&client, &status).await;
            Ok(())
        };
        status.send_replace(TorStatus::default());
        if let Err(error) = result {
            eprintln!("embedded onion service unavailable: {error}; retrying in {delay:?}");
        }
        tokio::time::sleep(delay).await;
        delay = delay.saturating_mul(2).min(Duration::from_secs(60));
    }
}

async fn monitor_client(client: &Client, status: &watch::Sender<TorStatus>) {
    let mut events = client.bootstrap_events();
    let mut was_ready = client.bootstrap_status().ready_for_traffic();
    status.send_replace(TorStatus {
        client_ready: was_ready,
        onion: None,
    });
    while let Some(event) = events.next().await {
        let ready = event.ready_for_traffic();
        if was_ready && !ready {
            eprintln!("embedded Tor client lost readiness: {event}");
            break;
        }
        was_ready |= ready;
        status.send_replace(TorStatus {
            client_ready: ready,
            onion: None,
        });
    }
}

fn publish_status(
    client: &Client,
    service: &RunningOnionService,
    status: &watch::Sender<TorStatus>,
) {
    let client_ready = client.bootstrap_status().ready_for_traffic();
    let onion = if service_ready(client_ready, service.status().state()) {
        service
            .onion_address()
            .map(|id| NetAddr::TorV3(*id.as_ref()))
    } else {
        None
    };
    status.send_replace(TorStatus {
        client_ready,
        onion,
    });
}

// Arti's reachability predicate includes a published service whose redundant
// introduction points or HSDir uploads are partially unavailable. Requiring
// every upload to succeed would keep a reachable service offline indefinitely.
fn service_ready(client_ready: bool, state: tor_hsservice::status::State) -> bool {
    client_ready && state.is_fully_reachable()
}

/// Arti publishes `Shutdown` before its service tasks have initialized. Only
/// a shutdown after startup activity means an existing service has stopped.
#[derive(Default)]
struct ServiceLifecycle {
    started: bool,
}

impl ServiceLifecycle {
    fn stopped(&mut self, state: tor_hsservice::status::State) -> bool {
        use tor_hsservice::status::State;
        match state {
            State::Broken => true,
            State::Shutdown => self.started,
            _ => {
                self.started = true;
                false
            }
        }
    }
}

async fn serve(
    client: &Client,
    ports: &[u16],
    incoming: &mpsc::Sender<Incoming>,
    status: &watch::Sender<TorStatus>,
) -> Result<()> {
    let config = OnionServiceConfig::builder()
        .nickname(SERVICE_NICKNAME.parse().map_err(tor_error)?)
        .max_concurrent_streams_per_circuit(8)
        .build()
        .map_err(tor_error)?;
    let Some((service, requests)) = client.launch_onion_service(config).map_err(tor_error)? else {
        return Err(Error::Tor("onion service is disabled".into()));
    };
    let mut bootstrap = client.bootstrap_events();
    let mut changes = service.status_events();
    tokio::pin!(requests);
    let mut circuits = JoinSet::new();
    let accepting = Arc::new(Semaphore::new(MAX_ACCEPTING));
    let mut limit = Admission::new(Instant::now());
    let stream_limit = Arc::new(Mutex::new(Admission::new(Instant::now())));
    let mut lifecycle = ServiceLifecycle::default();
    let mut was_ready = client.bootstrap_status().ready_for_traffic();
    let initial = service.status();
    if lifecycle.stopped(initial.state()) {
        return Err(Error::Tor(format!(
            "onion service failed at startup: {:?}; problem: {:?}",
            initial.state(),
            initial.current_problem()
        )));
    }
    publish_status(client, &service, status);
    let startup_deadline = tokio::time::sleep(SERVICE_STARTUP_TIMEOUT);
    tokio::pin!(startup_deadline);
    let mut became_ready = status.borrow().onion.is_some();
    let failure = loop {
        tokio::select! {
            () = &mut startup_deadline, if !became_ready => {
                let service_status = service.status();
                break Error::Tor(format!("onion service startup timed out: client {}; service {service_status:?}", client.bootstrap_status()));
            }
            change = bootstrap.next() => {
                let Some(change) = change else { break Error::Tor("client bootstrap status stream ended".into()); };
                let ready = change.ready_for_traffic();
                if was_ready && !ready { break Error::Tor(format!("client lost bootstrap readiness: {change}")); }
                was_ready |= ready;
                publish_status(client, &service, status);
                became_ready |= status.borrow().onion.is_some();
            }
            change = changes.next() => {
                let Some(change) = change else { break Error::Tor("onion service status stream ended".into()); };
                if lifecycle.stopped(change.state()) {
                    break Error::Tor(format!("onion service stopped: {:?}; problem: {:?}", change.state(), change.current_problem()));
                }
                publish_status(client, &service, status);
                became_ready |= status.borrow().onion.is_some();
            }
            Some(_) = circuits.join_next(), if !circuits.is_empty() => {}
            request = requests.next() => {
                let Some(request) = request else { break Error::Tor("onion rendezvous request stream ended".into()); };
                if circuits.len() >= MAX_RENDEZVOUS || !limit.allow(Instant::now()) { continue; }
                let Ok(permit) = Arc::clone(&accepting).try_acquire_owned() else { continue; };
                let ports = ports.to_vec();
                let incoming = incoming.clone();
                let stream_limit = Arc::clone(&stream_limit);
                let accepting = Arc::clone(&accepting);
                circuits.spawn(async move {
                    let accepted = tokio::time::timeout(HANDSHAKE_TIMEOUT, request.accept()).await;
                    drop(permit);
                    let Ok(Ok(mut streams)) = accepted else { return; };
                    while let Ok(Some(request)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, streams.next()).await {
                        let IncomingStreamRequest::Begin(begin) = request.request() else { continue; };
                        let port = begin.port();
                        if !ports.contains(&port) { continue; }
                        let allowed = stream_limit.lock().is_ok_and(|mut limit| limit.allow(Instant::now()));
                        if !allowed { continue; }
                        let Ok(slot) = incoming.try_reserve() else { continue; };
                        let Ok(_accept_permit) = Arc::clone(&accepting).try_acquire_owned() else { continue; };
                        if let Ok(Ok(stream)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, request.accept(Connected::new_empty())).await {
                            slot.send(Incoming { port, stream: Stream::Tor(Box::new(stream)) });
                        }
                    }
                });
            }
        }
    };
    Err(failure)
}

/// Conservative admission bucket used while experimental Tor proof of work is disabled.
/// Permits two openings per second, with an initial burst of eight.
#[derive(Debug)]
struct Admission {
    tokens: u32,
    last: Instant,
}
impl Admission {
    fn new(now: Instant) -> Self {
        Self {
            tokens: 8,
            last: now,
        }
    }
    fn allow(&mut self, now: Instant) -> bool {
        let steps = now.saturating_duration_since(self.last).as_millis() / 500;
        if steps > 0 {
            self.tokens = self
                .tokens
                .saturating_add(u32::try_from(steps).unwrap_or(u32::MAX))
                .min(8);
            self.last = now;
        }
        if let Some(tokens) = self.tokens.checked_sub(1) {
            self.tokens = tokens;
            true
        } else {
            false
        }
    }
}

/// Sending half of a framed application stream.
#[derive(Debug)]
pub struct ConnectionWriter {
    stream: tokio::io::WriteHalf<Stream>,
}
/// Receiving half of a framed application stream.
#[derive(Debug)]
pub struct ConnectionReader {
    stream: tokio::io::ReadHalf<Stream>,
}

/// Splits a Tor stream into bounded framed application halves.
pub fn split(stream: impl Into<Stream>) -> (ConnectionWriter, ConnectionReader) {
    let (reader, writer) = tokio::io::split(stream.into());
    (
        ConnectionWriter { stream: writer },
        ConnectionReader { stream: reader },
    )
}

impl ConnectionWriter {
    /// Sends and flushes one bounded message.
    ///
    /// # Errors
    /// Fails on an oversized message or stream error.
    pub async fn send(&mut self, message: &Message) -> Result<()> {
        let wire = frame(message);
        if wire.len() > MAX_MESSAGE_LEN.saturating_add(4) {
            return Err(Error::TooLarge(wire.len()));
        }
        self.stream.write_all(&wire).await?;
        self.stream.flush().await?;
        Ok(())
    }
}
impl ConnectionReader {
    /// Receives one frame, validating its size before allocation.
    ///
    /// # Errors
    /// Fails on EOF, invalid framing, oversized data, or stream errors.
    pub async fn recv(&mut self) -> Result<Message> {
        let mut prefix = [0u8; 4];
        self.stream.read_exact(&mut prefix).await?;
        let len =
            usize::try_from(u32::from_le_bytes(prefix)).map_err(|_| Error::TooLarge(usize::MAX))?;
        if len > MAX_MESSAGE_LEN {
            return Err(Error::TooLarge(len));
        }
        let mut bytes = vec![0u8; len];
        self.stream.read_exact(&mut bytes).await?;
        Message::decode(&bytes)
    }
}

/// Connects to an explicitly local RPC test listener.
///
/// # Errors
/// Rejects non-loopback addresses and connection failures.
#[cfg(any(test, feature = "test-support"))]
pub async fn connect_loopback_for_tests(
    address: std::net::SocketAddr,
) -> Result<tokio::net::TcpStream> {
    if address.ip() != std::net::Ipv4Addr::LOCALHOST {
        return Err(Error::BadAddress("test socket must use IPv4 loopback"));
    }
    Ok(tokio::net::TcpStream::connect(address).await?)
}

/// Explicit in-memory network fixtures, never selected by production startup.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::{
        mpsc, watch, Arc, Backend, Error, Incoming, NetAddr, Result, Stream, TorNetwork, TorStatus,
        INCOMING_CAPACITY,
    };
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock, Weak};

    static ROUTES: OnceLock<Mutex<HashMap<NetAddr, Weak<Route>>>> = OnceLock::new();
    pub(super) struct Route {
        identity: NetAddr,
        ports: Vec<u16>,
        incoming: mpsc::Sender<Incoming>,
        status: watch::Sender<TorStatus>,
    }

    /// Creates an explicitly isolated in-memory onion fixture.
    pub fn network(
        identity: NetAddr,
        ports: &[u16],
    ) -> (Arc<TorNetwork>, mpsc::Receiver<Incoming>) {
        let (incoming, receiver) = mpsc::channel(INCOMING_CAPACITY);
        let (status, _) = watch::channel(TorStatus {
            client_ready: true,
            onion: Some(identity),
        });
        let route = Arc::new(Route {
            identity,
            ports: ports.to_vec(),
            incoming,
            status: status.clone(),
        });
        if let Ok(mut routes) = ROUTES.get_or_init(Mutex::default).lock() {
            routes.insert(identity, Arc::downgrade(&route));
        }
        (
            Arc::new(TorNetwork {
                backend: Backend::Memory(route),
                service: true,
                status,
                supervisor: None,
            }),
            receiver,
        )
    }

    /// Simulates loss or restoration of Tor readiness in an explicit fixture.
    pub fn set_ready(network: &TorNetwork, ready: bool) {
        if let Backend::Memory(route) = &network.backend {
            network.status.send_replace(TorStatus {
                client_ready: ready,
                onion: ready.then_some(route.identity),
            });
        }
    }

    pub(super) fn connect(identity: NetAddr, port: u16) -> Result<Stream> {
        let route = ROUTES
            .get_or_init(Mutex::default)
            .lock()
            .map_err(|_| Error::Closed)?
            .get(&identity)
            .and_then(Weak::upgrade)
            .ok_or(Error::Closed)?;
        if !route.ports.contains(&port) || !route.status.borrow().client_ready {
            return Err(Error::Closed);
        }
        let (client, server) = tokio::io::duplex(64 * 1024);
        route
            .incoming
            .try_send(Incoming {
                port,
                stream: Stream::Memory(server),
            })
            .map_err(|_| Error::Closed)?;
        Ok(Stream::Memory(client))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_readiness_requires_bootstrap_and_reachable_publication() {
        use tor_hsservice::status::State;
        for state in [State::Running, State::DegradedReachable] {
            assert!(service_ready(true, state));
            assert!(!service_ready(false, state));
        }
        for state in [
            State::Shutdown,
            State::Bootstrapping,
            State::DegradedUnreachable,
            State::Recovering,
            State::Broken,
        ] {
            assert!(!service_ready(true, state));
            assert!(!service_ready(false, state));
        }
    }

    #[test]
    fn service_initial_shutdown_does_not_cancel_startup() {
        use tor_hsservice::status::State;
        let mut lifecycle = ServiceLifecycle::default();
        for state in [
            State::Shutdown,
            State::Shutdown,
            State::Bootstrapping,
            State::Running,
            State::Recovering,
            State::Running,
        ] {
            assert!(!lifecycle.stopped(state), "premature restart at {state:?}");
        }
        assert!(lifecycle.stopped(State::Shutdown));
        assert!(ServiceLifecycle::default().stopped(State::Broken));
        let mut failed_start = ServiceLifecycle::default();
        assert!(!failed_start.stopped(State::Bootstrapping));
        assert!(failed_start.stopped(State::Shutdown));
    }

    #[test]
    fn admission_bounds_bursts_and_refills() {
        let now = Instant::now();
        let mut admission = Admission::new(now);
        for _ in 0..8 {
            assert!(admission.allow(now));
        }
        assert!(!admission.allow(now));
        assert!(!admission.allow(now + Duration::from_millis(499)));
        assert!(admission.allow(now + Duration::from_millis(500)));
        assert!(!admission.allow(now + Duration::from_millis(500)));
    }

    #[tokio::test]
    async fn memory_network_fails_closed_and_routes_ports() {
        let (alice, _) = test_support::network(NetAddr::TorV3([101; 32]), &[19000]);
        let (bob, mut incoming) = test_support::network(NetAddr::TorV3([102; 32]), &[19000]);
        let target = NetAddr::TorV3([102; 32]).endpoint(19000);
        assert!(alice.connect("127.0.0.1:19000").await.is_err());
        assert!(alice
            .connect(&NetAddr::TorV3([101; 32]).endpoint(19000))
            .await
            .is_err());
        test_support::set_ready(&bob, false);
        assert!(alice.connect(&target).await.is_err());
        test_support::set_ready(&bob, true);
        let client = alice.connect(&target).await.unwrap();
        let server = incoming.recv().await.unwrap();
        assert_eq!(server.port, 19000);
        let (mut writer, _) = split(client);
        let (_, mut reader) = split(server.stream);
        writer.send(&Message::Ping(123)).await.unwrap();
        assert_eq!(reader.recv().await.unwrap(), Message::Ping(123));
    }

    #[tokio::test]
    async fn frame_bound_is_checked_before_allocation() {
        let (mut client, server) = tokio::io::duplex(64);
        let (_, mut reader) = split(server);
        client.write_all(&u32::MAX.to_le_bytes()).await.unwrap();
        assert!(matches!(reader.recv().await, Err(Error::TooLarge(_))));
    }
}
