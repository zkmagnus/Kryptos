//! The local control socket: one request per line, one reply per line.
//! A session must start by presenting the node's token; anything else
//! before that is refused, and three refusals close the connection.
//!
//! ```text
//! auth <token>           -> ok | err unauthorized
//! status                 -> ok height=<h> hash=<hex> peers=<n> mempool=<n> mined=<n> in_chain=<n> syncing=<bool>
//! block <height>         -> ok <hex> | err not found
//! compact <height>       -> ok <hex> | err not found
//! hash <height>          -> ok <hex> | err not found
//! submit <hex tx> -> ok <txid hex> | err <reason>
//! txstatus <hex txid>    -> ok unknown | ok pooled | ok confirmed <height> <index>
//! spent <hex nullifier>  -> ok true | ok false
//! ```
//!
//! The token is a random 32-byte hex string the node generates on first
//! startup and persists in `rpc.token` in its data directory. Later starts
//! reuse the file unless a token is explicitly given with `--rpc-token`.
//! It is a shared secret, compared in constant
//! time. Optional local RPC listeners bind only to IPv4 localhost; remote
//! requests arrive directly on streams accepted by the embedded onion service.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crypto::encoding::{from_hex, to_hex};
use p2p::transport::{Stream, TorNetwork};
use protocol::bytes::Encodable;
use protocol::nullifier::Nullifier;
use protocol::transaction::{Transaction, TxId};
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, Semaphore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::node::{Event, Request, Response, TxStatus};
use crate::{Error, Result};

/// File name of the token in a node's data directory.
pub const TOKEN_FILE: &str = "rpc.token";
/// How long a client waits for one reply before giving up.
const CALL_TIMEOUT: Duration = Duration::from_secs(120);
/// Largest reply a client will buffer. A full block's hex is tens of
/// megabytes; past this the node is misbehaving and the client bails
/// rather than allocating without bound.
const MAX_REPLY_BYTES: usize = 128 * 1024 * 1024;
/// Longest token accepted, in bytes.
pub const MAX_TOKEN_LEN: usize = 128;
/// Refusals before a session is closed.
const MAX_REFUSALS: u32 = 3;
/// Bytes of randomness in a generated token.
const TOKEN_RANDOM_BYTES: usize = 32;
/// The reply to a request without a valid token.
const UNAUTHORIZED: &str = "err unauthorized";

/// The shared secret a client must present first.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Token(Vec<u8>);

impl core::fmt::Debug for Token {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Token(<secret>)")
    }
}

impl Token {
    /// A fresh random token: 32 bytes as hex.
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut bytes = [0u8; TOKEN_RANDOM_BYTES];
        rng.fill_bytes(&mut bytes);
        Self(to_hex(&bytes).into_bytes())
    }

    /// A token from its text: non-empty, at most [`MAX_TOKEN_LEN`] bytes,
    /// no whitespace, since a line carries it.
    ///
    /// # Errors
    /// Returns [`Error::Argument`] for an unusable token.
    pub fn new(text: &str) -> Result<Self> {
        let text = text.trim();
        if text.is_empty() || text.len() > MAX_TOKEN_LEN || text.contains(char::is_whitespace) {
            return Err(Error::Argument(
                "token must be 1 to 128 bytes without whitespace".into(),
            ));
        }
        Ok(Self(text.as_bytes().to_vec()))
    }

    /// Reads a token file, ignoring surrounding whitespace.
    ///
    /// # Errors
    /// Fails if the file cannot be read or holds an unusable token.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        Self::new(&std::fs::read_to_string(path)?)
    }

    /// Writes the token to `path`, readable only by the owner on Unix.
    ///
    /// # Errors
    /// Fails if the file cannot be written.
    pub fn write_to(&self, path: impl AsRef<Path>) -> Result<()> {
        crate::paths::write_private(path.as_ref(), self.expose().as_bytes())
    }

    /// The token text, for writing it out or presenting it.
    pub fn expose(&self) -> &str {
        // Only constructed from `str`, so this cannot fail.
        core::str::from_utf8(&self.0).unwrap_or_default()
    }

    /// Whether `presented` is this token, in time independent of where
    /// they differ.
    #[must_use]
    pub fn matches(&self, presented: &str) -> bool {
        self.0.ct_eq(presented.as_bytes()).into()
    }
}

/// Binds a local RPC endpoint after enforcing the loopback-only boundary.
///
/// # Errors
/// Rejects any address other than IPv4 localhost or a failed bind.
pub async fn bind_local(addr: SocketAddr) -> Result<TcpListener> {
    if addr.ip() != std::net::IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return Err(Error::Argument("local RPC must bind to 127.0.0.1".into()));
    }
    Ok(TcpListener::bind(addr).await?)
}

/// Serves requests forever, each session behind the token.
pub async fn serve(listener: TcpListener, events: mpsc::Sender<Event>, token: Token) {
    let slots = Arc::new(Semaphore::new(32));
    while let Ok((stream, _)) = listener.accept().await {
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let events = events.clone();
        let token = token.clone();
        tokio::spawn(async move {
            let _permit = permit;
            serve_stream(stream, events, token).await;
        });
    }
}

/// What a session does with one line before it reaches the node.
enum Gate {
    /// The line is a request to dispatch.
    Pass,
    /// Reply with this and continue.
    Reply(&'static str),
    /// Reply with this and close.
    Close(&'static str),
}

/// Per-session token state.
struct Auth {
    token: Token,
    authorized: bool,
    refusals: u32,
}

impl Auth {
    fn new(token: Token) -> Self {
        Self {
            token,
            authorized: false,
            refusals: 0,
        }
    }

    /// Handles `auth` lines and refuses everything else until one
    /// succeeded.
    fn gate(&mut self, line: &str) -> Gate {
        if let Some(presented) = line.strip_prefix("auth ") {
            if self.token.matches(presented.trim()) {
                self.authorized = true;
                return Gate::Reply("ok");
            }
            return self.refuse();
        }
        if self.authorized {
            Gate::Pass
        } else {
            self.refuse()
        }
    }

    fn refuse(&mut self) -> Gate {
        self.refusals = self.refusals.saturating_add(1);
        if self.refusals >= MAX_REFUSALS {
            Gate::Close(UNAUTHORIZED)
        } else {
            Gate::Reply(UNAUTHORIZED)
        }
    }
}

/// Serves one authenticated control connection over an already accepted stream.
pub async fn serve_stream<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    events: mpsc::Sender<Event>,
    token: Token,
) {
    let (read, mut write) = tokio::io::split(stream);
    let mut reader = BufReader::new(read);
    let mut auth = Auth::new(token);
    loop {
        let limit = if auth.authorized {
            32 * 1024 * 1024
        } else {
            256
        };
        let Ok(Ok(Some(line))) = tokio::time::timeout(
            Duration::from_secs(30),
            read_bounded_line(&mut reader, limit),
        )
        .await
        else {
            break;
        };
        let (reply, close) = match auth.gate(&line) {
            Gate::Pass => (answer(&events, &line).await, false),
            Gate::Reply(text) => (text.to_string(), false),
            Gate::Close(text) => (text.to_string(), true),
        };
        if !matches!(
            tokio::time::timeout(CALL_TIMEOUT, async {
                write.write_all(format!("{reply}\n").as_bytes()).await?;
                write.flush().await
            })
            .await,
            Ok(Ok(()))
        ) || close
        {
            break;
        }
    }
}

/// Reads at most `limit` bytes, rejecting an unfinished or oversized line.
async fn read_bounded_line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> std::io::Result<Option<String>> {
    let mut bytes = Vec::new();
    let max_read = u64::try_from(limit)
        .ok()
        .and_then(|limit| limit.checked_add(1))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "RPC line limit is too large",
            )
        })?;
    reader.take(max_read).read_until(b'\n', &mut bytes).await?;
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() > limit || !bytes.ends_with(b"\n") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "RPC line too large or incomplete",
        ));
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Parses, dispatches and formats one authorized request line.
async fn answer(events: &mpsc::Sender<Event>, line: &str) -> String {
    match parse(line) {
        Ok(request) => match dispatch(events, request).await {
            Ok(response) => format(&response),
            Err(error) => format!("err {error}"),
        },
        Err(error) => format!("err {error}"),
    }
}

async fn dispatch(events: &mpsc::Sender<Event>, request: Request) -> Result<Response> {
    let (reply, response) = oneshot::channel();
    events
        .send(Event::Rpc { request, reply })
        .await
        .map_err(|_| Error::Stopped)?;
    response.await.map_err(|_| Error::Stopped)
}

/// Parses one request line.
///
/// # Errors
/// Returns [`Error::Argument`] on an unknown command or bad argument.
pub fn parse(line: &str) -> Result<Request> {
    let mut words = line.split_whitespace();
    let command = words.next().unwrap_or_default();
    let argument = words.next().unwrap_or_default();
    match command {
        "status" => Ok(Request::Status),
        "block" => argument
            .parse()
            .map(Request::Block)
            .map_err(|_| Error::Argument("height".into())),
        "compact" => argument
            .parse()
            .map(Request::Compact)
            .map_err(|_| Error::Argument("height".into())),
        "hash" => argument
            .parse()
            .map(Request::Hash)
            .map_err(|_| Error::Argument("height".into())),
        "coinbase" => argument
            .parse()
            .map(Request::Coinbase)
            .map_err(|_| Error::Argument("height".into())),
        "submit" => {
            let bytes = from_hex(argument)?;
            let tx = Box::new(Transaction::from_slice(&bytes)?);
            Ok(Request::Submit(tx))
        }
        "txstatus" => {
            let bytes = from_hex(argument)?
                .try_into()
                .map_err(|_| Error::Argument("transaction id".into()))?;
            Ok(Request::TransactionStatus(TxId::from_bytes(bytes)))
        }
        "spent" => {
            let bytes: [u8; 32] = from_hex(argument)?
                .try_into()
                .map_err(|_| Error::Argument("nullifier".into()))?;
            Ok(Request::IsSpent(Nullifier::from_bytes(&bytes)?))
        }
        other => Err(Error::Argument(format!("unknown command {other}"))),
    }
}

/// Formats one reply line.
pub fn format(response: &Response) -> String {
    match response {
        Response::Status {
            height,
            hash,
            peers,
            mempool,
            mined,
            mined_in_chain,
            syncing,
        } => {
            format!(
                "ok height={height} hash={hash} peers={peers} mempool={mempool} \
                 mined={mined} in_chain={mined_in_chain} syncing={syncing}"
            )
        }
        Response::Block(Some(block)) => format!("ok {}", to_hex(&block.to_vec())),
        Response::Compact(Some(block)) => format!("ok {}", to_hex(&block.to_vec())),
        Response::Hash(Some(hash)) => format!("ok {}", to_hex(hash.as_bytes())),
        Response::Coinbase(Some(tx)) => format!("ok {}", to_hex(&tx.to_vec())),
        Response::Block(None)
        | Response::Compact(None)
        | Response::Hash(None)
        | Response::Coinbase(None) => "err not found".into(),
        Response::Submitted(txid) => format!("ok {txid}"),
        Response::TransactionStatus(TxStatus::Unknown) => "ok unknown".into(),
        Response::TransactionStatus(TxStatus::Pooled) => "ok pooled".into(),
        Response::TransactionStatus(TxStatus::Confirmed { height, index }) => {
            format!("ok confirmed {height} {index}")
        }
        Response::Spent(spent) => format!("ok {spent}"),
        Response::MiningReadiness(None) => "ok ready".into(),
        Response::MiningReadiness(Some(reason)) => format!("ok waiting {reason}"),
        Response::Metrics(metrics) => {
            format!("ok {}", crate::metrics::render(metrics).replace('\n', " "))
        }
        Response::Failed(reason) => format!("err {reason}"),
        Response::Stopping => "ok stopping".into(),
        // Reachable only over JSON-RPC; the line protocol has no request
        // that yields them.
        Response::Transaction(_)
        | Response::Txids(_)
        | Response::Peers(_)
        | Response::BlockSubmitted(_)
        | Response::MiningInfo(_) => "err unsupported".into(),
    }
}

/// Where a node's onion control service is and how to unlock it.
#[derive(Clone, Debug)]
pub struct Endpoint {
    /// The validated onion-service address, as `<v3 hostname>.onion:port`.
    pub addr: String,
    /// The node's token.
    pub token: Token,
    /// Shared embedded Tor client for this application.
    pub network: Arc<TorNetwork>,
}

/// A node reached over an onion stream or through its in-process event channel.
#[derive(Clone)]
pub enum Source {
    /// An authenticated remote onion control service.
    Remote(Endpoint),
    /// A node owned by the same application.
    Embedded(mpsc::Sender<Event>),
}

impl Source {
    /// Opens a connection without a socket for an embedded node.
    ///
    /// # Errors
    /// Fails if a remote endpoint cannot be reached or authenticated.
    pub async fn connect(&self) -> Result<Connection> {
        match self {
            Self::Remote(endpoint) => Ok(Connection::Remote(endpoint.connect().await?)),
            Self::Embedded(events) => Ok(Connection::Embedded(events.clone())),
        }
    }
}

/// The wallet's control interface, independent of transport.
pub trait Control: Send {
    /// Sends a control command and returns its result without framing.
    fn call(&mut self, line: &str) -> impl std::future::Future<Output = Result<String>> + Send;

    /// Ends a download session before private wallet processing. In-process
    /// sources need no transport shutdown; socket implementations send EOF.
    fn close(&mut self) -> impl std::future::Future<Output = Result<()>> + Send {
        async { Ok(()) }
    }
}

/// Looks up a transaction on the node's current chain or in its mempool.
///
/// # Errors
/// Fails on a transport error or a malformed status reply.
pub async fn transaction_status(client: &mut impl Control, txid: TxId) -> Result<TxStatus> {
    let reply = client.call(&format!("txstatus {txid}")).await?;
    let words: Vec<_> = reply.split_whitespace().collect();
    match words.as_slice() {
        ["unknown"] => Ok(TxStatus::Unknown),
        ["pooled"] => Ok(TxStatus::Pooled),
        ["confirmed", height, index] => {
            let malformed = |_| Error::Argument("bad transaction status".into());
            Ok(TxStatus::Confirmed {
                height: height.parse().map_err(malformed)?,
                index: index.parse().map_err(malformed)?,
            })
        }
        _ => Err(Error::Argument("bad transaction status".into())),
    }
}

/// A connection to a remote or embedded node.
pub enum Connection {
    /// An authenticated onion stream client.
    Remote(Client),
    /// A direct event channel; no token or socket is required.
    Embedded(mpsc::Sender<Event>),
}

impl Control for Connection {
    async fn close(&mut self) -> Result<()> {
        match self {
            Self::Remote(client) => Control::close(client).await,
            Self::Embedded(_) => Ok(()),
        }
    }

    async fn call(&mut self, line: &str) -> Result<String> {
        match self {
            Self::Remote(client) => client.call(line).await,
            Self::Embedded(events) => {
                let response = dispatch(events, parse(line)?).await?;
                decode_reply(&format(&response))
            }
        }
    }
}

impl Control for Client {
    async fn close(&mut self) -> Result<()> {
        self.stream.get_mut().shutdown().await?;
        Ok(())
    }

    async fn call(&mut self, line: &str) -> Result<String> {
        Self::call(self, line).await
    }
}

fn decode_reply(reply: &str) -> Result<String> {
    let reply = reply.trim_end();
    match reply.strip_prefix("ok") {
        Some(rest) => Ok(rest.trim_start().to_string()),
        None => Err(Error::Argument(
            reply.strip_prefix("err ").unwrap_or(reply).to_string(),
        )),
    }
}

impl Endpoint {
    /// Validates the onion service endpoint.
    ///
    /// # Errors
    /// Rejects direct IP/DNS destinations, malformed onions, and port zero.
    pub fn validate(&self) -> Result<()> {
        p2p::address::NetAddr::parse_endpoint(&self.addr)?;
        Ok(())
    }

    /// Connects and authenticates.
    ///
    /// # Errors
    /// Fails if the socket cannot be reached, or with
    /// [`Error::Unauthorized`] if the token is refused.
    pub async fn connect(&self) -> Result<Client> {
        self.validate()?;
        Client::connect(&self.network, &self.addr, &self.token).await
    }
}

/// A client for the control socket.
pub struct Client {
    // Keep the client lifecycle alive for this connection.
    _network: Arc<TorNetwork>,
    stream: BufReader<Stream>,
    timeout: Duration,
}

impl Client {
    /// Opens an isolated connection through the application's embedded Tor client.
    ///
    /// # Errors
    /// Fails on unavailable Tor, an invalid onion endpoint, or a rejected token.
    pub async fn connect(network: &Arc<TorNetwork>, addr: &str, token: &Token) -> Result<Self> {
        let stream = network.connect(addr).await?;
        let mut client = Self {
            _network: Arc::clone(network),
            stream: BufReader::new(stream),
            timeout: CALL_TIMEOUT,
        };
        match client.call(&format!("auth {}", token.expose())).await {
            Ok(_) => Ok(client),
            Err(Error::Argument(reason)) if reason == "unauthorized" => Err(Error::Unauthorized),
            Err(error) => Err(error),
        }
    }

    /// Sends one request line and returns the reply without the `ok `
    /// prefix.
    ///
    /// # Errors
    /// Returns [`Error::Argument`] carrying the node's error text.
    pub async fn call(&mut self, line: &str) -> Result<String> {
        tokio::time::timeout(self.timeout, async {
            self.stream
                .get_mut()
                .write_all(format!("{line}\n").as_bytes())
                .await?;
            self.stream.get_mut().flush().await
        })
        .await
        .map_err(|_| Error::Argument("control request timed out".into()))??;
        let reply = tokio::time::timeout(self.timeout, self.read_reply())
            .await
            .map_err(|_| Error::Argument("control socket timed out".into()))??;
        decode_reply(&reply)
    }

    /// Reads one newline-terminated reply, bounded by [`MAX_REPLY_BYTES`]
    /// so a hostile node cannot make the client allocate without limit.
    async fn read_reply(&mut self) -> Result<String> {
        let mut buf = Vec::new();
        loop {
            let chunk = self.stream.fill_buf().await?;
            if chunk.is_empty() {
                return Err(Error::Argument("control socket closed".into()));
            }
            if let Some(pos) = chunk.iter().position(|&b| b == b'\n') {
                buf.extend_from_slice(chunk.get(..pos).unwrap_or_default());
                self.stream.consume(pos.saturating_add(1));
                break;
            }
            if buf.len().saturating_add(chunk.len()) > MAX_REPLY_BYTES {
                return Err(Error::Argument("control reply too long".into()));
            }
            let take = chunk.len();
            buf.extend_from_slice(chunk);
            self.stream.consume(take);
        }
        String::from_utf8(buf).map_err(|_| Error::Argument("control reply not UTF-8".into()))
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn control_endpoints_require_valid_onions() {
        let onion = format!("{}:18444", p2p::address::NetAddr::TorV3([4; 32]));
        let endpoint = Endpoint {
            addr: onion,
            token: Token::new("node").unwrap(),
            network: p2p::transport::test_support::network(
                p2p::address::NetAddr::TorV3([44; 32]),
                &[],
            )
            .0,
        };
        assert!(endpoint.validate().is_ok());
        for addr in [
            "127.0.0.1:18444",
            "localhost:18444",
            "example.com:18444",
            "bad.onion:18444",
        ] {
            assert!(Endpoint {
                addr: addr.into(),
                ..endpoint.clone()
            }
            .validate()
            .is_err());
        }
    }

    #[tokio::test]
    async fn closing_a_download_session_sends_eof_before_private_processing() {
        let (client_stream, stream) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            let mut reader = BufReader::new(stream);
            let mut auth = String::new();
            reader.read_line(&mut auth).await.unwrap();
            assert_eq!(auth, "auth test-token\n");
            reader.get_mut().write_all(b"ok\n").await.unwrap();
            let mut remaining = Vec::new();
            reader.read_to_end(&mut remaining).await.unwrap()
        });
        let mut client = Client {
            _network: p2p::transport::test_support::network(
                p2p::address::NetAddr::TorV3([45; 32]),
                &[],
            )
            .0,
            stream: BufReader::new(Stream::Memory(client_stream)),
            timeout: CALL_TIMEOUT,
        };
        client.call("auth test-token").await.unwrap();
        Control::close(&mut client).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), server)
                .await
                .unwrap()
                .unwrap(),
            0
        );
        // The client object remains alive; EOF does not wait for scope exit.
        drop(client);
    }

    #[tokio::test]
    async fn bounded_lines_reject_oversized_data_without_waiting_for_newline() {
        let (mut writer, reader) = tokio::io::duplex(1024);
        writer.write_all(&[b'x'; 257]).await.unwrap();
        let mut reader = BufReader::new(reader);
        let result =
            tokio::time::timeout(Duration::from_secs(1), read_bounded_line(&mut reader, 256))
                .await
                .unwrap();
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
        // Writer is still open: rejection did not depend on EOF.
        drop(writer);
    }

    #[tokio::test]
    async fn bounded_lines_preserve_pipelined_requests() {
        let mut reader = BufReader::new(&b"auth secret\nstatus\n"[..]);
        assert_eq!(
            read_bounded_line(&mut reader, 256).await.unwrap().unwrap(),
            "auth secret\n"
        );
        assert_eq!(
            read_bounded_line(&mut reader, 256).await.unwrap().unwrap(),
            "status\n"
        );
        assert!(read_bounded_line(&mut reader, 256).await.unwrap().is_none());
    }

    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    struct StatusReply(String);

    impl Control for StatusReply {
        fn call(&mut self, line: &str) -> impl std::future::Future<Output = Result<String>> + Send {
            assert!(matches!(
                parse(line).unwrap(),
                Request::TransactionStatus(_)
            ));
            std::future::ready(Ok(self.0.clone()))
        }
    }

    #[tokio::test]
    async fn transaction_status_round_trips_and_rejects_malformed_replies() {
        let txid = TxId::from_bytes([7; 32]);
        for status in [
            TxStatus::Unknown,
            TxStatus::Pooled,
            TxStatus::Confirmed {
                height: 9,
                index: 2,
            },
        ] {
            let reply = decode_reply(&format(&Response::TransactionStatus(status))).unwrap();
            assert_eq!(
                transaction_status(&mut StatusReply(reply), txid)
                    .await
                    .unwrap(),
                status
            );
        }
        for reply in [
            "",
            "confirmed",
            "confirmed x 0",
            "confirmed 1 -1",
            "pooled extra",
            "unknown extra",
        ] {
            assert!(transaction_status(&mut StatusReply(reply.into()), txid)
                .await
                .is_err());
        }
        assert!(parse("txstatus").is_err());
        assert!(parse("txstatus 00").is_err());
        assert!(parse("txstatus zz").is_err());
    }

    #[test]
    fn tokens_are_validated_and_compared() {
        let token = Token::random(&mut ChaCha20Rng::seed_from_u64(1));
        assert_eq!(token.expose().len(), 2 * TOKEN_RANDOM_BYTES);
        assert!(token.matches(token.expose()));
        assert!(!token.matches(&token.expose()[1..]));
        assert!(!token.matches(""));
        assert!(Token::new("  spaced out ").is_err());
        assert!(Token::new("").is_err());
        assert!(Token::new(&"x".repeat(MAX_TOKEN_LEN + 1)).is_err());
        assert_eq!(Token::new(" abc\n").unwrap().expose(), "abc");
        assert_eq!(format!("{token:?}"), "Token(<secret>)");
    }

    #[test]
    fn token_files_round_trip_with_owner_only_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(TOKEN_FILE);
        let token = Token::random(&mut ChaCha20Rng::seed_from_u64(2));
        token.write_to(&path).unwrap();
        assert!(Token::from_file(&path).unwrap().matches(token.expose()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert!(Token::from_file(dir.path().join("missing")).is_err());
    }

    #[test]
    fn the_gate_refuses_until_the_token_is_presented_and_closes_after_three() {
        let token = Token::new("secret").unwrap();
        let mut auth = Auth::new(token.clone());
        assert!(matches!(auth.gate("status"), Gate::Reply(UNAUTHORIZED)));
        assert!(matches!(auth.gate("auth wrong"), Gate::Reply(UNAUTHORIZED)));
        assert!(matches!(auth.gate("auth secret"), Gate::Reply("ok")));
        assert!(matches!(auth.gate("status"), Gate::Pass));

        let mut auth = Auth::new(token);
        assert!(matches!(auth.gate("auth a"), Gate::Reply(UNAUTHORIZED)));
        assert!(matches!(auth.gate("auth b"), Gate::Reply(UNAUTHORIZED)));
        assert!(matches!(auth.gate("auth c"), Gate::Close(UNAUTHORIZED)));
    }

    /// Answers every status request with a fixed height.
    fn fake_node() -> mpsc::Sender<Event> {
        let (events, mut receiver) = mpsc::channel(8);
        tokio::spawn(async move {
            while let Some(event) = receiver.recv().await {
                if let Event::Rpc { request, reply } = event {
                    let response = match request {
                        Request::Status => Response::Status {
                            height: 42,
                            hash: protocol::block::BlockHash::ZERO,
                            peers: 0,
                            mempool: 0,
                            mined: 0,
                            mined_in_chain: 0,
                            syncing: false,
                        },
                        _ => Response::Failed("unsupported".into()),
                    };
                    let _ = reply.send(response);
                }
            }
        });
        events
    }

    #[tokio::test]
    async fn embedded_control_uses_the_event_channel_and_preserves_errors() {
        let mut client = Source::Embedded(fake_node()).connect().await.unwrap();
        assert!(client.call("status").await.unwrap().contains("height=42"));
        assert!(
            matches!(client.call("hash 0").await, Err(Error::Argument(reason)) if reason == "unsupported")
        );
        assert!(client.call("not-a-command").await.is_err());
        let (events, receiver) = mpsc::channel(1);
        drop(receiver);
        let mut stopped = Source::Embedded(events).connect().await.unwrap();
        assert!(matches!(stopped.call("status").await, Err(Error::Stopped)));
    }

    #[tokio::test]
    async fn a_silent_node_times_out_instead_of_hanging() {
        let (stream, _held) = tokio::io::duplex(4096);
        let mut client = Client {
            _network: p2p::transport::test_support::network(
                p2p::address::NetAddr::TorV3([45; 32]),
                &[],
            )
            .0,
            stream: BufReader::new(Stream::Memory(stream)),
            timeout: Duration::from_millis(100),
        };
        assert!(matches!(
            client.call("status").await,
            Err(Error::Argument(_))
        ));
    }

    #[tokio::test]
    async fn a_closed_node_is_an_error_not_a_hang() {
        let (stream, server) = tokio::io::duplex(4096);
        drop(server);
        let mut client = Client {
            _network: p2p::transport::test_support::network(
                p2p::address::NetAddr::TorV3([45; 32]),
                &[],
            )
            .0,
            stream: BufReader::new(Stream::Memory(stream)),
            timeout: Duration::from_secs(2),
        };
        assert!(client.call("status").await.is_err());
    }

    #[tokio::test]
    async fn sessions_need_the_token_and_clients_present_it() {
        let identity = p2p::address::NetAddr::TorV3([43; 32]);
        let (server_network, mut incoming) =
            p2p::transport::test_support::network(identity, &[18444]);
        let network =
            p2p::transport::test_support::network(p2p::address::NetAddr::TorV3([46; 32]), &[]).0;
        let addr = identity.endpoint(18444);
        let token = Token::new("hunter2").unwrap();
        let server_token = token.clone();
        tokio::spawn(async move {
            let _service = server_network;
            while let Some(incoming) = incoming.recv().await {
                tokio::spawn(serve_stream(
                    incoming.stream,
                    fake_node(),
                    server_token.clone(),
                ));
            }
        });

        assert!(matches!(
            Client::connect(&network, &addr, &Token::new("wrong").unwrap()).await,
            Err(Error::Unauthorized)
        ));
        let mut client = Client::connect(&network, &addr, &token).await.unwrap();
        assert!(client.call("status").await.unwrap().contains("height=42"));

        // A raw session: commands before auth are refused, the third
        // refusal closes the connection.
        let mut raw = BufReader::new(network.connect(&addr).await.unwrap());
        let mut line = String::new();
        for _ in 0..3 {
            raw.get_mut().write_all(b"status\n").await.unwrap();
            line.clear();
            raw.read_line(&mut line).await.unwrap();
            assert_eq!(line.trim_end(), UNAUTHORIZED);
        }
        line.clear();
        assert_eq!(raw.read_line(&mut line).await.unwrap(), 0, "closed");
    }

    #[test]
    fn requests_parse_and_bad_ones_fail() {
        assert!(matches!(parse("status"), Ok(Request::Status)));
        assert!(matches!(parse("block 7"), Ok(Request::Block(7))));
        assert!(matches!(parse("compact 7"), Ok(Request::Compact(7))));
        assert!(matches!(parse("coinbase 7"), Ok(Request::Coinbase(7))));
        assert!(parse("coinbase x").is_err());
        assert!(matches!(parse("hash 7"), Ok(Request::Hash(7))));
        assert!(parse("block x").is_err());
        assert!(parse("submit zz").is_err());
        assert!(parse("spent 00").is_err());
        assert!(parse("dance").is_err());
    }

    #[test]
    fn responses_format_as_documented() {
        let status = Response::Status {
            height: 1,
            hash: protocol::block::BlockHash::ZERO,
            peers: 2,
            mempool: 3,
            mined: 5,
            mined_in_chain: 4,
            syncing: false,
        };
        let line = format(&status);
        assert!(line.starts_with("ok height=1 hash=0000"));
        assert!(line.ends_with(" peers=2 mempool=3 mined=5 in_chain=4 syncing=false"));
        assert_eq!(format(&Response::Block(None)), "err not found");
        assert_eq!(format(&Response::Spent(true)), "ok true");
        assert_eq!(format(&Response::Failed("x".into())), "err x");
    }
}
