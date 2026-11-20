//! Embedded Tor streams and bounded connection tasks.

use std::mem::size_of;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use p2p::address::{NetAddr, PeerKey};
use p2p::message::{Message, MAX_MESSAGE_LEN};
use p2p::peer::Direction;
use p2p::transport::{
    split, ConnectionReader, ConnectionWriter, Stream, TorNetwork, TorSettings, TorStatus,
};
use protocol::action::{Action, ACTION_LEN};
use protocol::block::{Block, BlockHeader};
use protocol::consensus::MAX_BLOCK_TRANSACTIONS;
use protocol::transaction::Transaction;
use tokio::sync::{mpsc, watch};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

use crate::node::{Event, PeerId};

/// Messages queued to a peer before it is considered stuck.
const OUTBOX_CAPACITY: usize = 1_024;
/// Conservative memory charges for all queued and currently written messages.
const PEER_OUTBOX_BYTES: usize = 384 * 1024 * 1024;
const GLOBAL_OUTBOX_BYTES: usize = 1024 * 1024 * 1024;
/// Leave room for control traffic while bulk serving is paused.
const CONTROL_HEADROOM: usize = 512 * 1024;
/// Conservative framing scratch allowance for each outbound message.
const WRITE_SCRATCH: usize = 128 * 1024;
// Queued permits are retained through the configured per-message write deadline.
static OUTBOUND_BYTES: OnceLock<Arc<Semaphore>> = OnceLock::new();

/// Metadata recorded only after a request frame reaches the transport.
#[derive(Debug)]
pub enum Sent {
    /// Ticket of a flushed headers request.
    Headers {
        /// Sync session identifier.
        epoch: u64,
        /// Reservation identifier within the session.
        request: u64,
    },
    /// Flushed block-body requests.
    Blocks {
        /// Sync session identifier.
        epoch: u64,
        /// Hashes and reservation identifiers within the session.
        requests: Vec<(protocol::block::BlockHash, u64)>,
    },
    /// A keepalive whose RTT starts at this write.
    Ping(u64),
    /// Traffic with no response deadline.
    Other,
}

/// A peer's outbound queue, bounded by both message count and memory charges.
/// Dropping its last clone cancels the connection and discards the backlog.
#[derive(Clone, Debug)]
pub struct Outbox {
    sender: mpsc::Sender<Queued>,
    state: Arc<OutboxState>,
}

#[derive(Debug)]
struct OutboxState {
    peer: Arc<Semaphore>,
    global: Arc<Semaphore>,
    // The connection watches channel closure; queued messages must not hold
    // this sender, so even a blocked write is cancelled on the last Outbox drop.
    _lifetime: watch::Sender<()>,
}

/// Capacity reserved before loading a stored block into memory.
#[derive(Debug)]
pub struct Reservation {
    peer: Arc<Semaphore>,
    bytes: usize,
    _peer: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
}

#[derive(Debug)]
struct Queued {
    message: Message,
    sent: Option<Sent>,
    _reservation: Reservation,
}

/// An outbound queue could not accept a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    /// The peer's queue or a memory budget is full.
    Full,
    /// The connection is closed.
    Closed,
    /// The message exceeds the protocol limit or its reservation.
    TooLarge,
}

impl Outbox {
    fn channel(global: Arc<Semaphore>) -> (Self, mpsc::Receiver<Queued>, watch::Receiver<()>) {
        Self::with_limits(global, PEER_OUTBOX_BYTES, OUTBOX_CAPACITY)
    }

    fn with_limits(
        global: Arc<Semaphore>,
        peer_bytes: usize,
        capacity: usize,
    ) -> (Self, mpsc::Receiver<Queued>, watch::Receiver<()>) {
        let (sender, receiver) = mpsc::channel(capacity);
        let (lifetime, closed) = watch::channel(());
        let state = Arc::new(OutboxState {
            peer: Arc::new(Semaphore::new(peer_bytes)),
            global,
            _lifetime: lifetime,
        });
        (Self { sender, state }, receiver, closed)
    }

    fn reserve(&self, bytes: usize, headroom: usize) -> Option<Reservation> {
        if self.sender.is_closed() || self.sender.capacity() == 0 {
            return None;
        }
        let needed = bytes.checked_add(headroom)?;
        // Acquire the headroom atomically as well: a separate availability
        // check races with other connections sharing the global semaphore.
        let permits = u32::try_from(needed).ok()?;
        let mut peer = Arc::clone(&self.state.peer)
            .try_acquire_many_owned(permits)
            .ok()?;
        let mut global = Arc::clone(&self.state.global)
            .try_acquire_many_owned(permits)
            .ok()?;
        drop(peer.split(headroom)?);
        drop(global.split(headroom)?);
        Some(Reservation {
            peer: Arc::clone(&self.state.peer),
            bytes,
            _peer: peer,
            _global: global,
        })
    }

    /// Reserves memory before decoding a stored body. `encoded_len` is the
    /// stored block encoding length, excluding the network message tag.
    /// Returns `None` while bulk serving should wait for a writable event.
    pub fn try_reserve_block(&self, encoded_len: usize) -> Option<Reservation> {
        self.reserve(block_charge(encoded_len)?, CONTROL_HEADROOM)
    }

    /// Queues a message using an existing reservation, releasing it on error.
    ///
    /// # Errors
    /// Rejects a closed/full queue, an oversized message, or another peer's reservation.
    pub fn try_send_reserved(
        &self,
        message: Message,
        reservation: Reservation,
    ) -> std::result::Result<(), SendError> {
        let bytes = message_charge(&message).ok_or(SendError::TooLarge)?;
        if !Arc::ptr_eq(&reservation.peer, &self.state.peer) || bytes > reservation.bytes {
            return Err(SendError::TooLarge);
        }
        self.sender
            .try_send(Queued {
                message,
                sent: None,
                _reservation: reservation,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => SendError::Full,
                mpsc::error::TrySendError::Closed(_) => SendError::Closed,
            })
    }

    /// Queues a request with its local deadline ticket; tickets never go on wire.
    ///
    /// # Errors
    /// Same queue and memory admission failures as [`Self::try_send`].
    pub fn try_send_tracked(
        &self,
        message: Message,
        sent: Sent,
    ) -> std::result::Result<(), SendError> {
        let bytes = message_charge(&message).ok_or(SendError::TooLarge)?;
        let reservation = self.reserve(bytes, 0).ok_or(SendError::Full)?;
        self.sender
            .try_send(Queued {
                message,
                sent: Some(sent),
                _reservation: reservation,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => SendError::Full,
                mpsc::error::TrySendError::Closed(_) => SendError::Closed,
            })
    }

    /// Queues a control or relay message without waiting for capacity.
    ///
    /// # Errors
    /// Rejects a closed/full queue or a message beyond the protocol/byte limit.
    pub fn try_send(&self, message: Message) -> std::result::Result<(), SendError> {
        if self.sender.is_closed() {
            return Err(SendError::Closed);
        }
        let bytes = message_charge(&message).ok_or(SendError::TooLarge)?;
        let reservation = self.reserve(bytes, 0).ok_or(SendError::Full)?;
        self.try_send_reserved(message, reservation)
    }
}

// Charges include decoded allocations, spare Vec capacity, canonical encoding,
// framing buffers. These are conservative admission budgets,
// not an exact process-RSS measurement. No encoding or proof cloning is needed
// to account for a message. Retaining permits through the write covers all
// messages already removed from the channel as well as the queued backlog.
fn charge(encoded: usize, retained: usize) -> Option<usize> {
    if encoded > MAX_MESSAGE_LEN {
        return None;
    }
    retained
        .checked_mul(2)?
        .checked_add(encoded.checked_mul(4)?)?
        .checked_add(WRITE_SCRATCH)
}

fn transaction_usage(tx: &Transaction) -> Option<(usize, usize)> {
    let actions = tx.actions().len();
    let proof = tx.proof().as_bytes().len();
    let encoded = (1usize + 1 + 32 + 8 + 1 + 4 + 64)
        .checked_add(actions.checked_mul(ACTION_LEN)?)?
        .checked_add(proof)?;
    let heap = actions
        .checked_mul(size_of::<Action>())?
        .checked_add(proof)?;
    Some((encoded, heap))
}

fn transactions_usage(transactions: &[Transaction]) -> Option<(usize, usize)> {
    let mut encoded = 0usize;
    let mut retained = transactions.len().checked_mul(size_of::<Transaction>())?;
    for tx in transactions {
        let (wire, heap) = transaction_usage(tx)?;
        encoded = encoded.checked_add(wire)?;
        retained = retained.checked_add(heap)?;
    }
    Some((encoded, retained))
}

fn message_charge(message: &Message) -> Option<usize> {
    let (payload, heap) = match message {
        Message::Version(_) => (4 + 8 + 4 + 32 + 8 + 8 + 1 + 36, 0),
        Message::Verack | Message::GetAddr => (0, 0),
        Message::Ping(_) | Message::Pong(_) | Message::ConnectionLink(_) => (8, 0),
        Message::Addr(items) => (
            4usize.checked_add(items.len().checked_mul(44)?)?,
            items
                .capacity()
                .checked_mul(size_of::<p2p::message::PeerAddr>())?,
        ),
        Message::GetHeaders { locator, .. } => (
            36usize.checked_add(locator.len().checked_mul(32)?)?,
            locator.capacity().checked_mul(32)?,
        ),
        Message::Headers(items) => (
            4usize.checked_add(
                items
                    .iter()
                    .try_fold(0usize, |sum, header| sum.checked_add(header.encoded_len()))?,
            )?,
            items.capacity().checked_mul(size_of::<BlockHeader>())?,
        ),
        Message::Inv(items) | Message::GetData(items) | Message::NotFound(items) => (
            4usize.checked_add(items.len().checked_mul(33)?)?,
            items
                .capacity()
                .checked_mul(size_of::<p2p::message::Inventory>())?,
        ),
        Message::Block(block) => {
            let (wire, heap) = transactions_usage(block.transactions())?;
            (
                (block.header().encoded_len() + 4).checked_add(wire)?,
                size_of::<Block>().checked_add(heap)?,
            )
        }
        Message::Tx(tx) | Message::StemTx(tx) => {
            let (wire, heap) = transaction_usage(tx)?;
            (wire, size_of::<Transaction>().checked_add(heap)?)
        }
        Message::CompactBlock(block) => {
            let (wire, heap) = transaction_usage(&block.coinbase)?;
            (
                (block.header.encoded_len() + 4)
                    .checked_add(wire)?
                    .checked_add(block.txids.len().checked_mul(32)?)?,
                size_of::<p2p::message::CompactBlock>()
                    .checked_add(heap)?
                    .checked_add(block.txids.capacity().checked_mul(32)?)?,
            )
        }
        Message::GetBlockTxn { indices, .. } => (
            36usize.checked_add(indices.len().checked_mul(4)?)?,
            indices.capacity().checked_mul(size_of::<u32>())?,
        ),
        Message::BlockTxn { transactions, .. } => {
            let (wire, heap) = transactions_usage(transactions)?;
            // Unlike a Block's private vector, this vector's capacity is
            // visible, so include any caller-reserved excess directly.
            let spare = transactions.capacity().saturating_sub(transactions.len());
            (
                36usize.checked_add(wire)?,
                heap.checked_add(spare.checked_mul(size_of::<Transaction>())?)?,
            )
        }
        Message::GetSnapshotManifest { .. } => (4, 0),
        Message::SnapshotManifest(info) => (
            32usize
                .checked_add(4 + 4)?
                .checked_add(info.manifest.len())?
                .checked_add(8 + 4 + 4 + 32)?,
            info.manifest.capacity(),
        ),
        Message::GetSnapshotChunk { .. } => (36, 0),
        Message::SnapshotChunk { bytes, .. } => (
            32usize
                .checked_add(4 + 4 + 32 + 4)?
                .checked_add(bytes.len())?,
            bytes.capacity(),
        ),
    };
    charge(
        payload.checked_add(1)?,
        size_of::<Message>().checked_add(heap)?,
    )
}

fn block_charge(encoded_len: usize) -> Option<usize> {
    // Every action occupies ACTION_LEN encoded bytes; this bounds their
    // extra decoded point representation without inspecting the stored body.
    let action_overhead = size_of::<Action>().saturating_sub(ACTION_LEN);
    let retained = encoded_len
        .checked_add((encoded_len / ACTION_LEN).checked_mul(action_overhead)?)?
        .checked_add(MAX_BLOCK_TRANSACTIONS.checked_mul(size_of::<Transaction>())?)?
        .checked_add(size_of::<Block>().checked_add(size_of::<Message>())?)?;
    charge(encoded_len.checked_add(1)?, retained)
}
/// Connections waiting for admission to the node actor at once.
/// Application handshake and inbound-slot limits are enforced by the node.
pub const MAX_PENDING_INBOUND: usize = 8;

/// Admits one anonymous onion stream to the node actor.
pub async fn accept(
    stream: Stream,
    events: mpsc::Sender<Event>,
    id: PeerId,
    settings: TorSettings,
) {
    run_connection(
        Accepted {
            stream,
            direction: Direction::Inbound,
            id,
            target: "inbound onion stream".into(),
            endpoint: None,
            permit: None,
            settings,
            connect_time: None,
        },
        events,
    )
    .await;
}

/// A socket about to be handshaken and run.
struct Accepted {
    stream: Stream,
    direction: Direction,
    id: PeerId,
    target: String,
    endpoint: Option<PeerKey>,
    /// The admission slot, released once the node receives the connection.
    permit: Option<OwnedSemaphorePermit>,
    settings: TorSettings,
    connect_time: Option<Duration>,
}

/// An onion destination and its shared embedded Tor client.
pub struct Route {
    /// Validated onion endpoint, including virtual port.
    pub target: String,
    /// Shared embedded Tor network.
    pub network: Arc<TorNetwork>,
    /// Our onion identity, excluded from all outbound destinations.
    pub own: Option<NetAddr>,
    /// Readiness gate; a Tor outage cancels even an in-progress dial.
    pub readiness: watch::Receiver<TorStatus>,
    /// Node-configured stream deadlines, also honored by test transports.
    pub settings: TorSettings,
}

/// Dials through an isolated stream on the embedded Tor client.
pub fn dial(route: Route, id: PeerId, events: mpsc::Sender<Event>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let endpoint = NetAddr::parse_endpoint(&route.target);
        let Ok(endpoint) = endpoint else {
            let _ = events
                .send(Event::DialFailed {
                    id,
                    target: route.target,
                })
                .await;
            return;
        };
        if route.own == Some(endpoint.0) {
            let _ = events
                .send(Event::DialedSelf {
                    id,
                    target: route.target,
                })
                .await;
            return;
        }
        let mut readiness = route.readiness;
        if readiness.has_changed().is_err()
            || !readiness.borrow().client_ready
            || readiness.borrow().onion.is_none()
        {
            let _ = events
                .send(Event::DialFailed {
                    id,
                    target: route.target,
                })
                .await;
            return;
        }
        let started = Instant::now();
        let settings = route.settings;
        let connected = tokio::select! {
            biased;
            () = unavailable(&mut readiness) => {
                let _ = events.send(Event::DialFailed { id, target: route.target }).await;
                return;
            }
            connected = tokio::time::timeout(
                settings.connect_timeout,
                route.network.connect(&route.target),
            ) => connected,
        };
        match connected {
            Ok(Ok(stream)) => {
                run_connection(
                    Accepted {
                        stream,
                        direction: Direction::Outbound,
                        id,
                        target: route.target,
                        endpoint: Some(endpoint),
                        permit: None,
                        settings,
                        connect_time: Some(started.elapsed()),
                    },
                    events,
                )
                .await;
            }
            _ => {
                let _ = events
                    .send(Event::DialFailed {
                        id,
                        target: route.target,
                    })
                    .await;
            }
        }
    })
}

async fn unavailable(status: &mut watch::Receiver<TorStatus>) {
    loop {
        let ready = {
            let state = status.borrow_and_update();
            state.client_ready && state.onion.is_some()
        };
        if !ready || status.changed().await.is_err() {
            return;
        }
    }
}

async fn run_connection(accepted: Accepted, events: mpsc::Sender<Event>) {
    let Accepted {
        stream,
        direction,
        id,
        target,
        endpoint,
        permit,
        settings,
        connect_time,
    } = accepted;
    let (writer, reader) = split(stream);
    let global = OUTBOUND_BYTES.get_or_init(|| Arc::new(Semaphore::new(GLOBAL_OUTBOX_BYTES)));
    let (outbox, inbox, mut closed) = Outbox::channel(Arc::clone(global));
    if events
        .send(Event::Connected {
            id,
            direction,
            addr: endpoint,
            target,
            outbox,
            connect_time,
        })
        .await
        .is_err()
    {
        return;
    }
    drop(permit);
    // All futures are owned here: ending any branch cancels socket work and
    // drops the buffered messages immediately, including a stalled write.
    tokio::select! {
        biased;
        _ = closed.changed() => {}
        () = read_loop(reader, id, &events, &settings) => {}
        () = write_loop_within(writer, inbox, id, &events, settings.message_timeout) => {}
    }
    let _ = events.send(Event::Disconnected { id }).await;
}

async fn write_loop_within(
    mut writer: ConnectionWriter,
    mut inbox: mpsc::Receiver<Queued>,
    id: PeerId,
    events: &mpsc::Sender<Event>,
    deadline: Duration,
) {
    while let Some(mut queued) = inbox.recv().await {
        match tokio::time::timeout(deadline, writer.send(&queued.message)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => break,
        }
        // A queued request is not in flight until its complete frame is flushed.
        let sent = queued.sent.take().unwrap_or(match &queued.message {
            Message::Ping(nonce) => Sent::Ping(*nonce),
            _ => Sent::Other,
        });
        let at = Instant::now();
        let timestamp = crate::now();
        let bytes = writer.sent_bytes();
        drop(queued);
        if events
            .send(Event::Sent {
                id,
                sent,
                at,
                timestamp,
                bytes,
            })
            .await
            .is_err()
        {
            break;
        }
        let _ = events.try_send(Event::Writable { id });
    }
}

async fn read_loop(
    mut reader: ConnectionReader,
    id: PeerId,
    events: &mpsc::Sender<Event>,
    settings: &TorSettings,
) {
    while let Ok(message) = reader
        .recv_with_timeouts(settings.idle_timeout, settings.message_timeout)
        .await
    {
        if events
            .send(Event::Received {
                id,
                bytes: reader.received_bytes(),
                at: Instant::now(),
            })
            .await
            .is_err()
        {
            break;
        }
        if events
            .send(Event::Message {
                id,
                message: Box::new(message),
            })
            .await
            .is_err()
        {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use p2p::message::Inventory;
    use p2p::transport::test_support;
    use protocol::block::{empty_header, BlockHash};
    use protocol::bytes::Encodable;
    use protocol::transaction::Anchor;
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn outbound_budgets_include_messages_removed_from_the_channel() {
        let bytes = message_charge(&Message::Ping(1)).unwrap();
        let global = Arc::new(Semaphore::new(10 * bytes));
        let (outbox, mut inbox, _) = Outbox::with_limits(global, 2 * bytes, 8);
        outbox.try_send(Message::Ping(1)).unwrap();
        outbox.try_send(Message::Ping(2)).unwrap();
        let writing = inbox.try_recv().unwrap();
        assert_eq!(outbox.try_send(Message::Ping(3)), Err(SendError::Full));
        drop(writing);
        outbox.try_send(Message::Ping(3)).unwrap();
        drop(inbox);
        assert_eq!(outbox.state.peer.available_permits(), 2 * bytes);
        assert_eq!(outbox.try_send(Message::Ping(4)), Err(SendError::Closed));
    }

    #[test]
    fn outbound_budget_is_shared_between_peers() {
        let bytes = message_charge(&Message::Ping(1)).unwrap();
        let global = Arc::new(Semaphore::new(2 * bytes));
        let (first, first_inbox, _) = Outbox::with_limits(Arc::clone(&global), 4 * bytes, 8);
        let (second, second_inbox, _) = Outbox::with_limits(Arc::clone(&global), 4 * bytes, 8);
        first.try_send(Message::Ping(1)).unwrap();
        second.try_send(Message::Ping(2)).unwrap();
        assert_eq!(second.try_send(Message::Ping(3)), Err(SendError::Full));
        assert_eq!(second.state.peer.available_permits(), 3 * bytes);
        drop(first_inbox);
        second.try_send(Message::Ping(3)).unwrap();
        drop(second_inbox);
        assert_eq!(global.available_permits(), 2 * bytes);
    }

    #[test]
    fn outbound_message_count_remains_bounded() {
        let bytes = message_charge(&Message::Verack).unwrap();
        let global = Arc::new(Semaphore::new(10 * bytes));
        let (outbox, _inbox, _) = Outbox::with_limits(global, 10 * bytes, 2);
        outbox.try_send(Message::Verack).unwrap();
        outbox.try_send(Message::Verack).unwrap();
        assert_eq!(outbox.try_send(Message::Verack), Err(SendError::Full));
        assert_eq!(outbox.state.peer.available_permits(), 8 * bytes);
    }

    #[test]
    fn block_preflight_allows_protocol_limit_and_preserves_control_capacity() {
        // Reserving is independent of loading/allocating the body itself.
        let global = Arc::new(Semaphore::new(GLOBAL_OUTBOX_BYTES));
        let (outbox, _inbox, _) = Outbox::channel(global);
        let reservation = outbox.try_reserve_block(MAX_MESSAGE_LEN - 1).unwrap();
        assert!(reservation.bytes < PEER_OUTBOX_BYTES - CONTROL_HEADROOM);
        outbox.try_send(Message::Ping(1)).unwrap();
        assert!(outbox.try_reserve_block(MAX_MESSAGE_LEN).is_none());
        drop(reservation);
    }

    #[test]
    fn block_preflight_reservation_covers_decoded_block_and_rejects_misuse() {
        let root = Anchor::from_base(crypto::pallas::Base::from(0));
        let block = Block::new(empty_header(0, BlockHash::ZERO, root), Vec::new());
        let encoded_len = block.to_vec().len();
        let global = Arc::new(Semaphore::new(GLOBAL_OUTBOX_BYTES));
        let (outbox, mut inbox, _) = Outbox::channel(Arc::clone(&global));
        let (other, _other_inbox, _) = Outbox::channel(global);
        let reserved = outbox.try_reserve_block(encoded_len).unwrap();
        outbox
            .try_send_reserved(Message::Block(Box::new(block.clone())), reserved)
            .unwrap();
        assert!(matches!(
            inbox.try_recv().unwrap().message,
            Message::Block(_)
        ));
        let wrong_peer = other.try_reserve_block(encoded_len).unwrap();
        assert_eq!(
            outbox.try_send_reserved(Message::Block(Box::new(block)), wrong_peer),
            Err(SendError::TooLarge)
        );
    }

    #[tokio::test]
    async fn dropping_last_outbox_cancels_even_with_a_buffered_backlog() {
        let global = Arc::new(Semaphore::new(GLOBAL_OUTBOX_BYTES));
        let (outbox, mut inbox, mut closed) = Outbox::channel(global);
        let clone = outbox.clone();
        outbox.try_send(Message::Ping(1)).unwrap();
        let writing = inbox.recv().await.unwrap();
        outbox.try_send(Message::Ping(2)).unwrap();
        drop(outbox);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), closed.changed())
                .await
                .is_err()
        );
        drop(clone);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), closed.changed())
                .await
                .unwrap()
                .is_err()
        );
        // Queue entries and the active write cannot hold the lifetime sender.
        drop(writing);
        drop(inbox);
    }

    #[tokio::test]
    async fn dropping_outbox_cancels_a_slow_socket_writer_and_releases_budgets() {
        slow_writer_releases_budgets(true).await;
    }

    #[tokio::test]
    async fn slow_socket_writer_times_out_and_releases_budgets_without_outbox_drop() {
        slow_writer_releases_budgets(false).await;
    }

    async fn slow_writer_releases_budgets(cancel: bool) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let global = Arc::new(Semaphore::new(GLOBAL_OUTBOX_BYTES));
        let global_for_server = Arc::clone(&global);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (writer, _reader) = split(stream);
            let (outbox, inbox, mut closed) = Outbox::channel(global_for_server);
            let bytes = message_charge(&Message::GetData(vec![
                Inventory::Block(BlockHash::ZERO);
                p2p::message::MAX_INVENTORY
            ]))
            .unwrap();
            for _ in 0..20 {
                outbox
                    .try_send(Message::GetData(vec![
                        Inventory::Block(BlockHash::ZERO);
                        p2p::message::MAX_INVENTORY
                    ]))
                    .unwrap();
            }
            let reserved = 20usize.checked_mul(bytes).unwrap();
            assert!(
                outbox.state.peer.available_permits()
                    <= PEER_OUTBOX_BYTES.checked_sub(reserved).unwrap()
            );
            let (events, _events_inbox) = mpsc::channel(8);
            let task = tokio::spawn(async move {
                tokio::select! {
                    biased;
                    _ = closed.changed() => {}
                    () = write_loop_within(writer, inbox, 1, &events, Duration::from_millis(200)) => {}
                }
            });
            // The client deliberately never reads. Enough data is queued to
            // exceed a normal TCP send buffer, so the writer cannot drain it.
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(!task.is_finished());
            if cancel {
                drop(outbox);
            }
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap();
        });
        let client = p2p::transport::connect_loopback_for_tests(addr)
            .await
            .unwrap();
        let (_writer, _reader) = split(client);
        server.await.unwrap();
        assert_eq!(global.available_permits(), GLOBAL_OUTBOX_BYTES);
    }

    #[tokio::test]
    async fn own_onion_is_not_dialed_even_on_another_service_port() {
        let own = NetAddr::TorV3([79; 32]);
        let (network, mut incoming) = test_support::network(own, &[19001]);
        let (events, mut inbox) = mpsc::channel(8);
        let target = own.endpoint(19001);
        dial(
            Route {
                readiness: network.status(),
                settings: TorSettings::default(),
                network,
                target: target.clone(),
                own: Some(own),
            },
            7,
            events,
        )
        .await
        .unwrap();
        assert!(
            matches!(inbox.recv().await, Some(Event::DialedSelf { id: 7, target: got }) if got == target)
        );
        assert!(incoming.try_recv().is_err());
    }

    #[tokio::test]
    async fn direct_and_dns_destinations_are_rejected_before_tor_dial() {
        let (network, mut incoming) = test_support::network(NetAddr::TorV3([80; 32]), &[19000]);
        for target in [
            "127.0.0.1:19000",
            "example.com:19000",
            "invalid.onion:19000",
        ] {
            let (events, mut inbox) = mpsc::channel(8);
            dial(
                Route {
                    readiness: network.status(),
                    settings: TorSettings::default(),
                    network: Arc::clone(&network),
                    target: target.into(),
                    own: None,
                },
                9,
                events,
            )
            .await
            .unwrap();
            assert!(matches!(
                inbox.recv().await,
                Some(Event::DialFailed { id: 9, .. })
            ));
        }
        assert!(incoming.try_recv().is_err());
    }

    #[tokio::test]
    async fn unavailable_tor_blocks_dials() {
        let (network, _incoming) = test_support::network(NetAddr::TorV3([81; 32]), &[19000]);
        test_support::set_ready(&network, false);
        let (events, mut inbox) = mpsc::channel(8);
        dial(
            Route {
                readiness: network.status(),
                settings: TorSettings::default(),
                network,
                target: NetAddr::TorV3([82; 32]).endpoint(19000),
                own: None,
            },
            1,
            events,
        )
        .await
        .unwrap();
        assert!(matches!(
            inbox.recv().await,
            Some(Event::DialFailed { id: 1, .. })
        ));
    }
}
