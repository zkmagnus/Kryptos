//! Optional end-to-end coverage over the public Tor network.

#[path = "support/arti_trace.rs"]
mod arti_trace;

use std::time::Duration;

use p2p::message::Message;
use p2p::transport::{split, TorNetwork};

/// Requires outbound access to public Tor relays; uses two independent keystores.
/// Run explicitly with:
/// `cargo test -p p2p --test real_tor -- --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires real Tor relay access and onion descriptor publication"]
async fn two_embedded_services_exchange_framed_messages() -> Result<(), Box<dyn std::error::Error>>
{
    arti_trace::init()?;
    let alice_dir = tempfile::tempdir()?;
    let bob_dir = tempfile::tempdir()?;
    let (alice, _alice_incoming) = TorNetwork::start(alice_dir.path(), true, &[19000])?;
    let (bob, mut bob_incoming) = TorNetwork::start(bob_dir.path(), true, &[19000])?;
    eprintln!("Waiting for two embedded onion services to publish descriptors");
    tokio::try_join!(wait_for_service(&alice), wait_for_service(&bob))?;
    let identity = bob
        .status()
        .borrow()
        .onion
        .ok_or("missing published onion")?;
    let client = alice.connect(&identity.endpoint(19000)).await?;
    let incoming = tokio::time::timeout(Duration::from_secs(180), bob_incoming.recv())
        .await?
        .ok_or("onion service stopped")?;
    let (mut client_writer, mut client_reader) = split(client);
    let (mut server_writer, mut server_reader) = split(incoming.stream);
    tokio::time::timeout(Duration::from_secs(120), async {
        client_writer.send(&Message::Ping(42)).await?;
        assert_eq!(server_reader.recv().await?, Message::Ping(42));
        server_writer.send(&Message::Pong(42)).await?;
        assert_eq!(client_reader.recv().await?, Message::Pong(42));
        Ok::<(), p2p::Error>(())
    })
    .await??;
    eprintln!("Two embedded onion services exchanged framed Ping/Pong over public Tor");
    Ok(())
}

async fn wait_for_service(network: &TorNetwork) -> Result<(), Box<dyn std::error::Error>> {
    let mut status = network.status();
    tokio::time::timeout(Duration::from_mins(15), async {
        while !network.ready() {
            status.changed().await?;
        }
        Ok::<(), tokio::sync::watch::error::RecvError>(())
    })
    .await??;
    Ok(())
}
