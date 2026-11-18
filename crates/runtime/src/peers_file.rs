//! The address book on disk, `peers.dat` in the data directory, so a
//! restart or upgrade keeps the reachable nodes this one has verified
//! instead of relearning them from scratch.
//!
//! The private snapshot preserves onion identities, behavior penalties, and
//! recently verified peers used as restart anchors.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use p2p::addrbook::{AddressBook, Snapshot, MAX_SNAPSHOT_BYTES};
use p2p::message::PeerAddr;

use crate::config::Config;
use crate::{logging, paths, Result};

/// File name of the saved address book in the data directory.
pub const PEERS_FILE: &str = "peers.dat";
/// Largest file [`load`] reads. Anything larger is not a book this node wrote.
const MAX_FILE_BYTES: u64 = MAX_SNAPSHOT_BYTES as u64;

/// Where `config` keeps its onion address book.
pub(crate) fn path(config: &Config) -> PathBuf {
    config.datadir.join(PEERS_FILE)
}

/// Reads the saved book at `path`, keeping only addresses `keep` accepts.
/// A missing file is a fresh start; an unreadable or malformed one is
/// reported and ignored, since it must never stop the node from starting.
pub(crate) fn load(path: &Path, now: u64, keep: impl Fn(&PeerAddr) -> bool) -> AddressBook {
    let mut book = AddressBook::new();
    match read_snapshot(path) {
        Ok(Some(snapshot)) => {
            let restored = book.restore(snapshot, now, keep);
            logging::info(&format!("loaded {restored} peer addresses"));
        }
        Ok(None) => {}
        Err(error) => logging::warn(&format!("ignoring {}: {error}", path.display())),
    }
    book
}

fn read_snapshot(path: &Path) -> Result<Option<Snapshot>> {
    let len = match std::fs::metadata(path) {
        Ok(meta) => meta.len(),
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if len > MAX_FILE_BYTES {
        return Err(crate::Error::Argument(format!(
            "{len} bytes, larger than any saved address book"
        )));
    }
    Ok(Some(Snapshot::from_bytes(&std::fs::read(path)?)?))
}

/// Writes `book` to `path` through a temporary file and a rename, so a
/// crash mid-write leaves the previous file intact.
///
/// # Errors
/// Fails if the file cannot be written or renamed.
pub(crate) fn save(path: &Path, book: &AddressBook) -> Result<()> {
    let tmp = path.with_extension("dat.tmp");
    paths::write_private(&tmp, &book.snapshot().to_bytes())?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use p2p::address::NetAddr;

    use super::*;

    fn book_with(addrs: &[PeerAddr], now: u64) -> AddressBook {
        let mut book = AddressBook::new();
        for a in addrs {
            book.add(*a, now);
            book.connected(a.key(), now);
        }
        book
    }

    fn public(last: u8) -> PeerAddr {
        PeerAddr::new(NetAddr::TorV3([last; 32]), 19_000, 100)
    }

    #[test]
    fn saved_books_load_back_with_their_verification() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(PEERS_FILE);
        save(&path, &book_with(&[public(1), public(2)], 100)).unwrap();
        let book = load(&path, 200, |_| true);
        assert_eq!(book.len(), 2);
        assert!(book.verified(public(1).key(), 200));
        assert!(!dir.path().join("peers.dat.tmp").exists());
    }

    #[test]
    fn loading_applies_the_policy_filter() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(PEERS_FILE);
        save(&path, &book_with(&[public(1), public(2)], 100)).unwrap();
        let book = load(&path, 200, |a| a.key() == public(2).key());
        assert_eq!(book.len(), 1);
    }

    #[test]
    fn missing_garbage_and_oversized_files_give_an_empty_book() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(PEERS_FILE);
        assert!(load(&path, 200, |_| true).is_empty(), "missing");
        std::fs::write(&path, b"not a book").unwrap();
        assert!(load(&path, 200, |_| true).is_empty(), "garbage");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_FILE_BYTES + 1).unwrap();
        assert!(read_snapshot(&path).is_err(), "oversized");
        assert!(load(&path, 200, |_| true).is_empty());
    }

    #[test]
    fn saving_replaces_the_previous_book() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(PEERS_FILE);
        save(&path, &book_with(&[public(1), public(2)], 100)).unwrap();
        save(&path, &book_with(&[public(3)], 100)).unwrap();
        let book = load(&path, 200, |_| true);
        assert_eq!(book.len(), 1);
        assert!(book.verified(public(3).key(), 200));
    }

    #[test]
    fn tor_nodes_keep_their_peer_book() {
        let mut config = Config::test();
        assert_eq!(path(&config), config.datadir.join(PEERS_FILE));
        config.datadir = PathBuf::from("/data");
        assert_eq!(path(&config), PathBuf::from("/data/peers.dat"));
        config.tor = crate::tor::TorConfig::default();
        assert_eq!(path(&config), PathBuf::from("/data/peers.dat"));
    }

    #[test]
    fn restart_preserves_behavior_bans_and_three_anchors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(PEERS_FILE);
        let peers = [public(1), public(2), public(3), public(4)];
        let mut book = book_with(&peers, 100);
        book.ban(peers[3].addr, 100);
        save(&path, &book).unwrap();
        let restored = load(&path, 200, |_| true);
        assert!(restored.is_banned(&peers[3].addr, 200));
        assert!(restored.score(&peers[3].addr) > 0);
        let anchors = restored.anchors(3, 200);
        assert_eq!(anchors, peers[..3]);
    }
}
