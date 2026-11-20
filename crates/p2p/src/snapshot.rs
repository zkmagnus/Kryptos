//! Bounded snapshot chunk assembly after checkpoint validation.

use crypto::hash::{blake2b_short, SNAPSHOT_CHUNK, SNAPSHOT_PAYLOAD};

use crate::message::{
    SnapshotChunk, SnapshotManifestInfo, MAX_SNAPSHOT_CHUNK_LEN, MAX_SNAPSHOT_TOTAL_LEN,
};
use crate::{Error, Result};

/// Computes the hash carried by one snapshot chunk.
pub fn chunk_hash(snapshot_id: &[u8; 32], index: u32, chunk_count: u32, bytes: &[u8]) -> [u8; 32] {
    blake2b_short(
        SNAPSHOT_CHUNK,
        &[
            snapshot_id,
            &index.to_le_bytes(),
            &chunk_count.to_le_bytes(),
            bytes,
        ],
    )
}

/// Computes the hash carried by a complete assembled payload.
pub fn payload_hash(bytes: &[u8]) -> [u8; 32] {
    blake2b_short(SNAPSHOT_PAYLOAD, &[bytes])
}

/// Sequential assembler for a manifest that has already passed checkpoint validation.
///
/// The constructor is deliberately named to make the trust boundary explicit: callers
/// must validate the opaque manifest against their local rules/checkpoint first.
#[derive(Debug)]
pub struct SnapshotAssembler {
    manifest: SnapshotManifestInfo,
    payload: Vec<u8>,
    next_index: u32,
}

impl SnapshotAssembler {
    /// Creates an assembler after the caller has verified the checkpoint binding.
    pub fn after_checkpoint(manifest: SnapshotManifestInfo) -> Result<Self> {
        manifest.validate()?;
        let capacity = usize::try_from(manifest.total_len)
            .map_err(|_| Error::BadSnapshot("payload allocation"))?;
        if capacity > usize::try_from(MAX_SNAPSHOT_TOTAL_LEN).unwrap_or(usize::MAX) {
            return Err(Error::BadSnapshot("payload allocation"));
        }
        Ok(Self {
            manifest,
            payload: Vec::with_capacity(capacity),
            next_index: 0,
        })
    }

    /// The next chunk index accepted by this assembler.
    pub fn next_index(&self) -> u32 {
        self.next_index
    }

    /// Whether all chunks have been accepted.
    pub fn is_complete(&self) -> bool {
        self.next_index == self.manifest.chunk_count
    }

    /// Accepts exactly the next chunk, rejecting duplicates and out-of-order data.
    pub fn push(&mut self, chunk: SnapshotChunk) -> Result<()> {
        if chunk.snapshot_id != self.manifest.snapshot_id
            || chunk.chunk_count != self.manifest.chunk_count
        {
            return Err(Error::BadSnapshot("chunk manifest mismatch"));
        }
        if chunk.index != self.next_index {
            return Err(if chunk.index < self.next_index {
                Error::BadSnapshot("duplicate snapshot chunk")
            } else {
                Error::BadSnapshot("out-of-order snapshot chunk")
            });
        }
        let bytes_len = chunk.bytes.len();
        if bytes_len == 0 || bytes_len > MAX_SNAPSHOT_CHUNK_LEN {
            return Err(Error::BadSnapshot("chunk length"));
        }
        let expected_len = if chunk.index + 1 < self.manifest.chunk_count {
            usize::try_from(self.manifest.chunk_size)
                .map_err(|_| Error::BadSnapshot("chunk size"))?
        } else {
            let used = u64::from(self.manifest.chunk_count.saturating_sub(1))
                .checked_mul(u64::from(self.manifest.chunk_size))
                .ok_or(Error::BadSnapshot("chunk length overflow"))?;
            usize::try_from(self.manifest.total_len.saturating_sub(used))
                .map_err(|_| Error::BadSnapshot("chunk length"))?
        };
        if bytes_len != expected_len
            || chunk_hash(
                &chunk.snapshot_id,
                chunk.index,
                chunk.chunk_count,
                &chunk.bytes,
            ) != chunk.chunk_hash
        {
            return Err(Error::BadSnapshot("chunk hash or length"));
        }
        self.payload.extend_from_slice(&chunk.bytes);
        self.next_index = self.next_index.saturating_add(1);
        Ok(())
    }

    /// Returns the complete payload after all chunks and the aggregate hash match.
    pub fn finish(self) -> Result<Vec<u8>> {
        if !self.is_complete()
            || u64::try_from(self.payload.len()).ok() != Some(self.manifest.total_len)
        {
            return Err(Error::BadSnapshot("incomplete snapshot"));
        }
        if payload_hash(&self.payload) != self.manifest.payload_hash {
            return Err(Error::BadSnapshot("snapshot payload hash"));
        }
        Ok(self.payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::MAX_SNAPSHOT_CHUNK_LEN;

    fn manifest(payload: &[u8], chunk_size: u32) -> SnapshotManifestInfo {
        let chunk_count = u32::try_from(
            (payload.len() + usize::try_from(chunk_size).unwrap() - 1)
                / usize::try_from(chunk_size).unwrap(),
        )
        .unwrap();
        SnapshotManifestInfo {
            snapshot_id: [3; 32],
            height: 10,
            manifest: vec![1],
            total_len: u64::try_from(payload.len()).unwrap(),
            chunk_size,
            chunk_count,
            payload_hash: payload_hash(payload),
        }
    }

    #[test]
    fn assembler_rejects_duplicate_and_out_of_order_chunks() {
        let payload = b"abcdefghijkl";
        let info = manifest(payload, 4);
        let mut assembler = SnapshotAssembler::after_checkpoint(info.clone()).unwrap();
        let second = SnapshotChunk {
            snapshot_id: info.snapshot_id,
            index: 1,
            chunk_count: info.chunk_count,
            chunk_hash: chunk_hash(&info.snapshot_id, 1, info.chunk_count, b"efgh"),
            bytes: b"efgh".to_vec(),
        };
        assert!(matches!(
            assembler.push(second),
            Err(Error::BadSnapshot("out-of-order snapshot chunk"))
        ));
        let first = SnapshotChunk {
            snapshot_id: info.snapshot_id,
            index: 0,
            chunk_count: info.chunk_count,
            chunk_hash: chunk_hash(&info.snapshot_id, 0, info.chunk_count, b"abcd"),
            bytes: b"abcd".to_vec(),
        };
        assembler.push(first.clone()).unwrap();
        assert!(matches!(
            assembler.push(first),
            Err(Error::BadSnapshot("duplicate snapshot chunk"))
        ));
    }

    #[test]
    fn assembler_hashes_chunks_and_complete_payload() {
        let payload = b"abcdefghijkl";
        let info = manifest(payload, 4);
        let mut assembler = SnapshotAssembler::after_checkpoint(info.clone()).unwrap();
        for (index, bytes) in [b"abcd".as_slice(), b"efgh", b"ijkl"]
            .into_iter()
            .enumerate()
        {
            let index = u32::try_from(index).unwrap();
            assembler
                .push(SnapshotChunk {
                    snapshot_id: info.snapshot_id,
                    index,
                    chunk_count: info.chunk_count,
                    chunk_hash: chunk_hash(&info.snapshot_id, index, info.chunk_count, bytes),
                    bytes: bytes.to_vec(),
                })
                .unwrap();
        }
        assert_eq!(assembler.finish().unwrap(), payload);
    }

    #[test]
    fn assembler_rejects_tampered_chunk_and_payload_hashes() {
        let payload = b"abcdefgh";
        let info = manifest(payload, 4);
        let mut assembler = SnapshotAssembler::after_checkpoint(info.clone()).unwrap();
        assert!(matches!(
            assembler.push(SnapshotChunk {
                snapshot_id: info.snapshot_id,
                index: 0,
                chunk_count: info.chunk_count,
                chunk_hash: [0; 32],
                bytes: b"abcd".to_vec(),
            }),
            Err(Error::BadSnapshot("chunk hash or length"))
        ));

        let mut wrong_payload_hash = info;
        wrong_payload_hash.payload_hash = [0; 32];
        let mut assembler =
            SnapshotAssembler::after_checkpoint(wrong_payload_hash.clone()).unwrap();
        for (index, bytes) in [b"abcd".as_slice(), b"efgh"].into_iter().enumerate() {
            let index = u32::try_from(index).unwrap();
            assembler
                .push(SnapshotChunk {
                    snapshot_id: wrong_payload_hash.snapshot_id,
                    index,
                    chunk_count: wrong_payload_hash.chunk_count,
                    chunk_hash: chunk_hash(
                        &wrong_payload_hash.snapshot_id,
                        index,
                        wrong_payload_hash.chunk_count,
                        bytes,
                    ),
                    bytes: bytes.to_vec(),
                })
                .unwrap();
        }
        assert!(matches!(
            assembler.finish(),
            Err(Error::BadSnapshot("snapshot payload hash"))
        ));
    }

    #[test]
    fn assembler_keeps_chunk_limit_bounded() {
        let payload = vec![1; MAX_SNAPSHOT_CHUNK_LEN + 1];
        let info = manifest(&payload, u32::try_from(MAX_SNAPSHOT_CHUNK_LEN).unwrap());
        assert!(SnapshotAssembler::after_checkpoint(info).is_ok());
    }
}
