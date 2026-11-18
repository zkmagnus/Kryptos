//! Restores the versioned plaintext backup through a private staging database.

use std::collections::BTreeSet;

use crate::operations::OperationStatus;
use protocol::transaction::Transaction;
use redb::ReadableTableMetadata;
use serde::Deserialize;

use super::{
    decode_height, decode_u64, read_address_range, read_auto_rotate_receive, read_receive_index,
    Anchor, BlockHash, Database, Encodable, Error, Operation, OwnedCoin, Path, ReadableDatabase,
    ReadableTable, Result, Wallet, ADDRESSES, ADDRESS_KEY_SCHEME, ADDRESS_KEY_START, BACKUP_FORMAT,
    BACKUP_VERSION, CAP, CHECKPOINTS, COINS, COIN_INDEX_VERSION, CURRENT_RECEIVE_ADDRESS,
    FINGERPRINT, GENESIS, HEIGHTS, META, NEXT_ADDRESS, NEXT_OPERATION, OPERATIONS, SHARDS,
    SPENDING_KEY,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Row<K> {
    key: K,
    value_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tables {
    meta: Vec<Row<String>>,
    coins: Vec<Row<u64>>,
    heights: Vec<Row<u32>>,
    shards: Vec<Row<u64>>,
    cap: Vec<Row<()>>,
    checkpoints: Vec<Row<u32>>,
    addresses: Vec<Row<u64>>,
    operations: Vec<Row<u64>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Backup {
    format: String,
    version: u32,
    encoding: String,
    plaintext_secrets: bool,
    tables: Tables,
}

impl Wallet {
    /// Restores a version-1 plaintext JSON backup to a new wallet file.
    ///
    /// Keys, address reservations, coins, witnesses, scan history and pending
    /// operations are preserved. The derived nullifier index is rebuilt.
    /// Validation happens in a private temporary file in the destination's
    /// directory, which is published only after successful validation and sync.
    /// Existing files (including symlinks) are never overwritten.
    ///
    /// A backup is trusted local wallet state, not authenticated chain data.
    /// Only restore your own backup, then synchronize before spending. Neither
    /// the JSON nor the restored database encrypts secret key material.
    ///
    /// # Errors
    /// Rejects malformed, inconsistent, unsupported or wrong-network backups,
    /// an existing destination, and filesystem/database failures. Failure before
    /// publication leaves the destination absent and removes the staging file.
    pub fn restore_backup_json(
        path: impl AsRef<Path>,
        bytes: &[u8],
        genesis: BlockHash,
    ) -> Result<()> {
        let path = path.as_ref();
        match std::fs::symlink_metadata(path) {
            Ok(_) => return Err(Error::WrongWallet),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let backup: Backup = serde_json::from_slice(bytes)?;
        if backup.format != BACKUP_FORMAT
            || backup.version != BACKUP_VERSION
            || backup.encoding != "hex"
            || !backup.plaintext_secrets
        {
            return Err(Error::Corrupt("unsupported wallet backup format"));
        }
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let temporary = tempfile::Builder::new()
            .prefix(".rhombus-wallet-restore-")
            .tempfile_in(parent)?;
        {
            let db = Database::builder().create_file(temporary.reopen()?)?;
            let tx = db.begin_write()?;
            let tables = backup.tables;
            macro_rules! restore_rows {
                ($definition:ident, $rows:expr, $key:expr) => {{
                    let mut table = tx.open_table($definition)?;
                    let mut seen = BTreeSet::new();
                    for row in $rows {
                        if !seen.insert(row.key.clone()) {
                            return Err(Error::Corrupt("duplicate wallet backup row"));
                        }
                        let value = crypto::encoding::from_hex(&row.value_hex)?;
                        table.insert($key(&row.key), value.as_slice())?;
                    }
                }};
            }
            restore_rows!(META, tables.meta, String::as_str);
            restore_rows!(COINS, tables.coins, |key: &u64| *key);
            restore_rows!(HEIGHTS, tables.heights, |key: &u32| *key);
            restore_rows!(SHARDS, tables.shards, |key: &u64| *key);
            restore_rows!(CAP, tables.cap, |key: &()| *key);
            restore_rows!(CHECKPOINTS, tables.checkpoints, |key: &u32| *key);
            restore_rows!(ADDRESSES, tables.addresses, |key: &u64| *key);
            restore_rows!(OPERATIONS, tables.operations, |key: &u64| *key);
            {
                let mut meta = tx.open_table(META)?;
                // The backup must include these fields so legacy database
                // migrations cannot invent missing metadata.
                for name in [
                    SPENDING_KEY,
                    FINGERPRINT,
                    GENESIS,
                    ADDRESS_KEY_SCHEME,
                    ADDRESS_KEY_START,
                    NEXT_ADDRESS,
                    CURRENT_RECEIVE_ADDRESS,
                ] {
                    if meta.get(name)?.is_none() {
                        return Err(Error::Corrupt("missing wallet backup metadata"));
                    }
                }
                if meta
                    .get(COIN_INDEX_VERSION)?
                    .is_some_and(|value| value.value() != [1])
                {
                    return Err(Error::Corrupt("unsupported backup nullifier index version"));
                }
                // Derived indexes are deliberately not trusted or exported.
                meta.remove(COIN_INDEX_VERSION)?;
            }
            tx.commit()?;
        }
        {
            let restored = Self::open(temporary.path(), genesis)?;
            // Positions can change under a reorganization while a transaction's
            // nullifiers remain stable. Rebuild recorded-operation reservations
            // against the restored coins rather than trusting stale positions.
            for operation in restored.validate_backup_state()? {
                restored.put_operation(&operation)?;
            }
        }
        temporary.as_file().sync_all()?;
        temporary
            .persist_noclobber(path)
            .map_err(|error| error.error)?;
        Ok(())
    }

    fn validate_backup_state(&self) -> Result<Vec<Operation>> {
        let tx = self.db.begin_read()?;
        let meta = tx.open_table(META)?;
        if meta.get(FINGERPRINT)?.map(|value| value.value().to_vec())
            != Some(self.keys.fingerprint().to_vec())
        {
            return Err(Error::Corrupt("wallet backup fingerprint"));
        }
        read_auto_rotate_receive(&meta)?;
        let range = read_address_range(&meta)?;
        read_receive_index(&meta, range)?;
        self.addresses()?;
        let tree_size = self.tree_size()?;
        let heights = tx.open_table(HEIGHTS)?;
        let mut count = 0u64;
        let mut first = 0;
        for row in heights.iter()? {
            let (height, value) = row?;
            if u64::from(height.value()) != count || value.value().len() != 40 {
                return Err(Error::Corrupt("wallet backup scan history"));
            }
            let (_, position) = decode_height(value.value())?;
            if (count == 0 && position != 0) || position < first || position > tree_size {
                return Err(Error::Corrupt("wallet backup tree positions"));
            }
            first = position;
            count = count
                .checked_add(1)
                .ok_or(Error::Corrupt("wallet backup height overflow"))?;
        }
        for row in tx.open_table(SHARDS)?.iter()? {
            let (index, value) = row?;
            if index.value() >= (1u64 << (crate::tree::DEPTH - crate::tree::SHARD_HEIGHT)) {
                return Err(Error::Corrupt("wallet backup shard index"));
            }
            crate::tree::decode_tree(value.value())?;
        }
        for row in tx.open_table(CAP)?.iter()? {
            crate::tree::decode_tree(row?.1.value())?;
        }
        let checkpoints = tx.open_table(CHECKPOINTS)?;
        if checkpoints.len()? > crate::tree::MAX_CHECKPOINTS as u64 {
            return Err(Error::Corrupt("wallet backup checkpoint count"));
        }
        let mut next_checkpoint = None;
        let coin_table = tx.open_table(COINS)?;
        for row in checkpoints.iter()? {
            let (height, value) = row?;
            let height = height.value();
            let checkpoint = crate::tree::decode_checkpoint(value.value())?;
            // Retained checkpoints form a contiguous suffix ending at the
            // scanned tip. Its length can be shorter after a rollback.
            if u64::from(height) >= count
                || next_checkpoint.is_some_and(|expected| expected != u64::from(height))
            {
                return Err(Error::Corrupt("wallet backup checkpoint"));
            }
            next_checkpoint = Some(u64::from(height).saturating_add(1));
            let block_end = height
                .checked_add(1)
                .and_then(|next| heights.get(next).transpose())
                .transpose()?
                .map(|value| decode_height(value.value()).map(|(_, position)| position))
                .transpose()?
                .unwrap_or(tree_size);
            if checkpoint.position().map(u64::from) != block_end.checked_sub(1) {
                return Err(Error::Corrupt("wallet backup checkpoint position"));
            }
            for position in checkpoint.marks_removed() {
                let value = coin_table
                    .get(u64::from(*position))?
                    .ok_or(Error::Corrupt("wallet backup checkpoint removed coin"))?;
                let coin = OwnedCoin::from_slice(value.value())?;
                if coin.spent_at != Some(height) {
                    return Err(Error::Corrupt("wallet backup checkpoint removed coin"));
                }
            }
        }
        if next_checkpoint != (count != 0).then_some(count) {
            return Err(Error::Corrupt("wallet backup checkpoint tip"));
        }
        let anchor = if count == 0 {
            if tree_size != 0 {
                return Err(Error::Corrupt("wallet backup tree without scan history"));
            }
            None
        } else {
            Some(self.anchor()?)
        };
        for row in tx.open_table(COINS)?.iter()? {
            let (position, value) = row?;
            let coin = OwnedCoin::from_slice(value.value())?;
            if coin.position != position.value()
                || coin.position >= tree_size
                || u64::from(coin.height) >= count
                || coin
                    .spent_at
                    .is_some_and(|height| height < coin.height || u64::from(height) >= count)
                || coin.nullifier != coin.coin.nullifier(self.keys.nullifier_key())?
            {
                return Err(Error::Corrupt("wallet backup coin state"));
            }
            let block_start = heights
                .get(coin.height)?
                .ok_or(Error::Corrupt("wallet backup coin height"))?;
            let (_, block_start) = decode_height(block_start.value())?;
            let block_end = coin
                .height
                .checked_add(1)
                .and_then(|next| heights.get(next).transpose())
                .transpose()?
                .map(|value| decode_height(value.value()).map(|(_, position)| position))
                .transpose()?
                .unwrap_or(tree_size);
            if !(block_start..block_end).contains(&coin.position) {
                return Err(Error::Corrupt("wallet backup coin height"));
            }
            let address = self
                .keys
                .address_for_coin(&coin.coin, coin.legacy_address)?;
            // The legacy receiver key scans every diversifier, including the
            // portion of its 88-bit index space beyond the local u64 allocator.
            if !coin.legacy_address && !self.scans_address(&address)? {
                return Err(Error::Corrupt("wallet backup coin outside address range"));
            }
            if coin.spent_at.is_none() {
                let (path, _) = self.witness(coin.position)?;
                if Some(Anchor::from_base(path.root(coin.coin.cmx()?.inner()))) != anchor {
                    return Err(Error::Corrupt("wallet backup coin witness"));
                }
            }
        }
        let next_operation = meta
            .get(NEXT_OPERATION)?
            .map(|value| decode_u64(value.value()))
            .transpose()?
            .unwrap_or(1);
        let coins = self.coins()?;
        let mut normalized = Vec::new();
        for row in tx.open_table(OPERATIONS)?.iter()? {
            let (id, value) = row?;
            let mut operation = Operation::from_slice(value.value())?;
            if operation.id != id.value() || operation.id >= next_operation {
                return Err(Error::Corrupt("wallet backup operation id"));
            }
            let attempts = operation
                .transactions()
                .map(|bytes| Transaction::from_slice(bytes))
                .collect::<protocol::Result<Vec<_>>>()?;
            if let Some(expected) = operation.status.txid() {
                let active = operation
                    .transaction
                    .as_ref()
                    .map(|bytes| Transaction::from_slice(bytes))
                    .transpose()?;
                if !active.is_some_and(|transaction| transaction.txid() == expected) {
                    return Err(Error::Corrupt("wallet backup operation transaction id"));
                }
            }
            if matches!(operation.status, OperationStatus::Confirmed { height, .. }
                if u64::from(height) >= count)
            {
                return Err(Error::Corrupt("wallet backup operation confirmation"));
            }
            if operation
                .locked
                .iter()
                .any(|position| *position >= (1u64 << crate::tree::DEPTH))
            {
                return Err(Error::Corrupt("wallet backup operation position"));
            }
            if !attempts.is_empty() {
                let positions = coins
                    .iter()
                    .filter_map(|coin| {
                        attempts
                            .iter()
                            .any(|attempt| {
                                attempt
                                    .actions()
                                    .iter()
                                    .any(|action| action.body().nullifier() == &coin.nullifier)
                            })
                            .then_some(coin.position)
                    })
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                if operation.locked != positions {
                    operation.locked = positions;
                    normalized.push(operation);
                }
            }
        }
        Ok(normalized)
    }
}

#[cfg(test)]
mod tests {
    use crate::keys::WalletKeys;
    use crate::wallet::AddressScanRange;
    use crypto::commitment::ValueCommitment;
    use crypto::keys::SpendingKey;
    use crypto::pallas;
    use protocol::address::RhombusAddress;
    use protocol::amount::RawCoin;
    use protocol::coin::{Coin, RandomSeed, Rho};
    use protocol::compact::CompactAction;
    use protocol::compact::CompactBlock;
    use protocol::encryption::{encrypt_coin, COMPACT_COIN_LEAD};
    use protocol::nullifier::Nullifier;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    fn action(
        address: &RhombusAddress,
        value: u64,
        nullifier: Nullifier,
        rng: &mut ChaCha20Rng,
    ) -> CompactAction {
        let coin = Coin::new(
            *address.diversifier(),
            *address.pk_d(),
            RawCoin::from_raw(value).unwrap(),
            Rho::from_nullifier(&nullifier).unwrap(),
            RandomSeed::random(rng),
        );
        let encrypted = encrypt_coin(&coin, address.kem_key(), rng).unwrap();
        let mut enc_lead = [0; COMPACT_COIN_LEAD];
        enc_lead.copy_from_slice(&encrypted.enc_ciphertext()[..COMPACT_COIN_LEAD]);
        CompactAction {
            nullifier,
            cmx: coin.cmx().unwrap(),
            kem_ciphertext: encrypted.kem_ciphertext().clone(),
            enc_lead,
        }
    }

    fn fixture(path: &Path) -> Wallet {
        let mut rng = ChaCha20Rng::seed_from_u64(8801);
        let source = Wallet::create(
            path,
            &SpendingKey::random(&mut rng),
            BlockHash::ZERO,
            &mut rng,
        )
        .unwrap();
        let recipient = source.new_address("savings").unwrap().1;
        let actions = [19, 23]
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                action(
                    &recipient,
                    value,
                    Nullifier::from_base(&pallas::Base::from((index as u64).saturating_add(1))),
                    &mut rng,
                )
            })
            .collect();
        source
            .scan_compact(&CompactBlock {
                height: 0,
                hash: BlockHash::ZERO,
                actions,
            })
            .unwrap();
        let coins = source.coins().unwrap();
        let foreign = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
        source
            .scan_compact(&CompactBlock {
                height: 1,
                hash: BlockHash::from_bytes([2; 32]),
                actions: vec![action(
                    &foreign.default_address().unwrap(),
                    7,
                    coins[0].nullifier,
                    &mut rng,
                )],
            })
            .unwrap();
        source.reserve_send_address(true).unwrap();
        source.new_address("current receive").unwrap();
        let mut operation = source.add_operation(None, 1, 12345).unwrap();
        operation.locked.push(coins[1].position);
        source.put_operation(&operation).unwrap();
        source
    }

    #[test]
    fn backup_round_trip_preserves_keys_coins_witnesses_history_and_reservations() {
        let directory = tempfile::tempdir().unwrap();
        let source = fixture(&directory.path().join("source.redb"));
        let destination = directory.path().join("restored.redb");
        let backup = source.backup_json().unwrap();
        Wallet::restore_backup_json(&destination, &backup, BlockHash::ZERO).unwrap();
        let restored = Wallet::open(&destination, BlockHash::ZERO).unwrap();
        assert_eq!(restored.backup_json().unwrap(), backup);
        assert_eq!(
            restored.keys().spending_key().to_bytes(),
            source.keys().spending_key().to_bytes()
        );
        assert_eq!(restored.balance().unwrap(), 23);
        assert_eq!(restored.scanned_height().unwrap(), Some(1));
        assert_eq!(
            restored.scanned_hash(1).unwrap(),
            source.scanned_hash(1).unwrap()
        );
        assert_eq!(restored.anchor().unwrap(), source.anchor().unwrap());
        assert_eq!(restored.addresses().unwrap(), source.addresses().unwrap());
        assert_eq!(
            restored.current_receive_address().unwrap(),
            source.current_receive_address().unwrap()
        );
        assert_eq!(
            restored.locked_positions().unwrap(),
            source.locked_positions().unwrap()
        );
        assert_eq!(restored.operations().unwrap(), source.operations().unwrap());
        let unspent = restored.unspent().unwrap().remove(0);
        let (path, anchor) = restored.witness(unspent.position).unwrap();
        assert_eq!(
            Anchor::from_base(path.root(unspent.coin.cmx().unwrap().inner())),
            anchor
        );
        // Spending after restoration must use the rebuilt nullifier index.
        restored
            .scan_compact(&CompactBlock {
                height: 2,
                hash: BlockHash::from_bytes([3; 32]),
                actions: vec![action(
                    &restored.keys().default_address().unwrap(),
                    1,
                    unspent.nullifier,
                    &mut ChaCha20Rng::seed_from_u64(8802),
                )],
            })
            .unwrap();
        assert_eq!(
            restored
                .coins()
                .unwrap()
                .iter()
                .find(|coin| coin.position == unspent.position)
                .unwrap()
                .spent_at,
            Some(2)
        );
        let next = source.address_scan_range().unwrap().end;
        assert_eq!(restored.new_address("after restore").unwrap().0, next);
        drop(restored);
        assert!(Wallet::open(&destination, BlockHash::ZERO).is_ok());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(destination).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    fn change_meta(backup: &mut serde_json::Value, name: &str, bytes: &[u8]) {
        let rows = backup["tables"]["meta"].as_array_mut().unwrap();
        let row = rows.iter_mut().find(|row| row["key"] == name).unwrap();
        row["value_hex"] = crypto::encoding::to_hex(bytes).into();
    }

    fn assert_rejected_without_destination(directory: &Path, backup: &serde_json::Value) {
        let destination = directory.join("rejected.redb");
        assert!(Wallet::restore_backup_json(
            &destination,
            &serde_json::to_vec(backup).unwrap(),
            BlockHash::ZERO,
        )
        .is_err());
        assert!(!destination.exists());
        assert!(!std::fs::read_dir(directory).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".rhombus-wallet-restore-")));
    }

    #[test]
    fn backup_rejects_coin_heights_outside_their_recorded_block_positions() {
        let directory = tempfile::tempdir().unwrap();
        let source = fixture(&directory.path().join("source.redb"));
        let mut rng = ChaCha20Rng::seed_from_u64(8802);
        source
            .scan_compact(&CompactBlock {
                height: 2,
                hash: BlockHash::from_bytes([3; 32]),
                actions: vec![action(
                    &source.keys().default_address().unwrap(),
                    7,
                    Nullifier::from_base(&pallas::Base::from(42)),
                    &mut rng,
                )],
            })
            .unwrap();
        let bytes = source.backup_json().unwrap();
        let valid: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        // Positions 0 (spent) and 1 (unspent) belong to block 0, while
        // position 3 belongs to block 2. Every substituted height exists.
        for (position, height) in [(0, 1), (1, 1), (3, 0)] {
            let mut invalid = valid.clone();
            let row = invalid["tables"]["coins"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|row| row["key"] == position)
                .unwrap();
            let mut coin = OwnedCoin::from_slice(
                &crypto::encoding::from_hex(row["value_hex"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
            coin.height = height;
            row["value_hex"] = crypto::encoding::to_hex(&coin.to_vec()).into();
            assert_rejected_without_destination(directory.path(), &invalid);
        }
        let destination = directory.path().join("restored.redb");
        Wallet::restore_backup_json(&destination, &bytes, BlockHash::ZERO).unwrap();
        let restored = Wallet::open(destination, BlockHash::ZERO).unwrap();
        assert_eq!(restored.backup_json().unwrap(), bytes);
        // The original heights retain both earlier coins during rollback,
        // resurrect the spent one, and discard the actual later receipt.
        restored.rollback_to(0).unwrap();
        assert_eq!(restored.balance().unwrap(), 42);
        for coin in restored.unspent().unwrap() {
            let (path, anchor) = restored.witness(coin.position).unwrap();
            assert_eq!(
                Anchor::from_base(path.root(coin.coin.cmx().unwrap().inner())),
                anchor
            );
        }
    }

    #[test]
    fn backup_restores_legacy_coins_beyond_the_local_address_index_space() {
        use crypto::diversifier::DiversifierIndex;

        let directory = tempfile::tempdir().unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(8803);
        let source = Wallet::create(
            directory.path().join("source.redb"),
            &SpendingKey::random(&mut rng),
            BlockHash::ZERO,
            &mut rng,
        )
        .unwrap();
        let mut index = [0; crypto::keys::DIVERSIFIER_LEN];
        index[8] = 1; // 2^64: valid in the 88-bit legacy diversifier space.
        let recipient = source
            .keys()
            .legacy_address(DiversifierIndex::from_bytes(index))
            .unwrap();
        source
            .scan_compact(&CompactBlock {
                height: 0,
                hash: BlockHash::ZERO,
                actions: [19, 23]
                    .into_iter()
                    .enumerate()
                    .map(|(index, value)| {
                        action(
                            &recipient,
                            value,
                            Nullifier::from_base(&pallas::Base::from(index as u64 + 1)),
                            &mut rng,
                        )
                    })
                    .collect(),
            })
            .unwrap();
        let coins = source.coins().unwrap();
        assert!(coins.iter().all(|coin| coin.legacy_address));
        let foreign = WalletKeys::from_spending_key(SpendingKey::random(&mut rng)).unwrap();
        source
            .scan_compact(&CompactBlock {
                height: 1,
                hash: BlockHash::from_bytes([4; 32]),
                actions: vec![action(
                    &foreign.default_address().unwrap(),
                    7,
                    coins[0].nullifier,
                    &mut rng,
                )],
            })
            .unwrap();
        let bytes = source.backup_json().unwrap();
        let destination = directory.path().join("restored.redb");
        Wallet::restore_backup_json(&destination, &bytes, BlockHash::ZERO).unwrap();
        let restored = Wallet::open(destination, BlockHash::ZERO).unwrap();
        assert_eq!(restored.backup_json().unwrap(), bytes);
        assert_eq!(restored.balance().unwrap(), 23);
        restored.witness(coins[1].position).unwrap();
        restored.rollback_to(0).unwrap();
        assert_eq!(restored.balance().unwrap(), 42);
        for coin in restored.unspent().unwrap() {
            assert_eq!(
                restored.keys().address_for_coin(&coin.coin, true).unwrap(),
                recipient
            );
            let (path, anchor) = restored.witness(coin.position).unwrap();
            assert_eq!(
                Anchor::from_base(path.root(coin.coin.cmx().unwrap().inner())),
                anchor
            );
        }
    }

    #[test]
    fn backup_rejects_checkpoint_gaps_positions_and_contradictory_removed_marks() {
        use shardtree::store::{Checkpoint, TreeState};

        let directory = tempfile::tempdir().unwrap();
        let source = fixture(&directory.path().join("source.redb"));
        for height in 2..=3 {
            source
                .scan_compact(&CompactBlock {
                    height,
                    hash: BlockHash::from_bytes([height as u8; 32]),
                    actions: vec![],
                })
                .unwrap();
        }
        let valid: serde_json::Value =
            serde_json::from_slice(&source.backup_json().unwrap()).unwrap();
        let mut gap = valid.clone();
        gap["tables"]["checkpoints"]
            .as_array_mut()
            .unwrap()
            .remove(1);
        assert_rejected_without_destination(directory.path(), &gap);

        let mut wrong_position = valid.clone();
        let checkpoint =
            Checkpoint::from_parts(TreeState::AtPosition(0u64.into()), BTreeSet::new());
        wrong_position["tables"]["checkpoints"][0]["value_hex"] =
            crypto::encoding::to_hex(&crate::tree::encode_checkpoint(&checkpoint)).into();
        assert_rejected_without_destination(directory.path(), &wrong_position);

        let mut wrong_marks = valid.clone();
        let checkpoint = Checkpoint::from_parts(
            TreeState::AtPosition(2u64.into()),
            [1u64.into()].into_iter().collect(),
        ); // coin 1 was never spent
        wrong_marks["tables"]["checkpoints"][1]["value_hex"] =
            crypto::encoding::to_hex(&crate::tree::encode_checkpoint(&checkpoint)).into();
        assert_rejected_without_destination(directory.path(), &wrong_marks);

        let mut missing_tip = valid.clone();
        missing_tip["tables"]["checkpoints"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert_rejected_without_destination(directory.path(), &missing_tip);
    }

    #[test]
    fn backup_accepts_pruned_checkpoint_suffix_after_rollback_and_preserves_further_rollback() {
        let directory = tempfile::tempdir().unwrap();
        let source = fixture(&directory.path().join("source.redb"));
        let final_height = u32::try_from(crate::tree::MAX_CHECKPOINTS).unwrap() + 10;
        for height in 2..=final_height {
            source
                .scan_compact(&CompactBlock {
                    height,
                    hash: BlockHash::from_bytes([0; 32]),
                    actions: vec![],
                })
                .unwrap();
        }
        let oldest = source.oldest_checkpoint().unwrap().unwrap();
        assert!(oldest > 0);
        source.rollback_to(100).unwrap();
        assert_eq!(source.oldest_checkpoint().unwrap(), Some(oldest));
        let backup = source.backup_json().unwrap();
        let destination = directory.path().join("restored.redb");
        Wallet::restore_backup_json(&destination, &backup, BlockHash::ZERO).unwrap();
        let restored = Wallet::open(destination, BlockHash::ZERO).unwrap();
        assert_eq!(restored.backup_json().unwrap(), backup);
        restored.rollback_to(oldest).unwrap();
        assert_eq!(restored.scanned_height().unwrap(), Some(oldest));
        assert_eq!(restored.balance().unwrap(), 23);
        let coin = restored.unspent().unwrap().remove(0);
        assert!(restored.witness(coin.position).is_ok());
    }

    /// Structurally encoded transactions isolate backup metadata validation;
    /// dummy proofs/signatures here do not establish transaction authorization.
    fn recorded_transaction(nullifier: Nullifier, salt: u8) -> Transaction {
        use protocol::bytes::Writer;
        use protocol::consensus::{proof_len, TRANSFER_KIND, TX_VERSION};
        let mut writer = Writer::default();
        writer
            .put_u8(TX_VERSION)
            .put_u8(TRANSFER_KIND)
            .put(&[0; 32])
            .put_u64_le(0)
            .put_u8(2);
        let rk = crypto::encoding::point_to_bytes(&crypto::curve::Generator::SpendAuth.point());
        for nf in [
            nullifier,
            Nullifier::from_base(&pallas::Base::from(u64::from(salt))),
        ] {
            writer
                .put(&nf.to_bytes())
                .put(&rk)
                .put(&[0; 32])
                .put(&ValueCommitment::identity().to_bytes())
                .put_u8(protocol::encryption::ENCRYPTED_COIN_VERSION)
                .put(&vec![0; protocol::encryption::ENCRYPTED_COIN_LEN - 1]);
        }
        writer
            .put(&[0; 2 * crypto::signature::SIGNATURE_LEN])
            .put(protocol::transaction::ACTION_PROOF_MAGIC)
            .put(&vec![0; proof_len(2).unwrap()])
            .put(&[0; crypto::signature::SIGNATURE_LEN]);
        Transaction::from_slice(&writer.into_bytes()).unwrap()
    }

    #[test]
    fn backup_rejects_operation_status_that_disagrees_with_recorded_transaction() {
        let directory = tempfile::tempdir().unwrap();
        let source = fixture(&directory.path().join("source.redb"));
        let transaction = recorded_transaction(source.coins().unwrap()[1].nullifier, 10);
        let mut operation = source.operations().unwrap().remove(0);
        operation.record_transaction(transaction.to_vec());
        let wrong_txid = protocol::transaction::TxId::from_bytes([99; 32]);
        for status in [
            OperationStatus::Submitted {
                txid: wrong_txid,
                built_at: 1,
            },
            OperationStatus::Confirmed {
                txid: wrong_txid,
                height: 1,
            },
            OperationStatus::Confirmed {
                txid: transaction.txid(),
                height: 2,
            },
        ] {
            operation.status = status;
            source.put_operation(&operation).unwrap();
            let backup: serde_json::Value =
                serde_json::from_slice(&source.backup_json().unwrap()).unwrap();
            assert_rejected_without_destination(directory.path(), &backup);
        }
        operation.transaction = None;
        operation.status = OperationStatus::Submitted {
            txid: transaction.txid(),
            built_at: 1,
        };
        source.put_operation(&operation).unwrap();
        let backup: serde_json::Value =
            serde_json::from_slice(&source.backup_json().unwrap()).unwrap();
        assert_rejected_without_destination(directory.path(), &backup);
    }

    #[test]
    fn backup_rebuilds_recorded_locks_after_reorg_without_forgetting_previous_attempts() {
        let directory = tempfile::tempdir().unwrap();
        let source = fixture(&directory.path().join("source.redb"));
        let coins = source.coins().unwrap();
        let first = recorded_transaction(coins[0].nullifier, 10);
        let second = recorded_transaction(coins[1].nullifier, 11);
        let mut operation = source.operations().unwrap().remove(0);
        operation.record_transaction(first.to_vec());
        operation.record_transaction(second.to_vec());
        operation.status = OperationStatus::Confirmed {
            txid: second.txid(),
            height: 1,
        };
        operation.attempts = 2;
        // This is a legitimate post-reorg state: the coin at position 0 is
        // unspent again, and stale position reservations may survive rollback.
        source.put_operation(&operation).unwrap();
        source.rollback_to(0).unwrap();
        operation = source.operation(operation.id).unwrap();
        assert!(matches!(
            operation.status,
            OperationStatus::Submitted { .. }
        ));
        operation.locked = vec![123, 123];
        source.put_operation(&operation).unwrap();
        let destination = directory.path().join("restored.redb");
        Wallet::restore_backup_json(
            &destination,
            &source.backup_json().unwrap(),
            BlockHash::ZERO,
        )
        .unwrap();
        let restored = Wallet::open(destination, BlockHash::ZERO).unwrap();
        let actual = restored.operation(operation.id).unwrap();
        let mut expected = operation.clone();
        expected.locked = vec![0, 1];
        assert_eq!(actual, expected);
        assert_eq!(restored.locked_positions().unwrap(), vec![0, 1]);
        assert_eq!(restored.balance().unwrap(), 42);
        assert_eq!(actual.previous_transactions, vec![first.to_vec()]);
        assert_eq!(actual.transaction, Some(second.to_vec()));
    }

    #[test]
    fn backup_rejects_invalid_state_without_publishing_or_leaking_staging_files() {
        let directory = tempfile::tempdir().unwrap();
        let source = fixture(&directory.path().join("source.redb"));
        let valid: serde_json::Value =
            serde_json::from_slice(&source.backup_json().unwrap()).unwrap();
        let mut invalid = Vec::new();
        let mut changed = valid.clone();
        changed["version"] = 2.into();
        invalid.push(changed);
        let mut changed = valid.clone();
        changed["format"] = "rhombus-wallet-backup".into();
        invalid.push(changed);
        let mut changed = valid.clone();
        changed["tables"]["meta"]
            .as_array_mut()
            .unwrap()
            .retain(|row| row["key"] != NEXT_ADDRESS);
        invalid.push(changed);
        let mut changed = valid.clone();
        change_meta(&mut changed, FINGERPRINT, &[0; 32]);
        invalid.push(changed);
        let mut changed = valid.clone();
        change_meta(&mut changed, crate::wallet::AUTO_ROTATE_RECEIVE, &[2]);
        invalid.push(changed);
        let mut changed = valid.clone();
        change_meta(&mut changed, NEXT_ADDRESS, &1u64.to_le_bytes());
        invalid.push(changed);
        let mut changed = valid.clone();
        changed["tables"]["coins"][0]["value_hex"] = "not-hex".into();
        invalid.push(changed);
        let mut changed = valid.clone();
        changed["tables"]["coins"][0]["key"] = 100.into();
        invalid.push(changed);
        let mut changed = valid.clone();
        changed["tables"]["shards"][0]["value_hex"] = "ff".into();
        invalid.push(changed);
        let mut changed = valid.clone();
        changed["tables"]["heights"][0]["key"] = 42.into();
        invalid.push(changed);
        let mut changed = valid.clone();
        changed["tables"]["operations"][0]["key"] = 42.into();
        invalid.push(changed);
        let mut changed = valid.clone();
        let duplicate = changed["tables"]["meta"][0].clone();
        changed["tables"]["meta"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        invalid.push(changed);
        let destination = directory.path().join("restored.redb");
        for (index, bad) in invalid.into_iter().enumerate() {
            assert!(
                Wallet::restore_backup_json(
                    &destination,
                    &serde_json::to_vec(&bad).unwrap(),
                    BlockHash::ZERO
                )
                .is_err(),
                "case {index}"
            );
            assert!(!destination.exists(), "case {index}");
            assert_eq!(
                std::fs::read_dir(directory.path()).unwrap().count(),
                1,
                "case {index}"
            );
        }
        assert!(Wallet::restore_backup_json(&destination, b"{broken", BlockHash::ZERO).is_err());
        assert!(Wallet::restore_backup_json(
            &destination,
            &source.backup_json().unwrap(),
            BlockHash::from_bytes([9; 32])
        )
        .is_err());
        assert!(!destination.exists());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn backup_never_overwrites_existing_destinations_or_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let source = fixture(&directory.path().join("source.redb"));
        let bytes = source.backup_json().unwrap();
        let destination = directory.path().join("existing");
        std::fs::write(&destination, b"original").unwrap();
        assert!(Wallet::restore_backup_json(&destination, &bytes, BlockHash::ZERO).is_err());
        assert_eq!(std::fs::read(&destination).unwrap(), b"original");
        #[cfg(unix)]
        {
            let symlink = directory.path().join("symlink");
            std::os::unix::fs::symlink(&destination, &symlink).unwrap();
            assert!(Wallet::restore_backup_json(&symlink, &bytes, BlockHash::ZERO).is_err());
            assert_eq!(std::fs::read(&destination).unwrap(), b"original");
        }
    }

    #[test]
    fn backup_round_trip_accepts_empty_and_migrated_legacy_wallets() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.redb");
        let mut rng = ChaCha20Rng::seed_from_u64(8803);
        let source = Wallet::create(
            &path,
            &SpendingKey::random(&mut rng),
            BlockHash::ZERO,
            &mut rng,
        )
        .unwrap();
        let empty = source.backup_json().unwrap();
        let destination = directory.path().join("empty.redb");
        Wallet::restore_backup_json(&destination, &empty, BlockHash::ZERO).unwrap();
        assert_eq!(
            Wallet::open(destination, BlockHash::ZERO)
                .unwrap()
                .backup_json()
                .unwrap(),
            empty
        );
        // A missing automatic-rotation preference defaults to enabled.
        let mut old_backup: serde_json::Value = serde_json::from_slice(&empty).unwrap();
        old_backup["tables"]["meta"]
            .as_array_mut()
            .unwrap()
            .retain(|row| row["key"] != crate::wallet::AUTO_ROTATE_RECEIVE);
        let old_backup = serde_json::to_vec(&old_backup).unwrap();
        let old_destination = directory.path().join("old-empty.redb");
        Wallet::restore_backup_json(&old_destination, &old_backup, BlockHash::ZERO).unwrap();
        let old_restored = Wallet::open(&old_destination, BlockHash::ZERO).unwrap();
        assert!(old_restored.auto_rotate_receive().unwrap());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&old_restored.backup_json().unwrap())
                .unwrap(),
            serde_json::from_slice::<serde_json::Value>(&old_backup).unwrap()
        );

        source.set_auto_rotate_receive(false).unwrap();
        let rotation_backup = source.backup_json().unwrap();
        let rotation_destination = directory.path().join("rotation-off.redb");
        Wallet::restore_backup_json(&rotation_destination, &rotation_backup, BlockHash::ZERO)
            .unwrap();
        assert!(!Wallet::open(&rotation_destination, BlockHash::ZERO)
            .unwrap()
            .auto_rotate_receive()
            .unwrap());

        let tx = source.db.begin_write().unwrap();
        {
            let mut meta = tx.open_table(META).unwrap();
            meta.remove(ADDRESS_KEY_SCHEME).unwrap();
            meta.remove(ADDRESS_KEY_START).unwrap();
            meta.insert(NEXT_ADDRESS, 5001u64.to_le_bytes().as_slice())
                .unwrap();
        }
        tx.commit().unwrap();
        drop(source);
        let source = Wallet::open(&path, BlockHash::ZERO).unwrap();
        let legacy = source.backup_json().unwrap();
        let destination = directory.path().join("legacy.redb");
        Wallet::restore_backup_json(&destination, &legacy, BlockHash::ZERO).unwrap();
        let restored = Wallet::open(&destination, BlockHash::ZERO).unwrap();
        assert_eq!(restored.backup_json().unwrap(), legacy);
        assert_eq!(
            restored.keys().default_address().unwrap(),
            source.keys().default_address().unwrap()
        );
        assert_eq!(
            restored.address_scan_range().unwrap(),
            AddressScanRange {
                start: 5001,
                end: 5001
            }
        );
    }
}
