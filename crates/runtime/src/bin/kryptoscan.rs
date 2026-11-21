//! Scan a local Kryptos chain into a wallet.

use std::path::PathBuf;

use clap::Parser;
use protocol::compact::CompactBlock;
use runtime::config::Network;
use runtime::paths;
use storage::store::Store;
use wallet::wallet::Wallet;

#[derive(Debug, Parser)]
#[command(
    name = "kryptoscan",
    version,
    about = "Scan a local Kryptos chain into a wallet"
)]
struct Args {
    /// Chain network.
    #[arg(long, default_value = "main")]
    network: Network,
    /// Chain database; defaults to kryptos-data/<network>/chain/chain.redb.
    #[arg(long)]
    chain: Option<PathBuf>,
    /// Wallet database; defaults to kryptos-data/<network>/wallet.redb.
    #[arg(long)]
    wallet: Option<PathBuf>,
    #[arg(long)]
    light: bool,
    /// Print each coin found while scanning.
    #[arg(long)]
    verbose: bool,
}

fn main() {
    if let Err(error) = run(Args::parse()) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run(args: Args) -> runtime::Result<()> {
    let network_dir = match (args.chain.as_ref(), args.wallet.as_ref()) {
        (None, None) => paths::default_network_dir(args.network)?,
        _ => std::env::current_dir()?
            .join("kryptos-data")
            .join(args.network.to_string()),
    };
    let chain_path = args
        .chain
        .unwrap_or_else(|| paths::chain_dir(&network_dir).join("chain.redb"));
    let wallet_path = args
        .wallet
        .unwrap_or_else(|| paths::wallet_file(&network_dir));
    let genesis = chain::genesis::genesis(&args.network.params());
    let store = Store::open(&chain_path)?;
    let tip = store
        .tip()?
        .ok_or_else(|| runtime::Error::Argument("chain has no genesis block".into()))?;
    if store.hash_at(0)? != Some(genesis.hash()) {
        return Err(runtime::Error::Argument(
            "wallet genesis does not match the local chain".into(),
        ));
    }
    let wallet = Wallet::open(&wallet_path, genesis.hash())?;
    prepare_scan(&store, &wallet, tip.height)?;

    let start = wallet.next_height()?;
    for height in start..=tip.height {
        let hash = store
            .hash_at(height)?
            .ok_or_else(|| runtime::Error::Argument(format!("missing block at height {height}")))?;
        let block = store.block(&hash)?.ok_or_else(|| {
            runtime::Error::Argument(format!("missing block data at height {height}"))
        })?;
        if args.light {
            let compact = CompactBlock::from_block(&block)?;
            wallet.scan_compact(&compact)?;
        } else {
            wallet.scan(&block)?;
        }
        if args.verbose {
            for coin in wallet
                .coins()?
                .into_iter()
                .filter(|coin| coin.height == height && coin.txid.is_some())
            {
                println!(
                    "found coin: height={} position={} value={}",
                    coin.height,
                    coin.position,
                    coin.coin.value().raw()
                );
            }
        }
        println!("scanned height {height}/{}", tip.height);
    }

    println!("network: {}", args.network);
    println!("chain tip: {} ({})", tip.height, tip.hash);
    println!(
        "new blocks scanned: {}",
        tip.height.saturating_add(1).saturating_sub(start)
    );
    println!("balance: {} raw", wallet.balance()?);
    println!("unspent coins: {}", wallet.unspent()?.len());
    Ok(())
}

fn prepare_scan(store: &Store, wallet: &Wallet, tip: u32) -> runtime::Result<()> {
    if let Some((base, hash)) = wallet.scan_base()? {
        if base > tip || store.hash_at(base)? != Some(hash) {
            wallet.reset_scan_to_genesis()?;
        }
    } else if let Some(base) = wallet
        .birthday_height()?
        .checked_sub(1)
        .filter(|h| *h <= tip)
    {
        let checkpoint = match store.hash_at(base)? {
            Some(hash) => store.header(&hash)?.zip(store.commitment_tree_at(&hash)?),
            None => None,
        };
        if let Some((header, tree)) = checkpoint {
            wallet.initialize_scan_checkpoint(&header, tree.frontier())?;
        } else {
            wallet.reset_scan_to_genesis()?;
        }
    }

    let Some(scanned) = wallet.scanned_height()? else {
        return Ok(());
    };
    if scanned <= tip && wallet.scanned_hash(scanned)? == store.hash_at(scanned)? {
        return Ok(());
    }
    if let Some(oldest) = wallet.oldest_checkpoint()? {
        for height in (oldest..=scanned.saturating_sub(1).min(tip)).rev() {
            if let Some(hash) = wallet.scanned_hash(height)? {
                if store.hash_at(height)? == Some(hash) {
                    wallet.rewind_after_reorg(Some(height))?;
                    return Ok(());
                }
            }
        }
    }
    wallet.rewind_after_reorg(None)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::path::Path;

    use crypto::keys::SpendingKey;
    use protocol::block::{empty_header, Block};

    use super::*;

    #[test]
    fn local_scan_imports_the_birthday_frontier_and_replays_if_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let chain_path = dir.path().join("chain.redb");
        let (genesis, tree) = chain::genesis::genesis_with_tree(&Network::Test.params());
        let original = {
            let store = Store::open(&chain_path).unwrap();
            store.apply(&genesis, &tree, &[0; 32]).unwrap();
            let mut header = empty_header(1, genesis.hash(), tree.root());
            header.history_root = store
                .header_frontier(&genesis.hash())
                .unwrap()
                .unwrap()
                .root();
            let original = Block::new(header, vec![]);
            store.apply(&original, &tree, &[0; 32]).unwrap();
            original
        };
        let scan = |wallet_path: &Path, light| {
            run(Args {
                network: Network::Test,
                chain: Some(chain_path.clone()),
                wallet: Some(wallet_path.to_path_buf()),
                light,
                verbose: false,
            })
            .unwrap();
            Wallet::open(wallet_path, genesis.hash()).unwrap()
        };
        let modes = [
            (dir.path().join("full.redb"), false),
            (dir.path().join("compact.redb"), true),
        ];
        for (wallet_path, light) in &modes {
            Wallet::create_with_birthday(
                wallet_path,
                &SpendingKey::from_bytes([31; 32]),
                genesis.hash(),
                2,
                &mut rand::rngs::OsRng,
            )
            .unwrap();
            let wallet = scan(wallet_path, *light);
            assert_eq!(wallet.scan_base().unwrap(), Some((1, original.hash())));
            assert_eq!(wallet.scanned_hash(0).unwrap(), None);
        }
        let replacement = {
            let store = Store::open(&chain_path).unwrap();
            store.revert().unwrap();
            let mut header = original.header().clone();
            header.timestamp = header.timestamp.saturating_add(1);
            let replacement = Block::new(header, vec![]);
            store.apply(&replacement, &tree, &[0; 32]).unwrap();
            replacement
        };
        for (wallet_path, light) in &modes {
            let wallet = scan(wallet_path, *light);
            assert_eq!(wallet.scan_base().unwrap(), None);
            assert_eq!(wallet.scanned_hash(0).unwrap(), Some(genesis.hash()));
            assert_eq!(wallet.scanned_hash(1).unwrap(), Some(replacement.hash()));
            assert_eq!(wallet.next_height().unwrap(), 2);
        }
    }
}
