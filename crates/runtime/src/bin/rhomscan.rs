//! Scan a local Rhombus chain into a wallet.

use std::path::PathBuf;

use clap::Parser;
use protocol::compact::CompactBlock;
use runtime::config::Network;
use runtime::paths;
use storage::store::Store;
use wallet::wallet::Wallet;

#[derive(Debug, Parser)]
#[command(
    name = "rhomscan",
    version,
    about = "Scan a local Rhombus chain into a wallet"
)]
struct Args {
    /// Chain network.
    #[arg(long, default_value = "main")]
    network: Network,
    /// Chain database; defaults to rhombus-data/<network>/chain/chain.redb.
    #[arg(long)]
    chain: Option<PathBuf>,
    /// Wallet database; defaults to rhombus-data/<network>/wallet.redb.
    #[arg(long)]
    wallet: Option<PathBuf>,
    /// Scan compact blocks. Memos will not be recovered.
    #[arg(long)]
    light: bool,
    /// Print each note found while scanning.
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
            .join("rhombus-data")
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
    let wallet = Wallet::open(&wallet_path, genesis.hash())?;
    let tip = store
        .tip()?
        .ok_or_else(|| runtime::Error::Argument("chain has no genesis block".into()))?;

    let mut next = wallet.next_height()?;
    while next > 0 {
        let Some(wallet_hash) = wallet.scanned_hash(next - 1)? else {
            next -= 1;
            continue;
        };
        if next - 1 <= tip.height && store.hash_at(next - 1)? == Some(wallet_hash) {
            break;
        }
        if next < 2 {
            return Err(runtime::Error::Argument(
                "wallet genesis does not match the local chain".into(),
            ));
        }
        wallet.rollback_to(next - 2)?;
        next = wallet.next_height()?;
    }

    let start = next;
    while next <= tip.height {
        let hash = store
            .hash_at(next)?
            .ok_or_else(|| runtime::Error::Argument(format!("missing block at height {next}")))?;
        let block = store.block(&hash)?.ok_or_else(|| {
            runtime::Error::Argument(format!("missing block data at height {next}"))
        })?;
        if args.light {
            let compact = CompactBlock::from_block(&block)?;
            wallet.scan_compact(&compact)?;
        } else {
            wallet.scan(&block)?;
        }
        if args.verbose {
            for note in wallet
                .notes()?
                .into_iter()
                .filter(|note| note.height == next && note.txid.is_some())
            {
                println!(
                    "found note: height={} position={} value={}",
                    note.height,
                    note.position,
                    note.note.value().raw()
                );
            }
        }
        println!("scanned height {next}/{}", tip.height);
        next = next.saturating_add(1);
    }

    println!("network: {}", args.network);
    println!("chain tip: {} ({})", tip.height, tip.hash);
    println!(
        "new blocks scanned: {}",
        tip.height.saturating_add(1).saturating_sub(start)
    );
    println!("balance: {} raw", wallet.balance()?);
    println!("unspent notes: {}", wallet.unspent()?.len());
    Ok(())
}
