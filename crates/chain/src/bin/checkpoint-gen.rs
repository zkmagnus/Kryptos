//! Emit a checkpoint tuple from deterministic genesis or a locally opened chain.

use std::env;
use std::path::PathBuf;

use chain::chain::Chain;
use chain::genesis::genesis;
use chain::params::ChainParams;
use chain::target::ChainWork;
use protocol::block::BlockHash;
use storage::store::Store;
use transaction_proof::VerifyingKey;

fn main() {
    if let Err(error) = run() {
        eprintln!("checkpoint-gen: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("--genesis") => {
            let network = parse_network(args.next().as_deref())?;
            ensure_no_more(args)?;
            let params = network_params(network);
            let block = genesis(&params);
            print_checkpoint(
                0,
                block.hash(),
                ChainWork::ZERO,
                block.header().state_root.to_bytes(),
            );
        }
        Some("--db") => {
            let database = args
                .next()
                .map(PathBuf::from)
                .ok_or("expected chain database path after --db")?;
            let mut network = None;
            let mut height = None;
            while let Some(option) = args.next() {
                match option.as_str() {
                    "--network" => network = Some(parse_network(args.next().as_deref())?),
                    "--height" => {
                        height = Some(
                            args.next()
                                .ok_or("expected height after --height")?
                                .parse::<u32>()?,
                        );
                    }
                    _ => return Err(format!("unknown option {option}").into()),
                }
            }
            let network = network.ok_or("--network is required with --db")?;
            let height = height.ok_or("--height is required with --db")?;
            let params = network_params(network);
            let chain = Chain::new(Store::open(database)?, params, VerifyingKey::build()?)?;
            let hash = chain
                .store()
                .hash_at(height)?
                .ok_or("requested height is not in the canonical chain")?;
            let header = chain
                .store()
                .header(&hash)?
                .ok_or("checkpoint header is missing")?;
            let work = chain
                .store()
                .chainwork(&hash)?
                .map(ChainWork::from_be_bytes)
                .ok_or("checkpoint work is missing")?;
            print_checkpoint(height, hash, work, header.state_root.to_bytes());
        }
        _ => {
            return Err("usage: checkpoint-gen --genesis <mainnet|testnet> | --db <path> --network <mainnet|testnet> --height <height>".into());
        }
    }
    Ok(())
}

fn parse_network(name: Option<&str>) -> Result<&'static str, Box<dyn std::error::Error>> {
    match name {
        Some("mainnet") => Ok("mainnet"),
        Some("testnet") => Ok("testnet"),
        _ => Err("network must be mainnet or testnet".into()),
    }
}

fn network_params(name: &str) -> ChainParams {
    match name {
        "mainnet" => ChainParams::mainnet(),
        _ => ChainParams::test(),
    }
}

fn ensure_no_more(
    mut args: impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if args.next().is_some() {
        return Err("unexpected extra arguments".into());
    }
    Ok(())
}

fn print_checkpoint(height: u32, hash: BlockHash, work: ChainWork, state_root: [u8; 32]) {
    println!("{{");
    println!("  \"height\": {height},");
    println!("  \"hash\": \"{}\",", hex(hash.as_bytes()));
    println!("  \"work\": \"{}\",", hex(&work.to_be_bytes()));
    println!("  \"state_root\": \"{}\"", hex(&state_root));
    println!("}}");
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use core::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}
