//! The `rhombus-wallet-rpc` binary.

use clap::Parser;

#[tokio::main]
async fn main() {
    let args = runtime::walletd::Args::parse();
    if let Err(error) = runtime::walletd::main(args).await {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
