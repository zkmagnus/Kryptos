//! The `kryptos` binary.

use clap::Parser;

#[tokio::main]
async fn main() {
    let cli = runtime::cli::Cli::parse();
    if let Err(error) = runtime::cli::run(cli).await {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
