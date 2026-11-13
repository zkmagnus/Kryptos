//! The `RawCoin` command line.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use chain::genesis::genesis;
use clap::{Parser, Subcommand};
use crypto::encoding::{from_hex, to_hex};
use crypto::keys::SpendingKey;
use protocol::address::RhombusAddress;
use protocol::amount::RawCoin;
use protocol::block::{Block, BlockHash};
use protocol::bytes::Encodable;
use protocol::compact::CompactBlock;
use protocol::consensus::{next_height, BranchId};
use protocol::memo::Memo;
use systemcall_proof::ProvingKey;
use wallet::keys::WalletKeys;
use wallet::seed::SeedPhrase;
use wallet::spend::{build_payments, build_payments_with_fee, Payment, MAX_RECIPIENTS};
use wallet::wallet::Wallet;

use crate::config::{Config, Network};
use crate::paths;
use crate::rpc::{Client, Control, Endpoint, Token, TOKEN_FILE};
use crate::shutdown::Shutdown;
use crate::{Error, Result};

/// Default control socket.
const DEFAULT_RPC: &str = "127.0.0.1:18444";
/// Default JSON-RPC HTTP listener.
const DEFAULT_RPC_HTTP: &str = "127.0.0.1:18443";
/// Environment variable that supplies the control socket token.
const TOKEN_ENV: &str = "RPC_TOKEN";
/// Environment variable that supplies a seed phrase to restore from.
const PHRASE_ENV: &str = "SEED_PHRASE";

/// The node daemon and wallet tools.
#[derive(Parser, Debug)]
#[command(name = "RawCoin", version)]
pub struct Cli {
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// Wallet file used by a wallet command.
#[derive(clap::Args, Debug)]
pub struct WalletArgs {
    /// Wallet file.
    #[arg(long)]
    pub wallet: PathBuf,
}

/// How a command reaches a node's control socket.
#[derive(clap::Args, Debug)]
pub struct RpcArgs {
    /// Node control socket.
    #[arg(long, default_value = DEFAULT_RPC)]
    pub rpc: String,
    /// The node's token; also read from `RPC_TOKEN`.
    #[arg(long, env = TOKEN_ENV, conflicts_with = "rpc_token_file", hide_env_values = true)]
    pub rpc_token: Option<String>,
    /// File holding the node's token, such as `rpc.token` in its data
    /// directory.
    #[arg(long)]
    pub rpc_token_file: Option<PathBuf>,
}

impl RpcArgs {
    /// The token from the flag, the environment or the file.
    ///
    /// # Errors
    /// Returns [`Error::Argument`] when none was given.
    pub fn token(&self) -> Result<Token> {
        match (&self.rpc_token, &self.rpc_token_file) {
            (Some(text), _) => Token::new(text),
            (None, Some(path)) => Token::from_file(path),
            (None, None) => Err(Error::Argument(format!(
                "pass --rpc-token, --rpc-token-file or set {TOKEN_ENV}"
            ))),
        }
    }

    /// The endpoint these arguments describe.
    ///
    /// # Errors
    /// See [`Self::token`].
    pub fn endpoint(&self) -> Result<Endpoint> {
        Ok(Endpoint {
            addr: self.rpc.clone(),
            token: self.token()?,
        })
    }

    /// Connects and authenticates.
    ///
    /// # Errors
    /// Fails without a token, if the socket is unreachable, or with
    /// [`Error::Unauthorized`].
    pub async fn connect(&self) -> Result<Client> {
        self.endpoint()?.connect().await
    }
}

/// Commands.
#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)] // Parsed once at startup; keep run options together for clap.
pub enum Command {
    /// Run a node.
    Run {
        /// Network: `test` or `main`.
        #[arg(long, default_value = "main")]
        network: Network,
        /// Data directory holding `chain.redb` and `rpc.token`; defaults to
        /// `<user data>/<network>/chain`, the same chain the desktop app uses.
        #[arg(long)]
        datadir: Option<PathBuf>,
        /// Address to accept peers on.
        #[arg(long)]
        listen: Option<SocketAddr>,
        /// Public IP:port to announce, for example a forwarded port behind NAT.
        #[arg(long, requires = "listen", conflicts_with = "proxy")]
        advertise: Option<SocketAddr>,
        /// Peers to connect to as `host:port`; repeatable.
        #[arg(long)]
        connect: Vec<String>,
        /// Extra seed peers as `host:port`; repeatable.
        #[arg(long)]
        seed: Vec<String>,
        /// SOCKS5 proxy for outbound connections, for example Tor's
        /// `127.0.0.1:9050`.
        #[arg(long)]
        proxy: Option<SocketAddr>,
        /// Mine to this address.
        #[arg(long)]
        mine: Option<String>,
        /// Miner worker threads; defaults to one. Ignored without --mine.
        #[arg(long, default_value_t = 1)]
        mining_threads: usize,
        /// Control socket address.
        #[arg(long, default_value = DEFAULT_RPC)]
        rpc: SocketAddr,
        /// Serve JSON-RPC 2.0 over HTTP on this address, behind the same
        /// token as the control socket (`Authorization: Bearer`).
        #[arg(long, default_value = DEFAULT_RPC_HTTP)]
        rpc_http: SocketAddr,
        /// Token the control socket demands; also read from
        /// `RPC_TOKEN`. Generated on first start and saved to `rpc.token`
        /// in the data directory when omitted; later starts reuse it.
        #[arg(long, env = TOKEN_ENV, hide_env_values = true)]
        rpc_token: Option<String>,
        /// Serve Prometheus metrics at `GET /metrics` on this address.
        #[arg(long)]
        metrics: Option<SocketAddr>,
        /// Shell command to run on every new main-chain tip, with `%s`
        /// replaced by the block hash.
        #[arg(long)]
        blocknotify: Option<String>,
        /// Log level: debug, info, warn or error.
        #[arg(long, default_value = "info")]
        log_level: crate::logging::Level,
        /// Also append log lines to this file, dated and without colors.
        #[arg(long)]
        log_file: Option<PathBuf>,
    },
    /// Generate a seed phrase with its account 0 spending key and default
    /// address, without a file.
    Keygen {
        /// Network to write the address for.
        #[arg(long, default_value = "main")]
        network: Network,
    },
    /// Print a node's status line.
    Status {
        /// The node.
        #[command(flatten)]
        rpc: RpcArgs,
    },
    /// Create a wallet database from a new seed phrase, a phrase
    /// to restore, or a spending key.
    Create {
        /// Wallet file to create.
        #[arg(long)]
        wallet: PathBuf,
        /// Spending key to import, hex.
        #[arg(long, conflicts_with = "phrase")]
        sk: Option<String>,
        /// Restore from a seed phrase, taken from `SEED_PHRASE` or
        /// prompted. A fresh phrase is generated and printed if not given.
        #[arg(long)]
        phrase: bool,
        /// Account of the seed phrase to use.
        #[arg(long, default_value_t = 0, conflicts_with = "sk")]
        account: u32,
        /// Network the wallet is for.
        #[arg(long, default_value = "main")]
        network: Network,
    },
    /// Export a complete plaintext JSON backup of a wallet.
    #[command(name = "backupwallet")]
    BackupWallet {
        /// The wallet to back up.
        #[command(flatten)]
        wallet: WalletArgs,
        /// Where to create the JSON backup, usually `wallet.json`.
        #[arg(long)]
        out: PathBuf,
        /// Network, for a wallet file.
        #[arg(long, default_value = "main")]
        network: Network,
    },
    /// Show the default address of a wallet.
    Address {
        /// The wallet.
        #[command(flatten)]
        wallet: WalletArgs,
        /// Network, for a wallet file.
        #[arg(long, default_value = "main")]
        network: Network,
    },
    /// Scan the chain through a node and show the balance.
    Balance {
        /// The wallet.
        #[command(flatten)]
        wallet: WalletArgs,
        /// The node.
        #[command(flatten)]
        rpc: RpcArgs,
        /// Scan compact blocks instead of full ones. Memos are not
        /// recovered, but the balance and witnesses are the same.
        #[arg(long)]
        light: bool,
    },
    /// Pay an address through a node.
    Send {
        /// The wallet.
        #[command(flatten)]
        wallet: WalletArgs,
        /// Recipient address.
        #[arg(long)]
        to: String,
        /// RawCoin in smallest units.
        #[arg(long)]
        amount: u64,
        /// Private fee amount in raw units (default: 1 raw unit per encoded byte).
        #[arg(long)]
        fee: Option<u64>,
        /// The node.
        #[command(flatten)]
        rpc: RpcArgs,
        /// Scan compact blocks instead of full ones.
        #[arg(long)]
        light: bool,
    },
    /// Pay several addresses in one transaction and one proof.
    #[command(name = "batchtransfer")]
    BatchTransfer {
        /// The wallet.
        #[command(flatten)]
        wallet: WalletArgs,
        /// Recipient in ADDRESS=RAW_AMOUNT form; repeat for each recipient.
        #[arg(long = "payment", required = true, value_name = "ADDRESS=RAW_AMOUNT")]
        payments: Vec<String>,
        /// Private fee amount in raw units (default: 1 raw unit per encoded byte).
        #[arg(long)]
        fee: Option<u64>,
        /// The node.
        #[command(flatten)]
        rpc: RpcArgs,
        /// Scan compact blocks instead of full ones.
        #[arg(long)]
        light: bool,
    },
}

/// Runs the parsed command.
///
/// # Errors
/// Returns the first failure.
pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Run {
            network,
            datadir,
            listen,
            advertise,
            connect,
            seed,
            proxy,
            mine,
            mining_threads,
            rpc,
            rpc_http,
            rpc_token,
            metrics,
            blocknotify,
            log_level,
            log_file,
        } => {
            crate::logging::init(log_level, log_file.as_deref())?;
            let token = rpc_token.as_deref().map(Token::new).transpose()?;
            run_node(RunOptions {
                network,
                datadir: node_datadir(datadir, network)?,
                listen,
                advertise,
                connect,
                seed,
                proxy,
                mine,
                mining_threads,
                rpc,
                rpc_http,
                rpc_token: token,
                metrics,
                blocknotify,
            })
            .await
        }
        Command::Status { rpc } => {
            let mut client = rpc.connect().await?;
            println!("{}", client.call("status").await?);
            Ok(())
        }
        Command::Keygen { network } => keygen(network),
        Command::Create {
            wallet,
            sk,
            phrase,
            account,
            network,
        } => create_wallet(&wallet, sk.as_deref(), phrase, account, network),
        Command::BackupWallet {
            wallet,
            out,
            network,
        } => backup_wallet(&wallet, &out, network),
        Command::Address { wallet, network } => show_address(&wallet, network),
        Command::Balance { wallet, rpc, light } => balance(&wallet, &rpc, light).await,
        Command::Send {
            wallet,
            to,
            amount,
            fee,
            rpc,
            light,
        } => send(&wallet, &to, amount, fee, &rpc, light).await,
        Command::BatchTransfer {
            wallet,
            payments,
            fee,
            rpc,
            light,
        } => batch_transfer(&wallet, &payments, fee, &rpc, light).await,
    }
}

async fn batch_transfer(
    wallet_args: &WalletArgs,
    payment_args: &[String],
    fee: Option<u64>,
    rpc: &RpcArgs,
    light: bool,
) -> Result<()> {
    if payment_args.is_empty() || payment_args.len() > MAX_RECIPIENTS {
        return Err(Error::Argument(format!(
            "batchtransfer accepts 1 to {MAX_RECIPIENTS} payments"
        )));
    }
    let mut client = rpc.connect().await?;
    let genesis = fetch_genesis(&mut client).await?;
    let network = network_of(&genesis)?;
    let mut payments = Vec::with_capacity(payment_args.len());
    for specification in payment_args {
        let (address, amount) = specification
            .split_once('=')
            .ok_or_else(|| Error::Argument("payment must use ADDRESS=RAW_AMOUNT".into()))?;
        if address.is_empty() || amount.is_empty() {
            return Err(Error::Argument(
                "payment must use ADDRESS=RAW_AMOUNT".into(),
            ));
        }
        let recipient = RhombusAddress::decode(address, network.address_prefix())?;
        let amount = amount
            .parse::<u64>()
            .map_err(|_| Error::Argument("payment amount must be an unsigned integer".into()))?;
        payments.push(Payment {
            recipient,
            amount: RawCoin::from_raw(amount)?,
            memo: Memo::empty(),
        });
    }
    let wallet = open_wallet(wallet_args, genesis)?;
    let params = network.params();
    let scanned = sync_wallet(&mut client, &wallet, light).await?;
    let branch = params.branch_at(next_height(scanned)?);
    let pk = tokio::task::spawn_blocking(ProvingKey::build)
        .await
        .map_err(|_| Error::Stopped)??;
    let built = match fee {
        Some(raw) => build_payments_with_fee(
            &wallet,
            &payments,
            RawCoin::from_raw(raw)?,
            &pk,
            branch,
            &[],
            u32::MAX,
            &mut rand::rngs::OsRng,
        )?,
        None => build_payments(
            &wallet,
            &payments,
            &pk,
            branch,
            &[],
            u32::MAX,
            &mut rand::rngs::OsRng,
        )?,
    };
    let actual_fee = built.transaction.fee().raw();
    let txid = client
        .call(&format!(
            "submit {} {}",
            to_hex(&built.transaction.to_vec()),
            to_hex(&built.fee_opening.to_vec())
        ))
        .await?;
    println!(
        "submitted {txid} ({} recipients, fee {actual_fee} raw units)",
        payments.len()
    );
    Ok(())
}

async fn balance(wallet: &WalletArgs, rpc: &RpcArgs, light: bool) -> Result<()> {
    let mut client = rpc.connect().await?;
    let genesis = fetch_genesis(&mut client).await?;
    let _network = network_of(&genesis)?;
    let wallet = open_wallet(wallet, genesis)?;
    let scanned = sync_wallet(&mut client, &wallet, light).await?;
    for coin in wallet.unspent()? {
        println!(
            "coin at height {} position {}: {}",
            coin.height,
            coin.position,
            coin.coin.value().raw()
        );
    }
    println!("scanned to height {scanned}, balance {}", wallet.balance()?);
    Ok(())
}

/// Syncs the wallet through the node, then builds and submits a payment.
async fn send(
    wallet: &WalletArgs,
    to: &str,
    amount: u64,
    fee: Option<u64>,
    rpc: &RpcArgs,
    light: bool,
) -> Result<()> {
    let amount = RawCoin::from_raw(amount)?;
    let mut client = rpc.connect().await?;
    let genesis = fetch_genesis(&mut client).await?;
    let network = network_of(&genesis)?;
    let recipient = RhombusAddress::decode(to, network.address_prefix())?;
    let wallet = open_wallet(wallet, genesis)?;
    let params = network.params();
    let scanned = sync_wallet(&mut client, &wallet, light).await?;
    let branch = params.branch_at(next_height(scanned)?);
    let pk = tokio::task::spawn_blocking(ProvingKey::build)
        .await
        .map_err(|_| Error::Stopped)??;
    let payment = Payment {
        recipient,
        amount,
        memo: Memo::empty(),
    };
    let built = match fee {
        Some(raw) => build_payments_with_fee(
            &wallet,
            &[payment],
            RawCoin::from_raw(raw)?,
            &pk,
            branch,
            &[],
            u32::MAX,
            &mut rand::rngs::OsRng,
        )?,
        None => build_payments(
            &wallet,
            &[payment],
            &pk,
            branch,
            &[],
            u32::MAX,
            &mut rand::rngs::OsRng,
        )?,
    };
    let actual_fee = built.fee_opening.fee().raw();
    let txid = client
        .call(&format!(
            "submit {} {}",
            to_hex(&built.transaction.to_vec()),
            to_hex(&built.fee_opening.to_vec())
        ))
        .await?;
    println!("submitted {txid} (fee {actual_fee} raw units)");
    Ok(())
}

/// The chain directory for `RawCoin run`: the given one, the per-user
/// default. Directories are created owner-only.
fn node_datadir(datadir: Option<PathBuf>, network: Network) -> Result<PathBuf> {
    let dir = match datadir {
        Some(dir) => dir,
        None => paths::chain_dir(&paths::default_network_dir(network)?),
    };
    paths::private_directory(&dir)?;
    Ok(dir)
}

/// Starts a node and runs it until interrupted.
#[allow(clippy::too_many_arguments)] // mirrors the command line options
/// The options `RawCoin run` was given.
struct RunOptions {
    network: Network,
    datadir: PathBuf,
    listen: Option<SocketAddr>,
    advertise: Option<SocketAddr>,
    connect: Vec<String>,
    seed: Vec<String>,
    proxy: Option<SocketAddr>,
    mine: Option<String>,
    mining_threads: usize,
    rpc: SocketAddr,
    rpc_http: SocketAddr,
    rpc_token: Option<Token>,
    metrics: Option<SocketAddr>,
    blocknotify: Option<String>,
}

async fn run_node(opts: RunOptions) -> Result<()> {
    let RunOptions {
        network,
        datadir,
        listen,
        advertise,
        connect,
        seed,
        proxy,
        mine,
        mining_threads,
        rpc,
        rpc_http,
        rpc_token,
        metrics,
        blocknotify,
    } = opts;
    let mine_to = mine
        .map(|a| RhombusAddress::decode(&a, network.address_prefix()))
        .transpose()?;
    let token_file = datadir.join(TOKEN_FILE);
    let token_given = rpc_token.is_some();
    let mut targets = connect;
    targets.extend(seed);
    targets.extend(network.seeds().iter().map(ToString::to_string));
    let config = Config {
        network,
        datadir,
        cleanup_datadir: false,
        listen,
        advertise,
        connect: targets,
        proxy,
        mine_to,
        mining_threads,
        rpc: Some(rpc),
        rpc_http: Some(rpc_http),
        rpc_token,
        block_notify: blocknotify,
        metrics,
        max_inbound: crate::config::DEFAULT_MAX_INBOUND,
    };
    let shutdown = Shutdown::listen()?;
    let handle = crate::node::spawn(config).await?;
    let log = crate::node::log;
    log(&format!("RawCoin up on the {network} network"));
    match handle.listen_addr {
        Some(addr) => log(&format!("peers      listening on {addr}")),
        None => log("peers      outbound only"),
    }
    match handle.rpc_addr {
        Some(addr) => log(&format!("control    {addr}")),
        None => log("control    disabled"),
    }
    match handle.rpc_http_addr {
        Some(addr) => log(&format!("json-rpc   http://{addr}/")),
        None => log("json-rpc   disabled"),
    }
    match handle.metrics_addr {
        Some(addr) => log(&format!("metrics    {addr}")),
        None => log("metrics    disabled"),
    }
    // Say where the token is, or that it was supplied by the operator.
    if token_given {
        log("token      as supplied");
    } else {
        log(&format!("token      {}", token_file.display()));
    }
    shutdown.requested().await;
    handle.shutdown().await;
    Ok(())
}

/// Builds and submits a payment, returning the transaction id.
///
/// # Errors
/// Fails on insufficient funds, a building error, or a refused submit.
pub async fn pay(
    client: &mut Client,
    wallet: &Wallet,
    pk: &ProvingKey,
    recipient: RhombusAddress,
    amount: RawCoin,
    fee: u64,
    branch: BranchId,
) -> Result<String> {
    let payment = Payment {
        recipient,
        amount,
        memo: Memo::empty(),
    };
    let built = build_payments_with_fee(
        wallet,
        &[payment],
        RawCoin::from_raw(fee)?,
        pk,
        branch,
        &[],
        u32::MAX,
        &mut rand::rngs::OsRng,
    )?;
    client
        .call(&format!(
            "submit {} {}",
            to_hex(&built.transaction.to_vec()),
            to_hex(&built.fee_opening.to_vec())
        ))
        .await
}

fn sk_from_hex(sk: &str) -> Result<SpendingKey> {
    let bytes: [u8; 32] = from_hex(sk)?
        .try_into()
        .map_err(|_| Error::Argument("spending key must be 32 bytes".into()))?;
    Ok(SpendingKey::from_bytes(bytes))
}

/// Creates a wallet file from an imported key, a restored phrase, or a
/// fresh phrase, which is printed once.
fn create_wallet(
    path: &Path,
    sk: Option<&str>,
    restore: bool,
    account: u32,
    network: Network,
) -> Result<()> {
    let (sk, fresh) = match (sk, restore) {
        (Some(hex), _) => (sk_from_hex(hex)?, None),
        (None, true) => (seed_phrase()?.spending_key(account)?, None),
        (None, false) => {
            let phrase = SeedPhrase::generate(&mut rand::rngs::OsRng)?;
            (phrase.spending_key(account)?, Some(phrase))
        }
    };
    let genesis = genesis(&network.params()).hash();
    let created = Wallet::create(path, &sk, genesis, &mut rand::rngs::OsRng)?;
    if let Some(phrase) = fresh {
        println!("seed_phrase: {}", *phrase.words());
        println!("write the seed phrase down; it restores this wallet on any machine");
    }
    println!(
        "address: {}",
        created
            .keys()
            .default_address()?
            .encode(network.address_prefix())
    );
    Ok(())
}

/// Writes a complete wallet backup as owner-readable JSON.
fn backup_wallet(wallet: &WalletArgs, out: &Path, network: Network) -> Result<()> {
    let genesis = genesis(&network.params()).hash();
    let wallet = open_wallet(wallet, genesis)?;
    let bytes = wallet.backup_json()?;
    let mut file = paths::create_private(out)?;
    use std::io::Write as _;
    file.write_all(&bytes)?;
    file.sync_all()?;
    println!("wrote JSON wallet backup to {}", out.display());
    Ok(())
}

/// Prints a fresh seed phrase with its account 0 key and address.
fn keygen(network: Network) -> Result<()> {
    let phrase = SeedPhrase::generate(&mut rand::rngs::OsRng)?;
    let keys = WalletKeys::from_spending_key(phrase.spending_key(0)?)?;
    println!("seed_phrase: {}", *phrase.words());
    println!("spending_key: {}", to_hex(&keys.spending_key().to_bytes()));
    println!(
        "address: {}",
        keys.default_address()?.encode(network.address_prefix())
    );
    Ok(())
}

/// Prints a wallet's default address for `network`.
fn show_address(wallet: &WalletArgs, network: Network) -> Result<()> {
    let genesis = genesis(&network.params()).hash();
    let wallet = open_wallet(wallet, genesis)?;
    println!(
        "{}",
        wallet
            .keys()
            .default_address()?
            .encode(network.address_prefix())
    );
    Ok(())
}

/// The network a node is on, from its genesis hash.
fn network_of(genesis: &BlockHash) -> Result<Network> {
    Network::for_genesis(genesis)
        .ok_or_else(|| Error::Argument("node is on an unknown network".into()))
}

/// The seed phrase from the environment, or prompted on standard input.
fn seed_phrase() -> Result<SeedPhrase> {
    let text = match std::env::var(PHRASE_ENV) {
        Ok(value) => value,
        Err(_) => {
            use std::io::Write as _;
            print!("Seed phrase: ");
            std::io::stdout().flush()?;
            let mut text = String::new();
            std::io::stdin().read_line(&mut text)?;
            text.trim().to_owned()
        }
    };
    Ok(SeedPhrase::parse(&text)?)
}

/// Opens a plaintext wallet file.
fn open_wallet(args: &WalletArgs, genesis: BlockHash) -> Result<Wallet> {
    open_wallet_file(&args.wallet, genesis)
}

fn open_wallet_file(path: &Path, genesis: BlockHash) -> Result<Wallet> {
    Ok(Wallet::open(path, genesis)?)
}

/// Brings the wallet up to the node's tip, rolling back first if the
/// node's chain diverged from what the wallet scanned. Returns the tip.
///
/// # Errors
/// Fails on a control socket or wallet error.
pub async fn sync_wallet(client: &mut impl Control, wallet: &Wallet, light: bool) -> Result<u32> {
    let tip = status_height(client).await?;
    let mut height = wallet.next_height()?;
    let oldest_checkpoint = wallet.oldest_checkpoint()?;
    let mut rollback_height = None;
    while height > 0 {
        let scanned = height.saturating_sub(1);
        let Some(hash) = wallet.scanned_hash(scanned)? else {
            break;
        };
        let matches = scanned <= tip && fetch_hash(client, scanned).await? == Some(hash);
        if matches {
            break;
        }
        if oldest_checkpoint.is_some_and(|oldest| scanned < oldest) {
            rollback_height = Some(oldest_checkpoint.unwrap_or(0).saturating_sub(1));
            break;
        }
        height = scanned;
    }
    if let Some(height) = rollback_height {
        wallet.rollback_to(height)?;
    } else if height < wallet.next_height()? {
        wallet.rollback_to(height.saturating_sub(1))?;
    }
    for h in wallet.next_height()?..=tip {
        if light {
            wallet.scan_compact(&fetch_compact(client, h).await?)?;
        } else {
            let block = fetch_block(client, h).await?;
            wallet.scan(&block)?;
        }
    }
    Ok(tip)
}

/// The genesis hash, over the cheap `hash` request.
async fn fetch_genesis(client: &mut impl Control) -> Result<BlockHash> {
    fetch_hash(client, 0)
        .await?
        .ok_or_else(|| Error::Argument("node has no genesis".into()))
}

/// The hash of the block at `height`, or `None` past the tip. One 32-byte
/// reply, so the reorg check does not re-download whole blocks.
async fn fetch_hash(client: &mut impl Control, height: u32) -> Result<Option<BlockHash>> {
    match client.call(&format!("hash {height}")).await {
        Ok(hex) => Ok(Some(BlockHash::from_bytes(
            from_hex(&hex)?
                .try_into()
                .map_err(|_| Error::Argument("hash length".into()))?,
        ))),
        Err(Error::Argument(reason)) if reason == "not found" => Ok(None),
        Err(error) => Err(error),
    }
}

async fn fetch_compact(client: &mut impl Control, height: u32) -> Result<CompactBlock> {
    let hex = client.call(&format!("compact {height}")).await?;
    Ok(CompactBlock::from_slice(&from_hex(&hex)?)?)
}

async fn status_height(client: &mut impl Control) -> Result<u32> {
    let status = client.call("status").await?;
    status
        .split_whitespace()
        .find_map(|w| w.strip_prefix("height="))
        .and_then(|h| h.parse().ok())
        .ok_or_else(|| Error::Argument("bad status".into()))
}

/// The full block at `height`.
///
/// # Errors
/// Fails if the node has no such block or the reply is malformed.
pub async fn fetch_block(client: &mut impl Control, height: u32) -> Result<Block> {
    let hex = client.call(&format!("block {height}")).await?;
    Ok(Block::from_slice(&from_hex(&hex)?)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nodes_use_the_default_or_given_datadir() {
        let dir = tempfile::tempdir().unwrap();
        let chain = dir.path().join("nested").join("chain");
        let resolved = node_datadir(Some(chain.clone()), Network::Test).unwrap();
        assert_eq!(resolved, chain.clone());
        assert!(chain.is_dir());
    }

    #[test]
    fn advertising_requires_a_listener_and_conflicts_with_a_proxy() {
        let base = ["RawCoin", "run", "--advertise", "8.8.8.8:19000"];
        assert!(Cli::try_parse_from(base).is_err());
        let listener = ["--listen", "0.0.0.0:19000"];
        assert!(Cli::try_parse_from(base.into_iter().chain(listener)).is_ok());
        for transport in ["--proxy"] {
            assert!(Cli::try_parse_from(
                base.into_iter()
                    .chain(listener)
                    .chain([transport, "127.0.0.1:9050"])
            )
            .is_err());
        }
    }

    /// The network a parsed command is for, if it takes one.
    fn network_of_command(command: &Command) -> Option<Network> {
        match command {
            Command::Run { network, .. }
            | Command::Keygen { network }
            | Command::Create { network, .. }
            | Command::Address { network, .. } => Some(*network),
            _ => None,
        }
    }

    #[test]
    fn every_command_defaults_to_the_main_network() {
        for argv in [
            &["RawCoin", "run"][..],
            &["RawCoin", "keygen"],
            &["RawCoin", "create", "--wallet", "w"],
            &["RawCoin", "address", "--wallet", "w"],
        ] {
            let cli = Cli::try_parse_from(argv).unwrap();
            assert_eq!(
                network_of_command(&cli.command),
                Some(Network::Main),
                "{argv:?}"
            );
        }
        let explicit = Cli::try_parse_from(["RawCoin", "keygen", "--network", "test"]).unwrap();
        assert_eq!(network_of_command(&explicit.command), Some(Network::Test));
    }
}
