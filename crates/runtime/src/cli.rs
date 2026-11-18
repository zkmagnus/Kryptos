//! The `Rhombus` command line.

use std::io::{Read, Seek, SeekFrom, Write};
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
use transaction_proof::ProvingKey;
use wallet::keys::WalletKeys;
use wallet::seed::SeedPhrase;
use wallet::spend::{build_payment, Payment};
use wallet::wallet::Wallet;

use crate::config::{Config, Network};
use crate::paths;
use crate::rpc::{Client, Control, Endpoint, Token, TOKEN_FILE};
use crate::shutdown::Shutdown;
use crate::tor::TorConfig;
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
#[command(name = "Rhombus", version)]
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
    /// Node onion control service, as `<v3 hostname>.onion:port`.
    #[arg(long)]
    pub rpc: String,
    /// Directory for this client's persistent embedded Tor state.
    #[arg(long)]
    pub datadir: Option<PathBuf>,
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
    pub async fn endpoint(&self) -> Result<Endpoint> {
        p2p::address::NetAddr::parse_endpoint(&self.rpc)?;
        let token = self.token()?;
        let directory = self.datadir.clone().map_or_else(
            || paths::user_data_dir().map(|path| path.join("rpc-client")),
            Ok,
        )?;
        let (network, _incoming) = p2p::transport::TorNetwork::start(&directory, false, &[])?;
        network.wait_ready().await?;
        let endpoint = Endpoint {
            addr: self.rpc.clone(),
            token,
            network,
        };
        endpoint.validate()?;
        Ok(endpoint)
    }

    /// Connects and authenticates.
    ///
    /// # Errors
    /// Fails without a token, if the socket is unreachable, or with
    /// [`Error::Unauthorized`].
    pub async fn connect(&self) -> Result<Client> {
        self.endpoint().await?.connect().await
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
        /// Disable inbound P2P service streams.
        #[arg(long)]
        no_p2p: bool,
        /// Tor v3 peers to connect to as `<hostname>.onion:port`; repeatable.
        #[arg(long)]
        connect: Vec<String>,
        /// Extra Tor v3 seed peers as `<hostname>.onion:port`; repeatable.
        #[arg(long)]
        seed: Vec<String>,
        /// Additional onion peers to maintain; repeatable.
        #[arg(long)]
        addnode: Vec<String>,
        /// Disable built-in seed peers.
        #[arg(long)]
        no_seeds: bool,
        /// Maximum maintained authenticated peers.
        #[arg(long, default_value_t = crate::config::OUTBOUND_TARGET)]
        max_outbound: usize,
        /// Public port of the Tor hidden service.
        #[arg(long, default_value_t = crate::config::DEFAULT_P2P_PORT)]
        p2p_port: u16,
        /// Seconds allowed to establish an onion connection.
        #[arg(long, default_value_t = 60)]
        connect_timeout: u64,
        /// Seconds allowed for the application version exchange.
        #[arg(long, default_value_t = 60)]
        handshake_timeout: u64,
        /// Seconds without incoming peer traffic before disconnecting.
        #[arg(long, default_value_t = 900)]
        idle_timeout: u64,
        /// Seconds allowed to read or write one peer message.
        #[arg(long, default_value_t = 120)]
        message_timeout: u64,
        /// Seconds allowed for a headers or body response after its request is flushed.
        #[arg(long, default_value_t = 300)]
        sync_response_timeout: u64,
        /// Seconds allowed per Tor directory bootstrap attempt.
        #[arg(long, default_value_t = 180)]
        tor_bootstrap_timeout: u64,
        /// Seconds allowed for anonymous onion-service publication.
        #[arg(long, default_value_t = 1200)]
        tor_service_startup_timeout: u64,
        /// Seconds Arti may spend building a requested circuit.
        #[arg(long, default_value_t = 60)]
        tor_circuit_request_timeout: u64,
        /// Maximum Arti circuit construction attempts per request.
        #[arg(long, default_value_t = 8)]
        tor_circuit_request_attempts: u32,
        /// Maximum onion introduction/rendezvous attempts per connection.
        #[arg(long, default_value_t = 3)]
        tor_intro_rendezvous_attempts: u32,
        /// Seconds a used circuit remains eligible for new streams.
        #[arg(long, default_value_t = 600)]
        tor_max_circuit_dirtiness: u64,
        /// Seconds to retain disused circuits with strong stream isolation.
        #[arg(long, default_value_t = 3600)]
        tor_disused_circuit_timeout: u64,
        /// Initial seconds between failed peer or Tor bootstrap attempts.
        #[arg(long, default_value_t = 60)]
        retry_initial: u64,
        /// Maximum retry seconds including jitter.
        #[arg(long, default_value_t = 3600)]
        retry_max: u64,
        /// Maximum inbound peers; Tor identities do not identify inbound dialers.
        #[arg(long, default_value_t = crate::config::DEFAULT_MAX_INBOUND)]
        max_inbound: usize,
        /// Mine to this address.
        #[arg(long)]
        mine: Option<String>,
        /// Miner worker threads; defaults to one. Ignored without --mine.
        #[arg(long, default_value_t = 1)]
        mining_threads: usize,
        /// Allow mining without peers when creating the first node of a chain.
        #[arg(long)]
        bootstrap_mining: bool,
        /// Distinct authenticated maintained peers required before online mining.
        #[arg(long, default_value_t = 1)]
        mining_min_peers: usize,
        /// Seconds readiness must remain stable before mining starts or resumes.
        #[arg(long, default_value_t = 5)]
        mining_ready_secs: u64,
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
        #[arg(long, conflicts_with = "phrase", requires = "restore_through")]
        sk: Option<String>,
        /// Restore from a seed phrase, taken from `SEED_PHRASE` or
        /// prompted. A fresh phrase is generated and printed if not given.
        #[arg(long, requires = "restore_through")]
        phrase: bool,
        /// Highest new-scheme address index to recover, inclusive (0..4095).
        /// Use zero for legacy-only recovery; all legacy addresses are scanned.
        /// Required when restoring a phrase/key; scan costs grow with this range.
        #[arg(long, value_parser = clap::value_parser!(u64).range(0..4096))]
        restore_through: Option<u64>,
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
    /// Restore a plaintext JSON backup to a new wallet database.
    #[command(name = "restorewallet")]
    RestoreWallet {
        /// Version 1 JSON backup created by backupwallet.
        #[arg(long)]
        backup: PathBuf,
        /// New destination wallet file; an existing path is never overwritten.
        #[arg(long)]
        wallet: PathBuf,
        /// Network recorded in the backup.
        #[arg(long, default_value = "main")]
        network: Network,
    },
    /// Show the current unused receiving address of a wallet.
    Address {
        /// The wallet.
        #[command(flatten)]
        wallet: WalletArgs,
        /// Network, for a wallet file.
        #[arg(long, default_value = "main")]
        network: Network,
    },
    /// Enable or disable automatic rotation after a payment to the current receive address.
    #[command(name = "set-receive-rotation")]
    SetReceiveRotation {
        /// The wallet.
        #[command(flatten)]
        wallet: WalletArgs,
        /// Enable automatic rotation (`true` or `false`).
        #[arg(long, action = clap::ArgAction::Set, value_parser = clap::value_parser!(bool))]
        enabled: bool,
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
        /// Rhombus in smallest units.
        #[arg(long)]
        amount: u64,
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
            no_p2p,
            connect,
            seed,
            addnode,
            no_seeds,
            max_outbound,
            p2p_port,
            connect_timeout,
            handshake_timeout,
            idle_timeout,
            message_timeout,
            sync_response_timeout,
            tor_bootstrap_timeout,
            tor_service_startup_timeout,
            tor_circuit_request_timeout,
            tor_circuit_request_attempts,
            tor_intro_rendezvous_attempts,
            tor_max_circuit_dirtiness,
            tor_disused_circuit_timeout,
            retry_initial,
            retry_max,
            max_inbound,
            mine,
            mining_threads,
            bootstrap_mining,
            mining_min_peers,
            mining_ready_secs,
            rpc,
            rpc_http,
            rpc_token,
            blocknotify,
            log_level,
            log_file,
        } => {
            crate::logging::init(log_level, log_file.as_deref())?;
            let token = rpc_token.as_deref().map(Token::new).transpose()?;
            run_node(RunOptions {
                network,
                datadir: node_datadir(datadir, network)?,
                p2p: !no_p2p,
                connect,
                seed,
                addnode,
                no_seeds,
                max_outbound,
                tor: TorConfig {
                    p2p_port,
                    settings: p2p::transport::TorSettings {
                        connect_timeout: std::time::Duration::from_secs(connect_timeout),
                        handshake_timeout: std::time::Duration::from_secs(handshake_timeout),
                        idle_timeout: std::time::Duration::from_secs(idle_timeout),
                        message_timeout: std::time::Duration::from_secs(message_timeout),
                        sync_response_timeout: std::time::Duration::from_secs(
                            sync_response_timeout,
                        ),
                        bootstrap_timeout: std::time::Duration::from_secs(tor_bootstrap_timeout),
                        service_startup_timeout: std::time::Duration::from_secs(
                            tor_service_startup_timeout,
                        ),
                        circuit_request_timeout: std::time::Duration::from_secs(
                            tor_circuit_request_timeout,
                        ),
                        circuit_request_attempts: tor_circuit_request_attempts,
                        intro_rendezvous_attempts: tor_intro_rendezvous_attempts,
                        max_circuit_dirtiness: std::time::Duration::from_secs(
                            tor_max_circuit_dirtiness,
                        ),
                        disused_circuit_timeout: std::time::Duration::from_secs(
                            tor_disused_circuit_timeout,
                        ),
                        retry_initial: std::time::Duration::from_secs(retry_initial),
                        retry_max: std::time::Duration::from_secs(retry_max),
                    },
                },
                max_inbound,
                mine,
                mining_threads,
                bootstrap_mining,
                mining_min_peers,
                mining_ready_secs,
                rpc,
                rpc_http,
                rpc_token: token,
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
            restore_through,
            account,
            network,
        } => create_wallet(
            &wallet,
            sk.as_deref(),
            phrase,
            account,
            network,
            restore_through,
        ),
        Command::BackupWallet {
            wallet,
            out,
            network,
        } => backup_wallet(&wallet, &out, network),
        Command::RestoreWallet {
            backup,
            wallet,
            network,
        } => restore_wallet(&backup, &wallet, network),
        Command::Address { wallet, network } => show_address(&wallet, network),
        Command::SetReceiveRotation {
            wallet,
            enabled,
            network,
        } => set_receive_rotation(&wallet, enabled, network),
        Command::Balance { wallet, rpc, light } => balance(&wallet, &rpc, light).await,
        Command::Send {
            wallet,
            to,
            amount,
            rpc,
            light,
        } => send(&wallet, &to, amount, &rpc, light).await,
    }
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
    rpc: &RpcArgs,
    light: bool,
) -> Result<()> {
    let amount = RawCoin::from_raw(amount)?;
    let endpoint = rpc.endpoint().await?;
    let mut client = endpoint.connect().await?;
    let genesis = fetch_genesis(&mut client).await?;
    let network = network_of(&genesis)?;
    let recipient = RhombusAddress::decode(to, network.address_prefix())?;
    let wallet = open_wallet(wallet, genesis)?;
    let params = network.params();
    let scanned = sync_wallet(&mut client, &wallet, light).await?;
    drop(client);
    let branch = params.branch_at(next_height(scanned)?);
    let pk = tokio::task::spawn_blocking(ProvingKey::build)
        .await
        .map_err(|_| Error::Stopped)??;
    let payment = Payment { recipient, amount };
    let transaction = build_payment(&wallet, payment, &pk, branch, &mut rand::rngs::OsRng)?;
    let actual_fee = transaction.fee().raw();
    // Download closes its session before private scanning; proof generation
    // can also exceed the server's idle deadline. Submit on a fresh connection.
    let mut client = endpoint.connect().await?;
    let txid = client
        .call(&format!("submit {}", to_hex(&transaction.to_vec())))
        .await?;
    println!("submitted {txid} (fee {actual_fee} raw units)");
    Ok(())
}

/// The chain directory for `Rhombus run`: the given one, the per-user
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
/// The options `Rhombus run` was given.
struct RunOptions {
    network: Network,
    datadir: PathBuf,
    p2p: bool,
    connect: Vec<String>,
    seed: Vec<String>,
    addnode: Vec<String>,
    no_seeds: bool,
    max_outbound: usize,
    tor: TorConfig,
    max_inbound: usize,
    mine: Option<String>,
    mining_threads: usize,
    bootstrap_mining: bool,
    mining_min_peers: usize,
    mining_ready_secs: u64,
    rpc: SocketAddr,
    rpc_http: SocketAddr,
    rpc_token: Option<Token>,
    blocknotify: Option<String>,
}

async fn run_node(opts: RunOptions) -> Result<()> {
    let RunOptions {
        network,
        datadir,
        p2p,
        connect,
        seed,
        addnode,
        no_seeds,
        max_outbound,
        tor,
        max_inbound,
        mine,
        mining_threads,
        bootstrap_mining,
        mining_min_peers,
        mining_ready_secs,
        rpc,
        rpc_http,
        rpc_token,
        blocknotify,
    } = opts;
    let mine_to = mine
        .map(|a| RhombusAddress::decode(&a, network.address_prefix()))
        .transpose()?;
    let token_file = datadir.join(TOKEN_FILE);
    let token_given = rpc_token.is_some();
    let mut targets = connect;
    targets.extend(seed);
    let config = Config {
        network,
        datadir,
        cleanup_datadir: false,
        offline: false,
        p2p,
        connect: targets,
        addnode,
        no_seeds,
        max_outbound,
        tor,
        mine_to,
        mining_threads,
        bootstrap_mining,
        mining_min_peers,
        mining_ready_secs,
        rpc: Some(rpc),
        rpc_http: Some(rpc_http),
        rpc_token,
        block_notify: blocknotify,
        max_inbound,
    };
    let shutdown = Shutdown::listen()?;
    let handle = crate::node::spawn(config).await?;
    let log = crate::node::log;
    log(&format!("Rhombus up on the {network} network"));
    if bootstrap_mining {
        crate::logging::warn("bootstrap mining enabled: may create a separate chain without peers");
    } else {
        log(&format!(
            "mining requires {mining_min_peers} distinct authenticated peers and completed sync"
        ));
    }
    log(if p2p {
        "peers      embedded onion service enabled"
    } else {
        "peers      outbound only"
    });
    match handle.rpc_addr {
        Some(addr) => log(&format!("control    {addr}")),
        None => log("control    disabled"),
    }
    match handle.rpc_http_addr {
        Some(addr) => log(&format!("json-rpc   http://{addr}/")),
        None => log("json-rpc   disabled"),
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
    branch: BranchId,
) -> Result<String> {
    let payment = Payment { recipient, amount };
    let transaction = build_payment(wallet, payment, pk, branch, &mut rand::rngs::OsRng)?;
    client
        .call(&format!("submit {}", to_hex(&transaction.to_vec())))
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
    restore_through: Option<u64>,
) -> Result<()> {
    if (restore || sk.is_some()) != restore_through.is_some() {
        return Err(Error::Argument(
            "restoring a phrase/key requires --restore-through; omit it for a new seed".into(),
        ));
    }
    let (sk, fresh) = match (sk, restore) {
        (Some(hex), _) => (sk_from_hex(hex)?, None),
        (None, true) => (seed_phrase()?.spending_key(account)?, None),
        (None, false) => {
            let phrase = SeedPhrase::generate(&mut rand::rngs::OsRng)?;
            (phrase.spending_key(account)?, Some(phrase))
        }
    };
    let genesis = genesis(&network.params()).hash();
    let created = match restore_through {
        Some(last) => Wallet::restore(path, &sk, genesis, last, &mut rand::rngs::OsRng)?,
        None => Wallet::create(path, &sk, genesis, &mut rand::rngs::OsRng)?,
    };
    if let Some(phrase) = fresh {
        println!("seed_phrase: {}", *phrase.words());
        println!("record the seed phrase and highest issued address index for recovery");
    }
    let receiving = created.current_receive_address()?;
    let range = created.address_scan_range()?;
    let last_index = range
        .end
        .checked_sub(1)
        .ok_or_else(|| Error::Argument("wallet address scan range is empty".into()))?;
    println!(
        "scan_address_indices: {}..={} (plus all legacy addresses)",
        range.start, last_index
    );
    println!("next_address_index: {}", range.end);
    match receiving {
        Some((index, address)) => {
            println!("address_index: {index}");
            println!("address: {}", address.encode(network.address_prefix()));
        }
        None => println!(
            "address_rotation_exhausted: true; use another account or wallet for new addresses"
        ),
    }
    Ok(())
}

/// Writes a complete wallet backup as owner-readable JSON.
fn backup_wallet(wallet: &WalletArgs, out: &Path, network: Network) -> Result<()> {
    let genesis = genesis(&network.params()).hash();
    let wallet = open_wallet(wallet, genesis)?;
    let bytes = wallet.backup_json()?;
    let parent = out
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut file = tempfile::Builder::new()
        .prefix(".rhombus-wallet-backup-")
        .tempfile_in(parent)?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(out).map_err(|error| error.error)?;
    println!("wrote plaintext JSON wallet backup to {}", out.display());
    Ok(())
}

/// Restores a complete backup without allocating or changing any address.
fn restore_wallet(backup: &Path, out: &Path, network: Network) -> Result<()> {
    let bytes = std::fs::read(backup)?;
    Wallet::restore_backup_json(out, &bytes, genesis(&network.params()).hash())?;
    println!("restored plaintext wallet backup to {}", out.display());
    println!("synchronize with the node before spending; retain the original backup");
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

/// Prints the wallet's current unused receiving address for `network`.
fn show_address(wallet: &WalletArgs, network: Network) -> Result<()> {
    let genesis = genesis(&network.params()).hash();
    let wallet = open_wallet(wallet, genesis)?;
    let (_, address) = wallet.current_receive_address()?.ok_or_else(|| {
        Error::Argument(
            "address rotation exhausted; use another account or wallet for new addresses".into(),
        )
    })?;
    println!("{}", address.encode(network.address_prefix()));
    Ok(())
}

/// Sets the persisted automatic receive-address rotation preference.
fn set_receive_rotation(wallet: &WalletArgs, enabled: bool, network: Network) -> Result<()> {
    let genesis = genesis(&network.params()).hash();
    let wallet = open_wallet(wallet, genesis)?;
    wallet.set_auto_rotate_receive(enabled)?;
    println!(
        "automatic receive-address rotation {}",
        if enabled { "enabled" } else { "disabled" }
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
    let text = if let Ok(value) = std::env::var(PHRASE_ENV) {
        value
    } else {
        print!("Seed phrase: ");
        std::io::stdout().flush()?;
        let mut text = String::new();
        std::io::stdin().read_line(&mut text)?;
        text.trim().to_owned()
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
/// Downloads the public snapshot to an anonymous temporary file before any
/// scanning, so requests for successive blocks do not expose trial-decryption
/// or wallet database timing. Memory use is bounded by one block; temporary
/// disk use is proportional to the missing snapshot and is released on return.
/// Closes the download session before scanning; callers performing later RPCs
/// must establish a fresh connection.
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
    let first = wallet.next_height()?;
    if first > tip {
        client.close().await?;
        return Ok(tip);
    }
    let mut downloaded = download_wallet_snapshot(client, first, tip, light).await?;
    // End-of-session timing must depend on downloading public bytes, not on
    // the subsequent private scan or database writes.
    client.close().await?;
    for h in wallet.next_height()?..=tip {
        let mut length = [0u8; 8];
        downloaded.read_exact(&mut length)?;
        let length = usize::try_from(u64::from_le_bytes(length))
            .map_err(|_| Error::Argument("downloaded block too large".into()))?;
        if length > MAX_WALLET_BLOCK_BYTES {
            return Err(Error::Argument("downloaded block too large".into()));
        }
        let mut bytes = vec![0; length];
        downloaded.read_exact(&mut bytes)?;
        if light {
            let block = CompactBlock::from_slice(&bytes)?;
            if block.height != h {
                return Err(Error::Argument("downloaded block height mismatch".into()));
            }
            wallet.scan_compact(&block)?;
        } else {
            let block = Block::from_slice(&bytes)?;
            if block.header().height != h {
                return Err(Error::Argument("downloaded block height mismatch".into()));
            }
            wallet.scan(&block)?;
        }
        tokio::task::yield_now().await;
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

// The control client's 128 MiB reply limit holds at most 64 MiB of hex data.
const MAX_WALLET_BLOCK_BYTES: usize = 64 * 1024 * 1024;

async fn download_wallet_snapshot(
    client: &mut impl Control,
    first: u32,
    tip: u32,
    light: bool,
) -> Result<std::fs::File> {
    let mut file = tempfile::tempfile()?;
    let command = if light { "compact" } else { "block" };
    for height in first..=tip {
        let hex = client.call(&format!("{command} {height}")).await?;
        if hex.len() > MAX_WALLET_BLOCK_BYTES.saturating_mul(2) {
            return Err(Error::Argument("downloaded block too large".into()));
        }
        let bytes = from_hex(&hex)?;
        let actual = if light {
            CompactBlock::from_slice(&bytes)?.height
        } else {
            Block::from_slice(&bytes)?.header().height
        };
        if actual != height {
            return Err(Error::Argument("downloaded block height mismatch".into()));
        }
        file.write_all(&(bytes.len() as u64).to_le_bytes())?;
        file.write_all(&bytes)?;
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
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
    fn restore_requires_an_explicit_bounded_address_range() {
        let base = ["rhombus", "create", "--wallet", "unused.redb", "--phrase"];
        assert!(Cli::try_parse_from(base).is_err());
        for bound in ["0", "4095"] {
            assert!(
                Cli::try_parse_from(base.into_iter().chain(["--restore-through", bound])).is_ok()
            );
        }
        for bound in ["4096", "18446744073709551615"] {
            assert!(
                Cli::try_parse_from(base.into_iter().chain(["--restore-through", bound])).is_err()
            );
        }
        assert!(Cli::try_parse_from([
            "rhombus",
            "create",
            "--wallet",
            "unused.redb",
            "--sk",
            "00"
        ])
        .is_err());
    }

    #[test]
    fn receive_rotation_command_requires_an_explicit_boolean() {
        for value in ["true", "false"] {
            assert!(Cli::try_parse_from([
                "rhombus",
                "set-receive-rotation",
                "--wallet",
                "wallet.redb",
                "--enabled",
                value,
            ])
            .is_ok());
        }
        assert!(Cli::try_parse_from([
            "rhombus",
            "set-receive-rotation",
            "--wallet",
            "wallet.redb",
        ])
        .is_err());
    }

    struct SnapshotSource<'a> {
        wallet: &'a Wallet,
        blocks: Vec<Block>,
        light: bool,
        expected_next: u32,
        requests: Vec<u32>,
        fail_at: Option<u32>,
    }

    impl Control for SnapshotSource<'_> {
        fn close(&mut self) -> impl std::future::Future<Output = Result<()>> {
            assert_eq!(
                self.wallet.next_height().unwrap(),
                self.expected_next,
                "end-of-session must precede private scanning"
            );
            std::future::ready(Ok(()))
        }

        fn call(&mut self, line: &str) -> impl std::future::Future<Output = Result<String>> {
            std::future::ready((|| {
                // Invariant: no note scanning or database update between requests.
                assert_eq!(self.wallet.next_height().unwrap(), self.expected_next);
                if line == "status" {
                    return Ok(format!("height={}", self.blocks.len().saturating_sub(1)));
                }
                let (command, height) = line.split_once(' ').unwrap();
                let height: u32 = height.parse().unwrap();
                let block = &self.blocks[height as usize];
                if command == "hash" {
                    return Ok(to_hex(block.hash().as_bytes()));
                }
                self.requests.push(height);
                if self.fail_at == Some(height) {
                    return Err(Error::Stopped);
                }
                assert_eq!(command, if self.light { "compact" } else { "block" });
                Ok(to_hex(&if self.light {
                    CompactBlock::from_block(block)?.to_vec()
                } else {
                    block.to_vec()
                }))
            })())
        }
    }

    struct ReorgSource<'a>(SnapshotSource<'a>);
    impl Control for ReorgSource<'_> {
        async fn close(&mut self) -> Result<()> {
            self.0.close().await
        }

        async fn call(&mut self, line: &str) -> Result<String> {
            self.0.expected_next = if line.starts_with("hash ") || line == "status" {
                3
            } else {
                2
            };
            self.0.call(line).await
        }
    }

    #[tokio::test]
    async fn sync_downloads_before_scanning_and_replays_reorganizations() {
        for light in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let first = genesis(&Network::Test.params());
            let second = Block::new(
                protocol::block::empty_header(1, first.hash(), first.header().commitment_root),
                vec![],
            );
            let third = Block::new(
                protocol::block::empty_header(2, second.hash(), second.header().commitment_root),
                vec![],
            );
            let wallet = Wallet::create(
                dir.path().join("wallet.redb"),
                &SpendingKey::from_bytes([42; 32]),
                first.hash(),
                &mut rand::rngs::OsRng,
            )
            .unwrap();
            let mut source = SnapshotSource {
                wallet: &wallet,
                blocks: vec![first, second, third],
                light,
                expected_next: 0,
                requests: vec![],
                fail_at: Some(1),
            };
            assert!(sync_wallet(&mut source, &wallet, light).await.is_err());
            assert_eq!(
                wallet.next_height().unwrap(),
                0,
                "failed download must not scan a prefix"
            );
            source.requests.clear();
            source.fail_at = None;
            assert_eq!(sync_wallet(&mut source, &wallet, light).await.unwrap(), 2);
            assert_eq!(source.requests, vec![0, 1, 2]);
            assert_eq!(wallet.next_height().unwrap(), 3);
            source.expected_next = 3;
            source.requests.clear();
            assert_eq!(sync_wallet(&mut source, &wallet, light).await.unwrap(), 2);
            assert!(
                source.requests.is_empty(),
                "up-to-date wallets do not fetch blocks"
            );

            // Rollback happens before the download; the remaining snapshot is
            // still fetched without interleaved scanning.
            let mut replacement = source.blocks[2].header().clone();
            replacement.timestamp += 1;
            source.blocks[2] = Block::new(replacement, vec![]);
            // Hash lookups happen before rollback, so use a separate source
            // that checks the invariant only for block requests below.
            let mut reorg = ReorgSource(source);
            assert_eq!(sync_wallet(&mut reorg, &wallet, light).await.unwrap(), 2);
            assert_eq!(reorg.0.requests, vec![2]);
            assert_eq!(
                wallet.scanned_hash(2).unwrap(),
                Some(reorg.0.blocks[2].hash())
            );
        }
    }

    #[test]
    fn nodes_use_the_default_or_given_datadir() {
        let dir = tempfile::tempdir().unwrap();
        let chain = dir.path().join("nested").join("chain");
        let resolved = node_datadir(Some(chain.clone()), Network::Test).unwrap();
        assert_eq!(resolved, chain.clone());
        assert!(chain.is_dir());
    }

    #[test]
    fn embedded_tor_cli_has_no_daemon_or_direct_transport_options() {
        for flag in [
            "--advertise",
            "--proxy",
            "--listen",
            "--socks-port",
            "--tor-binary",
            "--tor-external",
        ] {
            assert!(Cli::try_parse_from(["Rhombus", "run", flag, "127.0.0.1:9050"]).is_err());
        }
        let target = p2p::address::NetAddr::TorV3([9; 32]).endpoint(19000);
        let cli = Cli::try_parse_from([
            "Rhombus",
            "run",
            "--addnode",
            &target,
            "--addnode",
            &target,
            "--no-seeds",
        ])
        .unwrap();
        let Command::Run {
            no_p2p,
            no_seeds,
            addnode,
            max_outbound,
            p2p_port,
            ..
        } = cli.command
        else {
            panic!("run command")
        };
        assert!(!no_p2p);
        assert!(no_seeds);
        assert_eq!(addnode.len(), 2);
        assert_eq!(max_outbound, 8);
        assert_eq!(p2p_port, crate::config::DEFAULT_P2P_PORT);
        assert!(Cli::try_parse_from(["Rhombus", "status"]).is_err());
    }

    #[test]
    fn tor_deadlines_and_circuit_settings_are_configurable() {
        let cli = Cli::try_parse_from([
            "Rhombus",
            "run",
            "--connect-timeout",
            "45",
            "--handshake-timeout",
            "75",
            "--idle-timeout",
            "1200",
            "--message-timeout",
            "180",
            "--tor-bootstrap-timeout",
            "240",
            "--tor-circuit-request-timeout",
            "50",
            "--tor-intro-rendezvous-attempts",
            "2",
            "--retry-initial",
            "90",
            "--retry-max",
            "1800",
        ])
        .unwrap();
        let Command::Run {
            connect_timeout,
            handshake_timeout,
            idle_timeout,
            message_timeout,
            tor_bootstrap_timeout,
            tor_circuit_request_timeout,
            tor_intro_rendezvous_attempts,
            retry_initial,
            retry_max,
            ..
        } = cli.command
        else {
            panic!("run command")
        };
        assert_eq!(
            (
                connect_timeout,
                handshake_timeout,
                idle_timeout,
                message_timeout
            ),
            (45, 75, 1200, 180)
        );
        assert_eq!(
            (
                tor_bootstrap_timeout,
                tor_circuit_request_timeout,
                tor_intro_rendezvous_attempts
            ),
            (240, 50, 2)
        );
        assert_eq!((retry_initial, retry_max), (90, 1800));
    }

    /// The network a parsed command is for, if it takes one.
    fn network_of_command(command: &Command) -> Option<Network> {
        match command {
            Command::Run { network, .. }
            | Command::Keygen { network }
            | Command::Create { network, .. }
            | Command::BackupWallet { network, .. }
            | Command::RestoreWallet { network, .. }
            | Command::Address { network, .. }
            | Command::SetReceiveRotation { network, .. } => Some(*network),
            _ => None,
        }
    }

    #[test]
    fn wallet_backup_and_restore_commands_preserve_state_without_overwrite() {
        let directory = tempfile::tempdir().unwrap();
        let original = directory.path().join("original.redb");
        let backup = directory.path().join("backup.json");
        let restored = directory.path().join("restored.redb");
        let genesis = genesis(&Network::Test.params()).hash();
        let mut rng = rand::rngs::OsRng;
        let wallet =
            Wallet::create(&original, &SpendingKey::random(&mut rng), genesis, &mut rng).unwrap();
        wallet.new_address("retained label").unwrap();
        let expected = wallet.backup_json().unwrap();
        drop(wallet);
        let args = WalletArgs { wallet: original };
        backup_wallet(&args, &backup, Network::Test).unwrap();
        assert_eq!(std::fs::read(&backup).unwrap(), expected);
        assert!(backup_wallet(&args, &backup, Network::Test).is_err());
        assert_eq!(std::fs::read(&backup).unwrap(), expected);
        assert!(restore_wallet(&backup, &restored, Network::Main).is_err());
        assert!(!restored.exists());
        restore_wallet(&backup, &restored, Network::Test).unwrap();
        let wallet = Wallet::open(&restored, genesis).unwrap();
        assert_eq!(wallet.backup_json().unwrap(), expected);
        drop(wallet);
        assert!(restore_wallet(&backup, &restored, Network::Test).is_err());
        assert_eq!(
            Wallet::open(&restored, genesis)
                .unwrap()
                .backup_json()
                .unwrap(),
            expected
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(backup).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn every_command_defaults_to_the_main_network() {
        for argv in [
            &["Rhombus", "run"][..],
            &["Rhombus", "keygen"],
            &["Rhombus", "create", "--wallet", "w"],
            &["Rhombus", "address", "--wallet", "w"],
            &[
                "Rhombus",
                "backupwallet",
                "--wallet",
                "w",
                "--out",
                "backup.json",
            ],
            &[
                "Rhombus",
                "restorewallet",
                "--backup",
                "backup.json",
                "--wallet",
                "w",
            ],
        ] {
            let cli = Cli::try_parse_from(argv).unwrap();
            assert_eq!(
                network_of_command(&cli.command),
                Some(Network::Main),
                "{argv:?}"
            );
        }
        let explicit = Cli::try_parse_from(["Rhombus", "keygen", "--network", "test"]).unwrap();
        assert_eq!(network_of_command(&explicit.command), Some(Network::Test));
    }
}
