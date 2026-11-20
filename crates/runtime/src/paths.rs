//! Working-directory storage locations shared by `kryptos`,
//! `wallet`, and the desktop app, so all three find the same chain
//! and wallet without being told where to look.
//!
//! ```text
//! <working directory>/kryptos-data/ see [`user_data_dir`]
//!   <network>/                 see [`network_dir`]
//!     chain/chain.redb         the node's datadir, see [`chain_dir`]
//!     chain/rpc.token          the node's control token
//!     chain/peers.dat          the node's saved address book
//!     wallet.redb              see [`wallet_file`]
//!     wallet-rpc.token         wallet RPC token
//! ```
//!
//! Each database is locked while open, so a `kryptos` and a desktop app
//! using the same network directory cannot run at the same time.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::config::Network;
use crate::Result;

/// Open options whose newly created files are readable by the owner only
/// on Unix, from the moment they exist. Add the access mode to taste.
pub fn private_open_options() -> OpenOptions {
    // Only Unix sets a mode; elsewhere the builder is returned unchanged.
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

/// Makes an already open file owner-only on Unix, for files that may have
/// existed with broader permissions before [`private_open_options`] could
/// apply; a no-op elsewhere.
///
/// # Errors
/// Fails if the permissions cannot be changed.
pub fn restrict(file: &File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = file;
    Ok(())
}

/// Creates `path` for writing, failing if it exists, owner-only on Unix.
///
/// # Errors
/// Fails if the file exists or cannot be created.
pub fn create_private(path: &Path) -> Result<File> {
    Ok(private_open_options()
        .write(true)
        .create_new(true)
        .open(path)?)
}

/// Writes `bytes` to a new owner-only file at `path`, replacing a stale one,
/// and syncs it: tokens, settings and address books are private to the user.
///
/// # Errors
/// Fails if the old file cannot be removed or the new one written.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
        _ => {}
    }
    let mut file = create_private(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Subdirectory of a network directory holding the node's chain and token.
pub const CHAIN_DIR: &str = "chain";
/// Default wallet file name inside a network directory.
pub const WALLET_FILE: &str = "wallet.redb";

/// The default Kryptos data directory under the process's current working
/// directory: `./kryptos-data`.
///
/// # Errors
/// Returns an I/O error if the current working directory cannot be determined.
pub fn user_data_dir() -> Result<PathBuf> {
    Ok(std::env::current_dir()?.join("kryptos-data"))
}

/// The directory holding one network's chain and wallet.
pub fn network_dir(data: &Path, network: Network) -> PathBuf {
    data.join(network.to_string())
}

/// The node data directory inside a network directory.
pub fn chain_dir(network_dir: &Path) -> PathBuf {
    network_dir.join(CHAIN_DIR)
}

/// The default wallet file inside a network directory.
pub fn wallet_file(network_dir: &Path) -> PathBuf {
    network_dir.join(WALLET_FILE)
}

/// The node's control token file inside a network directory.
pub fn node_token_file(network_dir: &Path) -> PathBuf {
    chain_dir(network_dir).join(crate::rpc::TOKEN_FILE)
}

/// [`network_dir`] under [`user_data_dir`].
///
/// # Errors
/// See [`user_data_dir`].
pub fn default_network_dir(network: Network) -> Result<PathBuf> {
    Ok(network_dir(&user_data_dir()?, network))
}

/// Creates a directory and its parents. New directories are owner-only on
/// Unix; on Windows they inherit the parent's access list, which under the
/// user profile grants only the user, administrators, and SYSTEM.
/// Existing directories are left unchanged.
///
/// # Errors
/// Fails if a directory cannot be created.
pub fn private_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_files_are_replaced_and_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        write_private(&path, b"first").unwrap();
        write_private(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn default_storage_uses_the_working_directory() {
        assert_eq!(
            user_data_dir().unwrap(),
            std::env::current_dir().unwrap().join("kryptos-data")
        );
    }

    #[test]
    fn every_network_has_its_own_chain_wallet_and_token() {
        let data = Path::new("data");
        let test = network_dir(data, Network::Test);
        let main = network_dir(data, Network::Main);
        assert_ne!(test, main);
        assert_eq!(chain_dir(&test), data.join("test").join("chain"));
        assert_eq!(wallet_file(&test), data.join("test").join("wallet.redb"));
        assert_eq!(
            node_token_file(&test),
            data.join("test").join("chain").join("rpc.token")
        );
    }

    #[test]
    fn private_directories_are_created_recursively_and_owner_only_on_unix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a").join("b");
        private_directory(&path).unwrap();
        private_directory(&path).unwrap();
        assert!(path.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }
}
