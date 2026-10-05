//! Native server and operator-controlled public-key provisioning.
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use uuid::Uuid;
use zk_server::{db::ServerDb, init_logging, run_server, shutdown_signal, ServerConfig};
#[derive(Debug, Parser)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Debug, Subcommand)]
enum Command {
    Account {
        #[command(subcommand)]
        command: AccountCommand,
    },
}
#[derive(Debug, Subcommand)]
enum AccountCommand {
    Create {
        #[arg(long)]
        ssh_key: PathBuf,
        #[arg(long)]
        label: Option<String>,
    },
    AddSshKey {
        account_id: Uuid,
        #[arg(long)]
        ssh_key: PathBuf,
        #[arg(long)]
        label: Option<String>,
    },
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let config = ServerConfig::from_env()?;
    if let Some(Command::Account { command }) = cli.command {
        let path = config
            .db_path
            .as_deref()
            .ok_or("Set ZK_SERVER_DB_PATH for persistent provisioning")?;
        let db = ServerDb::open_file(path)?;
        let (account, key_path, label, create) = match command {
            AccountCommand::Create { ssh_key, label } => (Uuid::new_v4(), ssh_key, label, true),
            AccountCommand::AddSshKey {
                account_id,
                ssh_key,
                label,
            } => (account_id, ssh_key, label, false),
        };
        let public_key = zk_server_auth::ssh::read_public_key_file(&key_path)
            .map_err(|_| "Expected a valid ssh-ed25519 PUBLIC .pub file (at most 4096 bytes)")?;
        let credential = db
            .add_ssh_key(account, &public_key, label, create)
            .await
            .map_err(|error| match error {
                zk_server::error::DbError::SshAccountNotFound => "Unknown or inactive account",
                zk_server::error::DbError::SshCredentialAlreadyExists => "SSH public credential already registered",
                _ => "Public-key provisioning failed (expected a unique ssh-ed25519 public key and safe label)",
            })?;
        println!(
            "Account: {account}\nCredential: {}\nFingerprint: {}",
            credential.credential_id, credential.fingerprint
        );
        return Ok(());
    }
    init_logging(&config)?;
    tracing::info!(host = %config.host, port = config.port, "initializing zero-knowledge server");
    run_server(config, shutdown_signal()).await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn no_argument_startup_remains_default() {
        assert!(Cli::try_parse_from(["zk-server"])
            .unwrap()
            .command
            .is_none());
    }
}
