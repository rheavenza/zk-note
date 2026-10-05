//! Agent-first native authentication: this module never reads private key files.
use crate::{
    auth::{auth_http_client, get_or_create_device_id, save_auth_session, StoredAuthSession},
    client::auth::validate_and_normalize_server_url,
    config::{auth_session_file, resolve_data_dir},
    error::CliError,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use ssh_agent_client_rs::{Client, Identity};
use ssh_key::{Algorithm, HashAlg, PublicKey};
use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use zk_protocol::{
    auth::{AuthToken, SessionResponse},
    ssh::{SshChallenge, SshFinishRequest, SshStartRequest, SSH_AUTH_VERSION},
};
fn auth_error() -> CliError {
    CliError::AuthError("SSH authentication failed".into())
}
fn agent_error() -> CliError {
    CliError::AuthError(
        "SSH agent unavailable or refused signing; load an Ed25519 key with ssh-add".into(),
    )
}
fn connect_agent(path: &Path) -> Result<Client, CliError> {
    #[cfg(unix)]
    {
        let socket = std::os::unix::net::UnixStream::connect(path).map_err(|_| agent_error())?;
        socket
            .set_read_timeout(Some(Duration::from_secs(15)))
            .map_err(|_| agent_error())?;
        socket
            .set_write_timeout(Some(Duration::from_secs(15)))
            .map_err(|_| agent_error())?;
        Ok(Client::with_read_write(Box::new(socket)))
    }
    #[cfg(not(unix))]
    {
        Client::connect(path).map_err(|_| agent_error())
    }
}
/// Safe agent metadata only; never contains a private key or signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentIdentity {
    pub fingerprint: String,
    pub comment: String,
}
fn available_keys(agent: &mut Client) -> Result<Vec<PublicKey>, CliError> {
    let mut keys: Vec<PublicKey> = agent
        .list_all_identities()
        .map_err(|_| agent_error())?
        .into_iter()
        .filter_map(|identity| match identity {
            Identity::PublicKey(k) if k.algorithm() == Algorithm::Ed25519 => Some(k.into_owned()),
            _ => None,
        })
        .collect();
    keys.sort_by_key(|key| key.fingerprint(HashAlg::Sha256).to_string());
    keys.dedup_by(|a, b| a.key_data() == b.key_data());
    Ok(keys)
}
fn select_key(agent: &mut Client, selector: Option<&str>) -> Result<PublicKey, CliError> {
    let mut keys = available_keys(agent)?;
    if let Some(fingerprint) = selector {
        keys.retain(|key| key.fingerprint(HashAlg::Sha256).to_string() == fingerprint);
    }
    match keys.len() {
        0 => Err(CliError::AuthError("No supported matching ssh-ed25519 agent identity; load a key with ssh-add".into())),
        1 => Ok(keys.remove(0)),
        _ => Err(CliError::AuthError("Multiple SSH agent identities; choose --identity SHA256:... or select a key in the Account modal".into())),
    }
}
/// Discover only public Ed25519 identities via the library's agent API.
pub async fn discover_identities() -> Result<Vec<AgentIdentity>, CliError> {
    let path = std::env::var_os("SSH_AUTH_SOCK").ok_or_else(agent_error)?;
    tokio::task::spawn_blocking(move || {
        let keys = available_keys(&mut connect_agent(Path::new(&path))?)?;
        if keys.is_empty() {
            return Err(CliError::AuthError(
                "No supported ssh-ed25519 agent identity; load a key with ssh-add".into(),
            ));
        }
        Ok(keys
            .into_iter()
            .map(|key| AgentIdentity {
                fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
                // Strip terminal control characters and cap untrusted agent comments.
                comment: key
                    .comment()
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(80)
                    .collect(),
            })
            .collect())
    })
    .await
    .map_err(|_| agent_error())?
}
/// CLI-only interactive selection; noninteractive calls never guess among keys.
pub async fn interactive_selector(selector: Option<String>) -> Result<Option<String>, CliError> {
    use std::io::{IsTerminal, Write};
    if selector.is_some() {
        return Ok(selector);
    }
    let identities = discover_identities().await?;
    if identities.len() == 1 {
        return Ok(Some(identities[0].fingerprint.clone()));
    }
    if !std::io::stdin().is_terminal() {
        return Err(CliError::AuthError(
            "Multiple SSH identities; noninteractive login requires --identity SHA256:...".into(),
        ));
    }
    for (i, key) in identities.iter().enumerate() {
        println!("{}: ssh-ed25519 {} {}", i + 1, key.fingerprint, key.comment);
    }
    print!("Select identity [1-{}]: ", identities.len());
    std::io::stdout().flush().map_err(|_| auth_error())?;
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|_| auth_error())?;
    let index = input
        .trim()
        .parse::<usize>()
        .ok()
        .and_then(|n| n.checked_sub(1))
        .ok_or_else(auth_error)?;
    let key = identities.get(index).ok_or_else(auth_error)?;
    Ok(Some(key.fingerprint.clone()))
}
fn validate_challenge(challenge: &SshChallenge, request: &SshStartRequest) -> Result<(), CliError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| auth_error())?
        .as_secs();
    if challenge.nonce.len() != 43 {
        return Err(auth_error());
    }
    let nonce = Base64UrlUnpadded::decode_vec(&challenge.nonce).map_err(|_| auth_error())?;
    if &challenge.request != request
        || challenge.challenge_id.is_nil()
        || nonce.len() != 32
        || challenge.expires_at <= now
        || challenge.expires_at > now + 180
    {
        return Err(auth_error());
    }
    Ok(())
}
async fn bounded_json<T: serde::de::DeserializeOwned>(
    mut response: reqwest::Response,
) -> Result<T, CliError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| auth_error())? {
        if bytes.len() + chunk.len() > 8192 {
            return Err(auth_error());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| auth_error())
}
/// Prove ownership and persist only the existing restricted bearer-session representation.
pub async fn login(
    custom_data_dir: Option<&Path>,
    server: &str,
    account: Option<Uuid>,
    device: Option<Uuid>,
    selector: Option<String>,
) -> Result<StoredAuthSession, CliError> {
    let agent_path = std::env::var_os("SSH_AUTH_SOCK").ok_or_else(agent_error)?;
    login_with_agent(
        custom_data_dir,
        server,
        account,
        device,
        selector,
        Path::new(&agent_path),
    )
    .await
}
async fn login_with_agent(
    custom_data_dir: Option<&Path>,
    server: &str,
    account: Option<Uuid>,
    device: Option<Uuid>,
    selector: Option<String>,
    agent_path: &Path,
) -> Result<StoredAuthSession, CliError> {
    let server_url = validate_and_normalize_server_url(server)?;
    let data_dir = resolve_data_dir(custom_data_dir);
    std::fs::create_dir_all(&data_dir).map_err(|e| CliError::Io(e.to_string()))?;
    let device_id = get_or_create_device_id(&data_dir, device)?;
    let select_path = agent_path.to_path_buf();
    let key = tokio::task::spawn_blocking(move || {
        select_key(&mut connect_agent(&select_path)?, selector.as_deref())
    })
    .await
    .map_err(|_| agent_error())??;
    let request = SshStartRequest {
        version: SSH_AUTH_VERSION,
        audience: server_url.clone(),
        fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
        account_id: account,
        device_id,
    };
    let client = auth_http_client()?;
    let response = client
        .post(format!("{server_url}/v1/auth/ssh/start"))
        .json(&request)
        .send()
        .await
        .map_err(|_| auth_error())?;
    if !response.status().is_success() {
        return Err(auth_error());
    }
    let challenge: SshChallenge = bounded_json(response).await?;
    validate_challenge(&challenge, &request)?;
    let signing_bytes = challenge.signing_bytes().map_err(|_| auth_error())?;
    let sign_path = agent_path.to_path_buf();
    let signature = tokio::task::spawn_blocking(move || {
        let sig = connect_agent(&sign_path)?
            .sign(&key, &signing_bytes)
            .map_err(|_| agent_error())?;
        let bytes: Vec<u8> = sig.try_into().map_err(|_| agent_error())?;
        Ok::<_, CliError>(AuthToken::new(Base64UrlUnpadded::encode_string(&bytes)))
    })
    .await
    .map_err(|_| agent_error())??;
    let response = client
        .post(format!("{server_url}/v1/auth/ssh/finish"))
        .json(&SshFinishRequest {
            challenge,
            signature,
        })
        .send()
        .await
        .map_err(|_| auth_error())?;
    if !response.status().is_success() {
        return Err(auth_error());
    }
    let session: SessionResponse = bounded_json(response).await?;
    if session.device_id != Some(device_id)
        || account.is_some_and(|a| a != session.account_id)
        || session.token.is_empty()
    {
        return Err(auth_error());
    }
    let stored = StoredAuthSession {
        server_url,
        account_id: session.account_id,
        device_id,
        session_id: Some(session.session_id),
        token: session.token,
        expires_at: session.expires_at,
    };
    save_auth_session(&auth_session_file(&data_dir), &stored)?;
    Ok(stored)
}

/// Authenticated public-key management over the existing bearer session.
#[derive(Debug, clap::Subcommand)]
pub enum KeyCommand {
    List,
    Add {
        public_key: std::path::PathBuf,
        #[arg(long)]
        label: Option<String>,
    },
    Revoke {
        credential_id: Uuid,
    },
}
pub async fn manage_keys(
    custom_data_dir: Option<&Path>,
    command: KeyCommand,
) -> Result<(), CliError> {
    let dir = resolve_data_dir(custom_data_dir);
    let session = crate::auth::load_auth_session(&auth_session_file(&dir))?;
    let origin = validate_and_normalize_server_url(&session.server_url)?;
    let client = auth_http_client()?;
    let endpoint = format!("{origin}/v1/auth/ssh/keys");
    let request = match command {
        KeyCommand::List => client.get(&endpoint),
        KeyCommand::Add { public_key, label } => {
            use std::io::Read;
            if public_key.extension().and_then(|s| s.to_str()) != Some("pub") {
                return Err(CliError::AuthError("Expected a public .pub file".into()));
            }
            let mut input = String::new();
            std::fs::File::open(public_key)
                .map_err(|_| auth_error())?
                .take(4097)
                .read_to_string(&mut input)
                .map_err(|_| auth_error())?;
            if input.len() > 4096 || input.trim().chars().any(char::is_control) {
                return Err(auth_error());
            }
            let mut key = PublicKey::from_openssh(&input).map_err(|_| auth_error())?;
            if key.algorithm() != Algorithm::Ed25519 {
                return Err(auth_error());
            }
            key.set_comment("");
            let public_key = key.to_openssh().map_err(|_| auth_error())?;
            client
                .post(&endpoint)
                .json(&zk_protocol::ssh::AddSshKeyRequest { public_key, label })
        }
        KeyCommand::Revoke { credential_id } => {
            client.delete(format!("{endpoint}/{credential_id}"))
        }
    };
    let response = request
        .bearer_auth(session.token.expose_secret())
        .send()
        .await
        .map_err(|_| auth_error())?;
    if !response.status().is_success() {
        return Err(auth_error());
    }
    if response.status() == reqwest::StatusCode::NO_CONTENT {
        println!("SSH credential revoked.");
    } else if response.status() == reqwest::StatusCode::CREATED {
        let key: zk_protocol::ssh::SshCredential =
            response.json().await.map_err(|_| auth_error())?;
        println!("{} {}", key.credential_id, key.fingerprint);
    } else {
        let keys: Vec<zk_protocol::ssh::SshCredential> =
            response.json().await.map_err(|_| auth_error())?;
        for key in keys {
            println!(
                "{} {} {}",
                key.credential_id,
                key.fingerprint,
                if key.revoked { "revoked" } else { "active" }
            );
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Child, Command, Stdio};
    use zk_server::{create_app, AppState, ServerConfig};
    struct AgentFixture {
        child: Child,
        dir: std::path::PathBuf,
        socket: std::path::PathBuf,
    }
    impl AgentFixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("zk-ssh-agent-{}", Uuid::new_v4()));
            std::fs::create_dir(&dir).unwrap();
            let socket = dir.join("agent.sock");
            let child = Command::new("ssh-agent")
                .args(["-D", "-a"])
                .arg(&socket)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("ssh-agent test prerequisite");
            let fixture = Self { child, dir, socket };
            for _ in 0..100 {
                if connect_agent(&fixture.socket).is_ok() {
                    return fixture;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("test SSH agent did not start");
        }
    }
    impl Drop for AgentFixture {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
    #[tokio::test]
    async fn synthetic_agent_full_native_login_status_and_revoke() {
        let fixture = AgentFixture::new();
        let mut agent = connect_agent(&fixture.socket).unwrap();
        let key = ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519)
            .unwrap();
        let other = ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519)
            .unwrap();
        // Generated keys stay in process memory and are loaded directly into this isolated test agent.
        agent.add_identity(&key).unwrap();
        agent.add_identity(&other).unwrap();
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        assert_eq!(
            select_key(&mut agent, Some(&fingerprint))
                .unwrap()
                .key_data(),
            key.public_key().key_data()
        );
        let mut fingerprints = [
            fingerprint.clone(),
            other.fingerprint(HashAlg::Sha256).to_string(),
        ];
        fingerprints.sort();
        assert_eq!(
            available_keys(&mut agent).unwrap()[0]
                .fingerprint(HashAlg::Sha256)
                .to_string(),
            fingerprints[0]
        );
        assert!(select_key(&mut agent, None).is_err());
        assert!(select_key(&mut agent, Some("SHA256:missing")).is_err());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let state = AppState::new_in_memory(ServerConfig {
            ssh_auth_origin: origin.clone(),
            ..ServerConfig::default()
        })
        .unwrap();
        let account = Uuid::new_v4();
        state
            .db
            .add_ssh_key(account, &key.public_key().to_openssh().unwrap(), None, true)
            .await
            .unwrap();
        let app = create_app(state.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let data_dir = fixture.dir.join("client");
        let device = Uuid::new_v4();
        let session = login_with_agent(
            Some(&data_dir),
            &origin,
            Some(account),
            Some(device),
            Some(fingerprint),
            &fixture.socket,
        )
        .await
        .unwrap();
        assert_eq!(session.account_id, account);
        assert_eq!(session.device_id, device);
        let before = std::fs::read(auth_session_file(&data_dir)).unwrap();
        assert!(login_with_agent(
            Some(&data_dir),
            &origin,
            Some(account),
            Some(device),
            Some("SHA256:missing".into()),
            &fixture.socket
        )
        .await
        .is_err());
        assert_eq!(std::fs::read(auth_session_file(&data_dir)).unwrap(), before);
        assert!(
            crate::client::auth::check_auth_state_online(Some(&data_dir))
                .await
                .unwrap()
                .is_authenticated()
        );
        let status = crate::auth::api_query_status(&session).await.unwrap();
        assert_eq!(status.status, "active");
        assert!(!format!("{session:?}").contains(session.token.expose_secret()));
        let path = auth_session_file(&data_dir);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        for entry in std::fs::read_dir(&data_dir).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains("OPENSSH PRIVATE KEY"));
        }
        crate::client::auth::sign_out(Some(&data_dir))
            .await
            .unwrap();
        assert!(!path.exists());
        assert!(crate::auth::api_query_status(&session).await.is_err());
        server.abort();
    }
    #[test]
    fn isolated_agent_zero_one_multiple_and_unsupported_identities() {
        let fixture = AgentFixture::new();
        let mut agent = connect_agent(&fixture.socket).unwrap();
        assert!(select_key(&mut agent, None).is_err());
        let unsupported = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::OsRng,
            Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
        )
        .unwrap();
        agent.add_identity(&unsupported).unwrap();
        assert!(available_keys(&mut agent).unwrap().is_empty());
        assert!(select_key(&mut agent, None).is_err());
        let key = ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519)
            .unwrap();
        agent.add_identity(&key).unwrap();
        assert_eq!(
            select_key(&mut agent, None).unwrap().key_data(),
            key.public_key().key_data()
        );
        assert!(select_key(&mut agent, Some("SHA256:missing")).is_err());
        agent.remove_all_identities().unwrap();
        assert!(select_key(&mut agent, None).is_err());
    }
    #[test]
    fn malicious_challenge_and_agent_errors_are_safe() {
        let request = SshStartRequest {
            version: 1,
            audience: "https://notes.example.com".into(),
            fingerprint: format!(
                "SHA256:{}",
                base64ct::Base64Unpadded::encode_string(&[2; 32])
            ),
            account_id: None,
            device_id: Uuid::new_v4(),
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let good = SshChallenge {
            request: request.clone(),
            challenge_id: Uuid::new_v4(),
            nonce: Base64UrlUnpadded::encode_string(&[1; 32]),
            expires_at: now + 120,
        };
        assert!(validate_challenge(&good, &request).is_ok());
        for scenario in 0..6 {
            let mut bad = good.clone();
            match scenario {
                0 => bad.request.audience = "https://evil.example".into(),
                1 => bad.request.device_id = Uuid::new_v4(),
                2 => bad.expires_at = 0,
                3 => bad.expires_at = now + 181,
                4 => bad.nonce = "bad".into(),
                _ => bad.request.account_id = Some(Uuid::new_v4()),
            }
            assert!(validate_challenge(&bad, &request).is_err());
        }
        assert!(connect_agent(Path::new("/missing/agent-secret-sentinel")).is_err());
        let error = connect_agent(Path::new("/missing/agent-secret-sentinel"))
            .err()
            .unwrap();
        assert!(!format!("{error:?}").contains("agent-secret-sentinel"));
    }
}
