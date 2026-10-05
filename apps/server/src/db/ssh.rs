//! Native SSH public credentials and atomic one-time proof/session issuance.
use super::ServerDb;
use crate::error::DbError;
use base64ct::{Base64UrlUnpadded, Encoding};
use rand_core::{OsRng, RngCore};
use rusqlite::{params, OptionalExtension};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zk_protocol::auth::SessionResponse;
use zk_protocol::ssh::{
    SshChallenge, SshCredential, SshFinishRequest, SshStartRequest, SSH_AUTH_VERSION,
};

/// Shared server-only parser also used by operator provisioning.
pub fn parse_public_key(input: &str) -> Result<(ssh_key::PublicKey, String, String), DbError> {
    zk_server_auth::ssh::parse_public_key(input).map_err(|_| DbError::SshAuthFailed)
}
fn now() -> Result<u64, DbError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| DbError::ChallengeExpired)
}
impl ServerDb {
    /// Provision an operator-owned account or add a credential to an existing account.
    /// The public key is globally unique, including revoked credentials.
    pub async fn add_ssh_key(
        &self,
        account: Uuid,
        public_key: &str,
        label: Option<String>,
        create_account: bool,
    ) -> Result<SshCredential, DbError> {
        let (_, canonical, fingerprint) = parse_public_key(public_key)?;
        if label
            .as_ref()
            .is_some_and(|s| s.len() > 128 || s.chars().any(char::is_control))
        {
            return Err(DbError::SshAuthFailed);
        }
        let id = Uuid::new_v4();
        let connection = self.connection();
        let mut conn = connection.lock().await;
        let tx = conn.transaction()?;
        if create_account {
            tx.execute(
                "INSERT INTO accounts (id, status) VALUES (?1, 'active')",
                [account.to_string()],
            )?;
        }
        let active: Option<bool> = tx
            .query_row(
                "SELECT status = 'active' FROM accounts WHERE id = ?1",
                [account.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        if active != Some(true) {
            return Err(DbError::SshAccountNotFound);
        }
        let duplicate: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM ssh_credentials WHERE fingerprint = ?1 OR public_key = ?2)", params![fingerprint, canonical], |r| r.get(0))?;
        if duplicate {
            return Err(DbError::SshCredentialAlreadyExists);
        }
        tx.execute("INSERT INTO ssh_credentials (credential_id, account_id, fingerprint, public_key, label) VALUES (?1, ?2, ?3, ?4, ?5)", params![id.to_string(), account.to_string(), fingerprint, canonical, label])?;
        tx.commit()?;
        Ok(SshCredential {
            credential_id: id,
            fingerprint,
            label,
            device_id: None,
            revoked: false,
        })
    }
    /// List public metadata scoped to the authenticated account.
    pub async fn list_ssh_keys(&self, account: Uuid) -> Result<Vec<SshCredential>, DbError> {
        let connection = self.connection();
        let conn = connection.lock().await;
        let mut stmt = conn.prepare("SELECT credential_id, fingerprint, label, device_id, revoked_at IS NOT NULL FROM ssh_credentials WHERE account_id = ?1 ORDER BY fingerprint")?;
        let rows = stmt.query_map([account.to_string()], |r| {
            let id: String = r.get(0)?;
            let device: Option<String> = r.get(3)?;
            Ok((
                id,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                device,
                r.get::<_, bool>(4)?,
            ))
        })?;
        let mut result = Vec::new();
        for row in rows {
            let (id, fingerprint, label, device, revoked) = row?;
            result.push(SshCredential {
                credential_id: Uuid::parse_str(&id).map_err(|_| DbError::SshAuthFailed)?,
                fingerprint,
                label,
                device_id: device
                    .map(|d| Uuid::parse_str(&d))
                    .transpose()
                    .map_err(|_| DbError::SshAuthFailed)?,
                revoked,
            });
        }
        Ok(result)
    }
    /// Revoke a key and every session issued by that key in one transaction.
    pub async fn revoke_ssh_key(&self, account: Uuid, credential: Uuid) -> Result<bool, DbError> {
        let connection = self.connection();
        let mut conn = connection.lock().await;
        let tx = conn.transaction()?;
        let n = tx.execute("UPDATE ssh_credentials SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP) WHERE account_id = ?1 AND credential_id = ?2", params![account.to_string(), credential.to_string()])?;
        // A lost machine's pinned device and all its sessions are revoked too.
        tx.execute("UPDATE devices SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP) WHERE account_id = ?1 AND device_id = (SELECT device_id FROM ssh_credentials WHERE account_id = ?1 AND credential_id = ?2)", params![account.to_string(), credential.to_string()])?;
        tx.execute("UPDATE sessions SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP) WHERE account_id = ?1 AND device_id = (SELECT device_id FROM ssh_credentials WHERE account_id = ?1 AND credential_id = ?2)", params![account.to_string(), credential.to_string()])?;
        tx.execute("UPDATE sessions SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP) WHERE account_id = ?1 AND ssh_credential_id = ?2", params![account.to_string(), credential.to_string()])?;
        tx.commit()?;
        Ok(n == 1)
    }
    /// Carry key provenance into device sessions authorized by an SSH-issued session.
    /// If revocation raced authorization, revoke the new session before returning failure.
    pub async fn inherit_ssh_credential(
        &self,
        account: Uuid,
        source: Uuid,
        target: Uuid,
    ) -> Result<(), DbError> {
        let connection = self.connection();
        let mut conn = connection.lock().await;
        let tx = conn.transaction()?;
        let credential: Option<Option<String>> = tx.query_row(
            "SELECT ssh_credential_id FROM sessions WHERE account_id = ?1 AND session_id = ?2 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)",
            params![account.to_string(), source.to_string()], |r| r.get(0)).optional()?;
        let valid = if let Some(credential_id) = &credential {
            tx.execute("UPDATE sessions SET ssh_credential_id = ?1 WHERE account_id = ?2 AND session_id = ?3", params![credential_id, account.to_string(), target.to_string()])?;
            if let Some(id) = credential_id {
                tx.query_row(
                    "SELECT revoked_at IS NULL FROM ssh_credentials WHERE credential_id = ?1",
                    [id],
                    |r| r.get::<_, bool>(0),
                )
                .optional()?
                .unwrap_or(false)
            } else {
                true
            }
        } else {
            false
        };
        if !valid {
            tx.execute("UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP WHERE account_id = ?1 AND session_id = ?2", params![account.to_string(), target.to_string()])?;
        }
        tx.commit()?;
        if valid {
            Ok(())
        } else {
            Err(DbError::SshAuthFailed)
        }
    }

    /// Create a short-lived proof without looking up the account/key (no enumeration).
    pub async fn start_ssh_login(
        &self,
        request: SshStartRequest,
        audience: &str,
    ) -> Result<SshChallenge, DbError> {
        if request.version != SSH_AUTH_VERSION
            || request.audience != audience
            || request.device_id.is_nil()
            || request.fingerprint.len() > 100
            || request.fingerprint.parse::<ssh_key::Fingerprint>().is_err()
        {
            return Err(DbError::SshAuthFailed);
        }
        let timestamp = now()?;
        let mut nonce = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| DbError::ChallengeNotFound)?;
        let challenge = SshChallenge {
            request,
            challenge_id: Uuid::new_v4(),
            nonce: Base64UrlUnpadded::encode_string(&nonce),
            expires_at: timestamp + 120,
        };
        challenge
            .signing_bytes()
            .map_err(|_| DbError::SshAuthFailed)?;
        let connection = self.connection();
        let conn = connection.lock().await;
        // Known active credentials are linked; indistinguishable dummy challenges
        // for unknown/revoked keys prevent account enumeration at this endpoint.
        let credential: Option<String> = conn.query_row(
            "SELECT c.credential_id FROM ssh_credentials c JOIN accounts a ON a.id = c.account_id WHERE c.fingerprint = ?1 AND c.revoked_at IS NULL AND a.status = 'active'",
            [&challenge.request.fingerprint], |r| r.get(0)).optional()?;
        conn.execute(
            "DELETE FROM ssh_challenges WHERE expires_at <= ?1",
            [timestamp],
        )?;
        conn.execute("INSERT INTO ssh_challenges (challenge_id, purpose, challenge_json, expires_at, credential_id) VALUES (?1, 'login-v1', ?2, ?3, ?4)", params![challenge.challenge_id.to_string(), serde_json::to_string(&challenge)?, challenge.expires_at, credential])?;
        Ok(challenge)
    }
    /// Consume even failed proofs, then atomically validate key/device and issue a bearer session.
    pub async fn finish_ssh_login(
        &self,
        req: &SshFinishRequest,
        audience: &str,
    ) -> Result<SessionResponse, DbError> {
        let connection = self.connection();
        let mut conn = connection.lock().await;
        let tx = conn.transaction()?;
        let stored: Option<(String, String, Option<String>)> = tx.query_row("DELETE FROM ssh_challenges WHERE challenge_id = ?1 RETURNING purpose, challenge_json, credential_id", [req.challenge.challenge_id.to_string()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).optional()?;
        // Commit the deletion independently so bad proofs cannot retry the challenge.
        tx.commit()?;
        let (purpose, json, credential) = stored.ok_or(DbError::ChallengeNotFound)?;
        if purpose != "login-v1" {
            return Err(DbError::SshAuthFailed);
        }
        let challenge: SshChallenge = serde_json::from_str(&json)?;
        if challenge != req.challenge
            || challenge.expires_at <= now()?
            || challenge.request.audience != audience
            || challenge.request.version != SSH_AUTH_VERSION
        {
            return Err(DbError::ChallengeNotFound);
        }
        let tx = conn.transaction()?;
        let record: Option<(String, String, String, Option<String>)> = tx.query_row(
            "SELECT c.credential_id, c.account_id, c.public_key, c.device_id FROM ssh_credentials c JOIN accounts a ON a.id = c.account_id WHERE c.fingerprint = ?1 AND c.credential_id = ?2 AND c.revoked_at IS NULL AND a.status = 'active'", params![challenge.request.fingerprint, credential], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).optional()?;
        let (credential_id, account_str, public_key, bound_device) =
            record.ok_or(DbError::SshAuthFailed)?;
        let account_id = Uuid::parse_str(&account_str).map_err(|_| DbError::SshAuthFailed)?;
        let device_str = challenge.request.device_id.to_string();
        if challenge
            .request
            .account_id
            .is_some_and(|a| a != account_id)
            || bound_device.as_ref().is_some_and(|d| d != &device_str)
        {
            return Err(DbError::SshAuthFailed);
        }
        let revoked: Option<bool> = tx.query_row("SELECT revoked_at IS NOT NULL FROM devices WHERE account_id = ?1 AND device_id = ?2", params![account_str, device_str], |r| r.get(0)).optional()?;
        if revoked == Some(true) {
            return Err(DbError::SshAuthFailed);
        }
        let message = challenge
            .signing_bytes()
            .map_err(|_| DbError::SshAuthFailed)?;
        zk_server_auth::ssh::verify_signature(&public_key, &message, req.signature.expose_secret())
            .map_err(|_| DbError::SshAuthFailed)?;
        let (session, token) = Self::create_session_on(
            &tx,
            account_id,
            Some(challenge.request.device_id),
            Some("SSH native client".into()),
            Some(3600),
        )?;
        tx.execute(
            "UPDATE ssh_credentials SET device_id = ?1 WHERE credential_id = ?2",
            params![device_str, credential_id],
        )?;
        tx.execute(
            "UPDATE sessions SET ssh_credential_id = ?1 WHERE session_id = ?2",
            params![credential_id, session.session_id.to_string()],
        )?;
        tx.commit()?;
        Ok(SessionResponse {
            token,
            session_id: session.session_id,
            account_id,
            device_id: Some(challenge.request.device_id),
            expires_at: session.expires_at,
        })
    }
}
