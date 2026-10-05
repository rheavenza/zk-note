//! Deterministic native SSH authentication/security integration coverage.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use rand_core::OsRng;
use serde_json::{json, Value};
use signature::Signer;
use ssh_key::{Algorithm, PrivateKey, Signature};
use tower::ServiceExt;
use uuid::Uuid;
use zk_protocol::{
    auth::{AuthToken, SessionResponse},
    ssh::*,
};
use zk_server::{
    authenticate_bearer_token, create_app,
    db::{ssh::parse_public_key, ServerDb},
    AppState, ServerConfig,
};
const ORIGIN: &str = "http://127.0.0.1:8080";
fn key() -> PrivateKey {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()
}
fn public(key: &PrivateKey) -> String {
    key.public_key().to_openssh().unwrap()
}
fn start(key: &PrivateKey, device: Uuid) -> SshStartRequest {
    SshStartRequest {
        version: 1,
        fingerprint: key.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
        audience: ORIGIN.into(),
        account_id: None,
        device_id: device,
    }
}
fn proof(key: &PrivateKey, challenge: SshChallenge) -> SshFinishRequest {
    let sig: Signature = key.try_sign(&challenge.signing_bytes().unwrap()).unwrap();
    let bytes: Vec<u8> = sig.try_into().unwrap();
    SshFinishRequest {
        challenge,
        signature: AuthToken::new(Base64UrlUnpadded::encode_string(&bytes)),
    }
}
async fn call(
    app: &Router,
    method: &str,
    path: &str,
    body: Value,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 100_000).await.unwrap();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, value)
}
async fn setup() -> (ServerDb, PrivateKey, Uuid) {
    let db = ServerDb::new_in_memory().unwrap();
    let key = key();
    let account = Uuid::new_v4();
    db.add_ssh_key(account, &public(&key), Some("machine one".into()), true)
        .await
        .unwrap();
    (db, key, account)
}
#[tokio::test]
async fn public_parser_uniqueness_and_owner_constraints() {
    let (db, key, account) = setup().await;
    let (parsed, canonical, fingerprint) =
        parse_public_key(&format!("{} comment", public(&key))).unwrap();
    assert_eq!(parsed.algorithm(), Algorithm::Ed25519);
    assert_eq!(canonical, public(&key));
    assert_eq!(
        fingerprint,
        key.fingerprint(ssh_key::HashAlg::Sha256).to_string()
    );
    for malformed in [
        "",
        "ssh-ed25519 not-base64",
        "ssh-rsa AAAA",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
    ] {
        assert!(parse_public_key(malformed).is_err());
    }
    // Library fixture: valid OpenSSH ECDSA public key, unsupported by this profile.
    let unsupported = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHwf2HMM5TRXvo2SQJjsNkiDD5KqiiNjrGVv3UUh+mMT5RHxiRtOnlqvjhQtBq0VpmpCV/PwUdhOig4vkbqAcEc= user@example.com";
    assert!(parse_public_key(unsupported).is_err());
    assert!(db
        .add_ssh_key(account, &public(&key), None, false)
        .await
        .is_err());
    assert!(db
        .add_ssh_key(Uuid::new_v4(), &public(&key), None, true)
        .await
        .is_err());
    assert!(db
        .add_ssh_key(Uuid::new_v4(), &public(&super_key()), None, false)
        .await
        .is_err());
    let keys = db.list_ssh_keys(account).await.unwrap();
    assert_eq!(keys.len(), 1);
}
fn super_key() -> PrivateKey {
    key()
}
#[tokio::test]
async fn random_short_lived_challenges_no_enumeration_and_single_use() {
    let (db, key, _) = setup().await;
    let device = Uuid::new_v4();
    let a = db
        .start_ssh_login(start(&key, device), ORIGIN)
        .await
        .unwrap();
    let b = db
        .start_ssh_login(start(&key, device), ORIGIN)
        .await
        .unwrap();
    assert_ne!(a.nonce, b.nonce);
    assert_ne!(a.challenge_id, b.challenge_id);
    assert_eq!(Base64UrlUnpadded::decode_vec(&a.nonce).unwrap().len(), 32);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(a.expires_at >= now + 119 && a.expires_at <= now + 120);
    let unknown = super_key();
    assert!(db
        .start_ssh_login(start(&unknown, device), ORIGIN)
        .await
        .is_ok());
    let proof = proof(&key, a);
    let (one, two) = tokio::join!(
        db.finish_ssh_login(&proof, ORIGIN),
        db.finish_ssh_login(&proof, ORIGIN)
    );
    assert_ne!(one.is_ok(), two.is_ok());
    assert!(db.finish_ssh_login(&proof, ORIGIN).await.is_err());
}
#[tokio::test]
async fn failed_proofs_consume_challenge_and_never_issue_sessions() {
    let (db, key, account) = setup().await;
    for scenario in 0..10 {
        let mut request = start(&key, Uuid::new_v4());
        if scenario == 5 {
            request.account_id = Some(Uuid::new_v4());
        }
        let challenge = db.start_ssh_login(request, ORIGIN).await.unwrap();
        let mut req = proof(&key, challenge.clone());
        match scenario {
            0 => req.challenge.request.device_id = Uuid::new_v4(),
            1 => req.challenge.request.audience = "https://wrong.example".into(),
            2 => {
                req.challenge.request.fingerprint = super_key()
                    .fingerprint(ssh_key::HashAlg::Sha256)
                    .to_string()
            }
            3 => req.challenge.expires_at += 1,
            4 => req = proof(&super_key(), challenge.clone()),
            5 => {}
            6 => req.signature = AuthToken::new("malformed"),
            7 => {
                // True server expiry, not a client-side timestamp edit.
                let mut expired = challenge.clone();
                expired.expires_at = 1;
                let conn = db.connection();
                let conn = conn.lock().await;
                conn.execute("UPDATE ssh_challenges SET challenge_json = ?1, expires_at = 1 WHERE challenge_id = ?2", rusqlite::params![serde_json::to_string(&expired).unwrap(), challenge.challenge_id.to_string()]).unwrap();
                req = proof(&key, expired);
            }
            8 => req.challenge.request.account_id = Some(account),
            9 => req.challenge.nonce = Base64UrlUnpadded::encode_string(&[9; 32]),
            _ => unreachable!(),
        }
        assert!(
            db.finish_ssh_login(&req, ORIGIN).await.is_err(),
            "scenario {scenario}"
        );
        assert!(db
            .finish_ssh_login(&proof(&key, challenge), ORIGIN)
            .await
            .is_err());
    }
    assert!(db.list_sessions(account).await.unwrap().is_empty());
    let mut request = start(&key, Uuid::new_v4());
    request.audience = "https://wrong.example".into();
    assert!(db.start_ssh_login(request, ORIGIN).await.is_err());
}
#[tokio::test]
async fn device_pin_revoked_key_device_and_session_fail_closed() {
    let (db, key, account) = setup().await;
    let device = Uuid::new_v4();
    let req = proof(
        &key,
        db.start_ssh_login(start(&key, device), ORIGIN)
            .await
            .unwrap(),
    );
    let session = db.finish_ssh_login(&req, ORIGIN).await.unwrap();
    assert_eq!(session.account_id, account);
    assert_eq!(session.device_id, Some(device));
    assert!(
        authenticate_bearer_token(&db, session.token.expose_secret())
            .await
            .is_ok()
    );
    db.revoke_session(account, session.session_id)
        .await
        .unwrap();
    assert!(
        authenticate_bearer_token(&db, session.token.expose_secret())
            .await
            .is_err()
    );
    let req = proof(
        &key,
        db.start_ssh_login(start(&key, device), ORIGIN)
            .await
            .unwrap(),
    );
    let session = db.finish_ssh_login(&req, ORIGIN).await.unwrap();
    db.revoke_device(account, device).await.unwrap();
    assert!(
        authenticate_bearer_token(&db, session.token.expose_secret())
            .await
            .is_err()
    );
    for device in [device, Uuid::new_v4()] {
        let req = proof(
            &key,
            db.start_ssh_login(start(&key, device), ORIGIN)
                .await
                .unwrap(),
        );
        assert!(db.finish_ssh_login(&req, ORIGIN).await.is_err());
    }
    let second = super_key();
    let second_device = Uuid::new_v4();
    let cred = db
        .add_ssh_key(account, &public(&second), None, false)
        .await
        .unwrap();
    let req = proof(
        &second,
        db.start_ssh_login(start(&second, second_device), ORIGIN)
            .await
            .unwrap(),
    );
    let session = db.finish_ssh_login(&req, ORIGIN).await.unwrap();
    assert!(db
        .revoke_ssh_key(Uuid::new_v4(), cred.credential_id)
        .await
        .is_ok_and(|r| !r));
    db.revoke_ssh_key(account, cred.credential_id)
        .await
        .unwrap();
    assert!(
        authenticate_bearer_token(&db, session.token.expose_secret())
            .await
            .is_err()
    );
    for device in [second_device, Uuid::new_v4()] {
        let req = proof(
            &second,
            db.start_ssh_login(start(&second, device), ORIGIN)
                .await
                .unwrap(),
        );
        assert!(db.finish_ssh_login(&req, ORIGIN).await.is_err());
    }
    assert!(db
        .list_ssh_keys(account)
        .await
        .unwrap()
        .iter()
        .any(|k| k.revoked));
}
#[tokio::test]
async fn full_http_contract_and_authenticated_key_management() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let key = key();
    let account = Uuid::new_v4();
    let device = Uuid::new_v4();
    state
        .db
        .add_ssh_key(account, &public(&key), None, true)
        .await
        .unwrap();
    let app = create_app(state.clone());
    let (status, value) = call(
        &app,
        "POST",
        "/v1/auth/ssh/start",
        json!(start(&key, device)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let challenge: SshChallenge = serde_json::from_value(value).unwrap();
    let req = proof(&key, challenge);
    let (status, value) = call(&app, "POST", "/v1/auth/ssh/finish", json!(req), None).await;
    assert_eq!(status, StatusCode::OK);
    let session: SessionResponse = serde_json::from_value(value).unwrap();
    let token = session.token.expose_secret();
    assert_eq!(
        call(&app, "POST", "/v1/auth/ssh/finish", json!(req), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, who) = call(
        &app,
        "GET",
        "/v1/auth/session/status",
        Value::Null,
        Some(token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(who["account_id"], account.to_string());
    assert_eq!(
        call(&app, "GET", "/v1/auth/ssh/keys", Value::Null, None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let second = super_key();
    let (status, value) = call(
        &app,
        "POST",
        "/v1/auth/ssh/keys",
        json!({"public_key": public(&second), "label": "machine two"}),
        Some(token),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let credential: SshCredential = serde_json::from_value(value).unwrap();
    let (status, keys) = call(&app, "GET", "/v1/auth/ssh/keys", Value::Null, Some(token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(keys.as_array().unwrap().len(), 2);
    let other_account = Uuid::new_v4();
    let (_, other_token) = state
        .db
        .create_session(other_account, None, None, None)
        .await
        .unwrap();
    assert_eq!(
        call(
            &app,
            "DELETE",
            &format!("/v1/auth/ssh/keys/{}", credential.credential_id),
            Value::Null,
            Some(other_token.expose_secret())
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(
            &app,
            "DELETE",
            &format!("/v1/auth/ssh/keys/{}", credential.credential_id),
            Value::Null,
            Some(token)
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/auth/session/revoke",
            json!({}),
            Some(token)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &app,
            "GET",
            "/v1/auth/session/status",
            Value::Null,
            Some(token)
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn auth_traffic_rejects_secrets_and_errors_never_echo_payloads() {
    let app = create_app(AppState::new_in_memory(ServerConfig::default()).unwrap());
    for path in ["/v1/auth/ssh/start", "/v1/auth/ssh/finish"] {
        for secret_field in [
            "passphrase",
            "vault_key",
            "private_key",
            "note",
            "body",
            "title",
            "tags",
        ] {
            let (status, value) = call(
                &app,
                "POST",
                path,
                json!({secret_field: "super-secret-sentinel"}),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(!value.to_string().contains("super-secret-sentinel"));
        }
    }
    let key = key();
    let db = ServerDb::new_in_memory().unwrap();
    let challenge = db
        .start_ssh_login(start(&key, Uuid::new_v4()), ORIGIN)
        .await
        .unwrap();
    let req = proof(&key, challenge);
    let debug = format!("{req:?}");
    assert!(!debug.contains(req.signature.expose_secret()));
    assert!(!debug.contains(&req.challenge.nonce));
    let traffic = serde_json::to_string(&req).unwrap();
    for field in ["vault_key", "passphrase", "private_key", "plaintext"] {
        assert!(!traffic.contains(field));
    }
}
#[test]
fn configured_audience_rejects_unsafe_or_ambiguous_origins() {
    for origin in [
        "http://remote.example",
        "https://user:password@example.com",
        "https://example.com/path",
        "https://example.com/",
        "https://example.com?x=1",
        "ssh://example.com",
    ] {
        assert!(ServerConfig {
            ssh_auth_origin: origin.into(),
            ..ServerConfig::default()
        }
        .validate_ssh_origin()
        .is_err());
    }
    for origin in ["https://notes.example.com", ORIGIN, "http://[::1]:8080"] {
        assert!(ServerConfig {
            ssh_auth_origin: origin.into(),
            ..ServerConfig::default()
        }
        .validate_ssh_origin()
        .is_ok());
    }
}

#[tokio::test]
async fn derived_device_sessions_inherit_key_revocation() {
    let (db, key, account) = setup().await;
    let req = proof(
        &key,
        db.start_ssh_login(start(&key, Uuid::new_v4()), ORIGIN)
            .await
            .unwrap(),
    );
    let session = db.finish_ssh_login(&req, ORIGIN).await.unwrap();
    let (derived, token) = db
        .create_session(account, Some(Uuid::new_v4()), None, None)
        .await
        .unwrap();
    db.inherit_ssh_credential(account, session.session_id, derived.session_id)
        .await
        .unwrap();
    assert!(authenticate_bearer_token(&db, token.expose_secret())
        .await
        .is_ok());
    let id = db.list_ssh_keys(account).await.unwrap()[0].credential_id;
    db.revoke_ssh_key(account, id).await.unwrap();
    assert!(authenticate_bearer_token(&db, token.expose_secret())
        .await
        .is_err());
    // A source revoked during authorization cannot leave a valid derived session.
    let (raced, raced_token) = db.create_session(account, None, None, None).await.unwrap();
    assert!(db
        .inherit_ssh_credential(account, session.session_id, raced.session_id)
        .await
        .is_err());
    assert!(authenticate_bearer_token(&db, raced_token.expose_secret())
        .await
        .is_err());
}

#[tokio::test]
async fn credential_added_via_api_logs_in_and_revocation_invalidates_session() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let key = key();
    let account = Uuid::new_v4();
    let device = Uuid::new_v4();
    state
        .db
        .add_ssh_key(account, &public(&key), None, true)
        .await
        .unwrap();
    let session = state
        .db
        .finish_ssh_login(
            &proof(
                &key,
                state
                    .db
                    .start_ssh_login(start(&key, device), ORIGIN)
                    .await
                    .unwrap(),
            ),
            ORIGIN,
        )
        .await
        .unwrap();
    let app = create_app(state.clone());
    let second = super_key();
    let (_, record) = call(
        &app,
        "POST",
        "/v1/auth/ssh/keys",
        json!({"public_key": public(&second), "label": "machine two"}),
        Some(session.token.expose_secret()),
    )
    .await;
    let credential: SshCredential = serde_json::from_value(record).unwrap();
    let request = start(&second, Uuid::new_v4());
    let (_, challenge) = call(&app, "POST", "/v1/auth/ssh/start", json!(request), None).await;
    let (status, second_session) = call(
        &app,
        "POST",
        "/v1/auth/ssh/finish",
        json!(proof(&second, serde_json::from_value(challenge).unwrap())),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let second_session: SessionResponse = serde_json::from_value(second_session).unwrap();
    assert_eq!(second_session.account_id, account);
    // Session enrollment must propagate credential association through the live route.
    let (_, derived) = call(&app, "POST", "/v1/auth/device/authorize", json!({"account_id": account, "device_id": Uuid::new_v4(), "device_name": "delegated device"}), Some(second_session.token.expose_secret())).await;
    let derived: zk_protocol::auth::DeviceAuthResponse = serde_json::from_value(derived).unwrap();
    assert_eq!(
        call(
            &app,
            "DELETE",
            &format!("/v1/auth/ssh/keys/{}", credential.credential_id),
            Value::Null,
            Some(session.token.expose_secret())
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    for token in [
        second_session.token.expose_secret(),
        derived.session.token.expose_secret(),
    ] {
        assert_eq!(
            call(
                &app,
                "GET",
                "/v1/auth/session/status",
                Value::Null,
                Some(token)
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
    }
}

#[tokio::test]
async fn unknown_wrong_purpose_and_client_replacement_key_fail_closed() {
    let (db, key, account) = setup().await;
    let challenge = db
        .start_ssh_login(start(&key, Uuid::new_v4()), ORIGIN)
        .await
        .unwrap();
    let request = proof(&key, challenge.clone());
    let mut unknown = request.clone();
    unknown.challenge.challenge_id = Uuid::new_v4();
    assert!(db.finish_ssh_login(&unknown, ORIGIN).await.is_err());
    {
        let conn = db.connection();
        let conn = conn.lock().await;
        // Corrupt purpose through a test-only SQL override; production CHECK disallows this.
        conn.execute_batch("PRAGMA ignore_check_constraints = ON;")
            .unwrap();
        conn.execute(
            "UPDATE ssh_challenges SET purpose = 'other-purpose' WHERE challenge_id = ?1",
            [challenge.challenge_id.to_string()],
        )
        .unwrap();
        conn.execute_batch("PRAGMA ignore_check_constraints = OFF;")
            .unwrap();
    }
    assert!(db.finish_ssh_login(&request, ORIGIN).await.is_err());
    let conn = db.connection();
    let count: i64 = conn
        .lock()
        .await
        .query_row(
            "SELECT COUNT(*) FROM ssh_challenges WHERE challenge_id = ?1",
            [challenge.challenge_id.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    assert!(db.list_sessions(account).await.unwrap().is_empty());
    let mut value = serde_json::to_value(&request).unwrap();
    value["public_key"] = public(&super_key()).into();
    assert!(serde_json::from_value::<SshFinishRequest>(value).is_err());
}

#[tokio::test]
async fn credential_revoke_revokes_pinned_device_even_sessions_from_other_auth() {
    let (db, key, account) = setup().await;
    let device = Uuid::new_v4();
    let challenge = db
        .start_ssh_login(start(&key, device), ORIGIN)
        .await
        .unwrap();
    let ssh_session = db
        .finish_ssh_login(&proof(&key, challenge), ORIGIN)
        .await
        .unwrap();
    let (_, other_token) = db
        .create_session(account, Some(device), Some("other auth".into()), None)
        .await
        .unwrap();
    let credential = db.list_ssh_keys(account).await.unwrap().remove(0);
    db.revoke_ssh_key(account, credential.credential_id)
        .await
        .unwrap();
    assert!(db.is_device_revoked(account, device).await.unwrap());
    for token in [ssh_session.token, other_token] {
        assert!(authenticate_bearer_token(&db, token.expose_secret())
            .await
            .is_err());
    }
    assert!(db
        .create_session(account, Some(device), None, None)
        .await
        .is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_finish_across_independent_sqlite_connections_has_one_winner() {
    let path = std::env::temp_dir().join(format!("zk-ssh-race-{}.sqlite", Uuid::new_v4()));
    let db = ServerDb::open_file(&path).unwrap();
    let other_db = ServerDb::open_file(&path).unwrap();
    let key = key();
    let account = Uuid::new_v4();
    db.add_ssh_key(account, &public(&key), None, true)
        .await
        .unwrap();
    let challenge = db
        .start_ssh_login(start(&key, Uuid::new_v4()), ORIGIN)
        .await
        .unwrap();
    let request = proof(&key, challenge);
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let mut tasks = Vec::new();
    for db in [db.clone(), other_db.clone()] {
        let barrier = barrier.clone();
        let request = request.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            db.finish_ssh_login(&request, ORIGIN).await.is_ok()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        if task.await.unwrap() {
            winners += 1;
        }
    }
    assert_eq!(winners, 1);
    assert_eq!(db.list_sessions(account).await.unwrap().len(), 1);
    drop(db);
    drop(other_db);
    std::fs::remove_file(path).unwrap();
}
