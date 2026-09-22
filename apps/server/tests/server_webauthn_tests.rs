//! Signed WebAuthn fixtures exercise real verification and account enrollment boundaries.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use ciborium::Value as Cbor;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;
use zk_server::{create_app, AppState, ServerConfig};
mod common;

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}
fn cbor(value: Cbor) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(&value, &mut out).unwrap();
    out
}
fn n(n: i64) -> Cbor {
    Cbor::Integer(n.into())
}
async fn post(
    app: &axum::Router,
    path: &str,
    body: Value,
    auth: Option<&str>,
) -> (StatusCode, Value) {
    let mut req = Request::post(path).header("content-type", "application/json");
    if let Some(auth) = auth {
        req = req.header("authorization", auth);
    }
    let response = app
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 100000).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}
fn registration(start: &Value, key: &SigningKey, credential: &[u8]) -> Value {
    let point = key.verifying_key().to_encoded_point(false);
    let mut data = Sha256::digest(b"localhost").to_vec();
    data.push(0x45);
    data.extend([0; 4]);
    data.extend([0; 16]);
    data.extend((credential.len() as u16).to_be_bytes());
    data.extend(credential);
    data.extend(cbor(Cbor::Map(vec![
        (n(1), n(2)),
        (n(3), n(-7)),
        (n(-1), n(1)),
        (n(-2), Cbor::Bytes(point.x().unwrap().to_vec())),
        (n(-3), Cbor::Bytes(point.y().unwrap().to_vec())),
    ])));
    let att = cbor(Cbor::Map(vec![
        (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
        (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
        (Cbor::Text("authData".into()), Cbor::Bytes(data)),
    ]));
    json!({"challenge_id":start["challenge_id"],"credential_id":b64(credential),"public_key":"ignored", "attestation_object":b64(&att),"client_data_json":b64(json!({"type":"webauthn.create","challenge":start["challenge_b64"],"origin":"http://localhost:5173","crossOrigin":false}).to_string().as_bytes())})
}
fn assertion(
    start: &Value,
    key: &SigningKey,
    credential: &[u8],
    count: u32,
    origin: &str,
) -> Value {
    let client=json!({"type":"webauthn.get","challenge":start["challenge_b64"],"origin":origin,"crossOrigin":false}).to_string();
    let mut data = Sha256::digest(b"localhost").to_vec();
    data.push(5);
    data.extend(count.to_be_bytes());
    let mut signed = data.clone();
    signed.extend(Sha256::digest(client.as_bytes()));
    let sig: Signature = key.sign(&signed);
    json!({"challenge_id":start["challenge_id"],"credential_id":b64(credential),"signature":b64(sig.to_der().as_bytes()),"authenticator_data":b64(&data),"client_data_json":b64(client.as_bytes())})
}
#[tokio::test]
async fn signed_registration_login_replay_and_revocation() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());
    let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let credential = b"test-credential";
    let (status, start) = post(&app, "/v1/auth/webauthn/register/start", json!({}), None).await;
    assert_eq!(status, 200);
    let request = registration(&start, &key, credential);
    let (status, registered) = post(
        &app,
        "/v1/auth/webauthn/register/finish",
        request.clone(),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(registered["session"]["account_id"], start["user"]["id"]);
    assert_eq!(
        post(&app, "/v1/auth/webauthn/register/finish", request, None)
            .await
            .0,
        400
    );
    for (count, origin, expected) in [
        (1, "http://localhost:5173", 200),
        (1, "http://localhost:5173", 400),
        (2, "https://evil.example", 400),
    ] {
        let (_, start) = post(&app, "/v1/auth/webauthn/login/start", json!({}), None).await;
        let request = assertion(&start, &key, credential, count, origin);
        let (status, result) = post(
            &app,
            "/v1/auth/webauthn/login/finish",
            request.clone(),
            None,
        )
        .await;
        assert_eq!(status, expected, "{result}");
        assert_eq!(
            post(&app, "/v1/auth/webauthn/login/finish", request, None)
                .await
                .0,
            400
        );
    }
    let (_, start) = post(&app, "/v1/auth/webauthn/login/start", json!({}), None).await;
    let bad_key = SigningKey::from_bytes((&[8u8; 32]).into()).unwrap();
    assert_eq!(
        post(
            &app,
            "/v1/auth/webauthn/login/finish",
            assertion(&start, &bad_key, credential, 3, "http://localhost:5173"),
            None
        )
        .await
        .0,
        400
    );
    let auth = format!(
        "Bearer {}",
        registered["session"]["token"].as_str().unwrap()
    );
    assert_eq!(
        post(&app, "/v1/auth/session/revoke", json!({}), Some(&auth))
            .await
            .0,
        200
    );
    assert_eq!(
        post(&app, "/v1/auth/session/revoke", json!({}), Some(&auth))
            .await
            .0,
        401
    );
}
#[tokio::test]
async fn enrollment_requires_account_ownership_and_proofs() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());
    let account = Uuid::new_v4();
    let auth = common::bearer(&state, account).await;
    let other = common::bearer(&state, Uuid::new_v4()).await;
    for path in [
        "/v1/auth/webauthn/register/start",
        "/v1/auth/device/authorize",
        "/v1/auth/cli/login",
    ] {
        let body = json!({"account_id":account,"device_id":Uuid::new_v4()});
        assert_eq!(post(&app, path, body.clone(), None).await.0, 401);
        assert_eq!(
            post(&app, path, body.clone(), Some(&format!("Bearer {account}")))
                .await
                .0,
            401
        );
        assert_eq!(post(&app, path, body.clone(), Some(&other)).await.0, 403);
        assert_eq!(post(&app, path, body, Some(&auth)).await.0, 200);
    }
    let (_, start) = post(&app, "/v1/auth/webauthn/register/start", json!({}), None).await;
    let bad = json!({"challenge_id":start["challenge_id"],"credential_id":b64(b"cred"),"public_key":b64(b"not-a-key")});
    assert_eq!(
        post(&app, "/v1/auth/webauthn/register/finish", bad, None)
            .await
            .0,
        400
    );
    for path in [
        "/v1/auth/webauthn/register/finish",
        "/v1/auth/webauthn/login/finish",
    ] {
        assert_eq!(
            post(&app, path, json!({"passphrase":"never-echo-this"}), None)
                .await
                .0,
            400
        );
    }
}
