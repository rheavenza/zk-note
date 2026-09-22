use super::*;
pub async fn authenticate(req: &Request, db: &D1Database) -> ApiResult<SessionStatusResponse> {
    let header = req
        .headers()
        .get("authorization")?
        .ok_or(ApiError(401, "AUTH_REQUIRED"))?;
    let token = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))
        .ok_or(ApiError(401, "AUTH_REQUIRED"))?
        .trim();
    let result=rows(db,"SELECT s.account_id,s.session_id,s.device_id,s.revoked_at,(s.expires_at IS NOT NULL AND s.expires_at<=CURRENT_TIMESTAMP) AS expired,d.revoked_at AS device_revoked FROM sessions s LEFT JOIN devices d ON d.account_id=s.account_id AND d.device_id=s.device_id WHERE s.token_hash=?1",&[json!(digest(token.as_bytes()))]).await?;
    let row = result.first().ok_or(ApiError(401, "AUTH_REQUIRED"))?;
    if !row["revoked_at"].is_null() {
        return Err(ApiError(401, "AUTH_REVOKED"));
    }
    if num(row, "expired")? != 0 {
        return Err(ApiError(401, "AUTH_EXPIRED"));
    }
    if !row["device_revoked"].is_null() {
        return Err(ApiError(401, "DEVICE_REVOKED"));
    }
    let account_id =
        Uuid::parse_str(text(row, "account_id")?).map_err(|_| ApiError(500, "SERVER_FAILURE"))?;
    let device_id = row["device_id"]
        .as_str()
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|_| ApiError(500, "SERVER_FAILURE"))?;
    if let Some(target) = req.headers().get("x-account-id")? {
        if Uuid::parse_str(&target).is_ok_and(|v| v != account_id) {
            return Err(ApiError(403, "AUTH_FORBIDDEN"));
        }
    }
    if let (Some(device), Some(target)) = (device_id, req.headers().get("x-device-id")?) {
        if Uuid::parse_str(&target).is_ok_and(|v| v != device) {
            return Err(ApiError(403, "AUTH_FORBIDDEN"));
        }
    }
    Ok(SessionStatusResponse {
        account_id,
        device_id,
        session_id: Some(
            Uuid::parse_str(text(row, "session_id")?)
                .map_err(|_| ApiError(500, "SERVER_FAILURE"))?,
        ),
        status: "active".into(),
    })
}
pub async fn session(
    db: &D1Database,
    account: Uuid,
    device: Option<Uuid>,
    name: Option<String>,
) -> ApiResult<SessionResponse> {
    let session_id = Uuid::new_v4();
    let token = AuthToken::new(format!(
        "zk_sess_{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    ));
    let result=batch(db,vec![
        ("INSERT INTO accounts(id) VALUES(?1) ON CONFLICT DO NOTHING",vec![json!(account)]),
        ("INSERT INTO devices(account_id,device_id,display_name) SELECT ?1,?2,?3 WHERE ?2 IS NOT NULL ON CONFLICT(account_id,device_id) DO UPDATE SET display_name=coalesce(excluded.display_name,devices.display_name),last_seen=CURRENT_TIMESTAMP WHERE devices.revoked_at IS NULL",vec![json!(account),json!(device),json!(name)]),
        ("INSERT INTO sessions(session_id,account_id,device_id,token_hash,expires_at) SELECT ?1,?2,?3,?4,datetime('now','+30 days') WHERE NOT EXISTS(SELECT 1 FROM devices WHERE account_id=?2 AND device_id=?3 AND revoked_at IS NOT NULL) RETURNING expires_at",vec![json!(session_id),json!(account),json!(device),json!(digest(token.expose_secret().as_bytes()))])
    ]).await?;
    let rows = result[2].results::<Value>()?;
    let row = rows.first().ok_or(ApiError(403, "DEVICE_REVOKED"))?;
    Ok(SessionResponse {
        token,
        session_id,
        account_id: account,
        device_id: device,
        expires_at: Some(text(row, "expires_at")?.into()),
    })
}
pub async fn devices(db: &D1Database, account: &str) -> ApiResult<Response> {
    let result = rows(
        db,
        "SELECT * FROM devices WHERE account_id=?1 ORDER BY created_at,device_id",
        &[json!(account)],
    )
    .await?;
    let devices = result
        .into_iter()
        .map(|mut row| {
            row["is_revoked"] = json!(!row["revoked_at"].is_null());
            serde_json::from_value::<DeviceInfo>(row).map_err(ApiError::from)
        })
        .collect::<ApiResult<Vec<_>>>()?;
    response(200, &DeviceListResponse { devices })
}
pub async fn revoke_device(db: &D1Database, account: &str, device: &str) -> ApiResult<Response> {
    let _result=batch(db,vec![
        ("UPDATE devices SET revoked_at=CURRENT_TIMESTAMP WHERE account_id=?1 AND device_id=?2 AND revoked_at IS NULL RETURNING device_id",vec![json!(account),json!(device)]),
        ("UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE account_id=?1 AND device_id=?2 AND revoked_at IS NULL",vec![json!(account),json!(device)])
    ]).await?;
    response(
        200,
        &RevokeDeviceResponse {
            device_id: Uuid::parse_str(device).map_err(|_| invalid("INVALID_REQUEST"))?,
            revoked: true,
            message: "Device and associated sessions revoked successfully".into(),
        },
    )
}
pub async fn webauthn(
    req: &mut Request,
    env: &Env,
    db: &D1Database,
    path: &str,
) -> ApiResult<Response> {
    let rp = variable(env, "WEBAUTHN_RP_ID", "localhost");
    let origin = variable(env, "WEBAUTHN_ORIGIN", "http://localhost:5173");
    if path.ends_with("/start") {
        let registration = path == "/v1/auth/webauthn/register/start";
        if !registration && path != "/v1/auth/webauthn/login/start" {
            return Err(ApiError(404, "OBJECT_NOT_FOUND"));
        }
        let (account, username, display) = if registration {
            let request: WebAuthnRegisterStartRequest = parse(req, "INVALID_REQUEST").await?;
            if let Some(account) = request.account_id {
                if authenticate(req, db).await?.account_id != account {
                    return Err(ApiError(403, "AUTH_FORBIDDEN"));
                }
            }
            (
                Some(request.account_id.unwrap_or_else(Uuid::new_v4)),
                request.username,
                request.display_name,
            )
        } else {
            let request: WebAuthnLoginStartRequest = parse(req, "INVALID_REQUEST").await?;
            (request.account_id, None, None)
        };
        let challenge_id = Uuid::new_v4();
        let mut challenge = Uuid::new_v4().as_bytes().to_vec();
        challenge.extend(Uuid::new_v4().as_bytes());
        let challenge_b64 = Base64UrlUnpadded::encode_string(&challenge);
        run(db,"INSERT INTO webauthn_challenges(challenge_id,challenge,account_id,purpose,expires_at) VALUES(?1,?2,?3,?4,datetime('now','+5 minutes'))",&[json!(challenge_id),json!(challenge_b64),json!(account),json!(if registration{"register"}else{"login"})]).await?;
        if registration {
            let account = account.ok_or(ApiError(500, "SERVER_FAILURE"))?;
            let name = username.unwrap_or_else(|| format!("user_{}", &account.to_string()[..8]));
            response(
                200,
                &WebAuthnRegisterStartResponse {
                    challenge_id,
                    challenge_b64,
                    rp: WebAuthnRpInfo {
                        name: "Zero-Knowledge Notes".into(),
                        id: rp,
                    },
                    user: WebAuthnUserInfo {
                        id: account.to_string(),
                        display_name: display.unwrap_or_else(|| name.clone()),
                        name,
                    },
                },
            )
        } else {
            response(
                200,
                &WebAuthnLoginStartResponse {
                    challenge_id,
                    challenge_b64,
                    rp_id: rp,
                },
            )
        }
    } else if path == "/v1/auth/webauthn/register/finish" {
        let request: WebAuthnRegisterFinishRequest = parse(req, "CRYPTO_AUTH_FAILED").await?;
        let challenge = consume(db, request.challenge_id, "register").await?;
        let challenge_bytes = zk_server_auth::decode(text(&challenge, "challenge")?)
            .map_err(|_| invalid("WEBAUTHN_VERIFICATION_FAILED"))?;
        let key = zk_server_auth::register(&request, &challenge_bytes, &rp, &origin)
            .map_err(|_| invalid("WEBAUTHN_VERIFICATION_FAILED"))?;
        let account = Uuid::parse_str(text(&challenge, "account_id")?)
            .map_err(|_| ApiError(500, "SERVER_FAILURE"))?;
        let credential = Base64UrlUnpadded::encode_string(
            &zk_server_auth::decode(&request.credential_id)
                .map_err(|_| invalid("INVALID_CREDENTIAL_ID"))?,
        );
        let result=batch(db,vec![
            ("INSERT INTO accounts(id) VALUES(?1) ON CONFLICT DO NOTHING",vec![json!(account)]),
            ("INSERT INTO webauthn_credentials(credential_id,account_id,public_key,device_id,display_name) VALUES(?1,?2,?3,?4,?5) ON CONFLICT DO NOTHING RETURNING credential_id",vec![json!(credential),json!(account),json!(Base64UrlUnpadded::encode_string(&key)),json!(request.device_id),json!(request.display_name)])
        ]).await?;
        if result[1].results::<Value>()?.is_empty() {
            return Err(ApiError(409, "WEBAUTHN_CREDENTIAL_EXISTS"));
        }
        response(
            200,
            &WebAuthnRegisterFinishResponse {
                session: session(db, account, request.device_id, request.display_name).await?,
            },
        )
    } else if path == "/v1/auth/webauthn/login/finish" {
        let request: WebAuthnLoginFinishRequest = parse(req, "CRYPTO_AUTH_FAILED").await?;
        let challenge = consume(db, request.challenge_id, "login").await?;
        let result=rows(db,"SELECT c.*,d.revoked_at FROM webauthn_credentials c LEFT JOIN devices d ON c.account_id=d.account_id AND c.device_id=d.device_id WHERE c.credential_id=?1",&[json!(request.credential_id)]).await?;
        let credential = result
            .first()
            .ok_or(ApiError(401, "WEBAUTHN_CREDENTIAL_NOT_FOUND"))?;
        if !credential["revoked_at"].is_null() {
            return Err(ApiError(401, "DEVICE_REVOKED"));
        }
        if !challenge["account_id"].is_null() && challenge["account_id"] != credential["account_id"]
        {
            return Err(ApiError(401, "AUTH_REQUIRED"));
        }
        let decode = |s: &str| {
            zk_server_auth::decode(s).map_err(|_| invalid("WEBAUTHN_VERIFICATION_FAILED"))
        };
        let old = num(credential, "sign_count")?;
        let count = zk_server_auth::login(
            &request,
            &decode(text(&challenge, "challenge")?)?,
            &rp,
            &origin,
            &decode(text(credential, "public_key")?)?,
            old,
        )
        .map_err(|_| invalid("WEBAUTHN_VERIFICATION_FAILED"))?;
        let updated=rows(db,"UPDATE webauthn_credentials SET sign_count=?1 WHERE credential_id=?2 AND sign_count=?3 RETURNING account_id",&[json!(count),json!(request.credential_id),json!(old)]).await?;
        if updated.is_empty() {
            return Err(invalid("WEBAUTHN_VERIFICATION_FAILED"));
        }
        let account = Uuid::parse_str(text(credential, "account_id")?)
            .map_err(|_| ApiError(500, "SERVER_FAILURE"))?;
        let device = credential["device_id"]
            .as_str()
            .map(Uuid::parse_str)
            .transpose()
            .map_err(|_| ApiError(500, "SERVER_FAILURE"))?;
        response(
            200,
            &WebAuthnLoginFinishResponse {
                session: session(
                    db,
                    account,
                    device.or(request.device_id),
                    credential["display_name"].as_str().map(str::to_string),
                )
                .await?,
            },
        )
    } else {
        Err(ApiError(404, "OBJECT_NOT_FOUND"))
    }
}
async fn consume(db: &D1Database, id: Uuid, purpose: &str) -> ApiResult<Value> {
    let mut result=rows(db,"DELETE FROM webauthn_challenges WHERE challenge_id=?1 AND purpose=?2 RETURNING challenge,account_id,(expires_at<=CURRENT_TIMESTAMP) AS expired",&[json!(id),json!(purpose)]).await?;
    let record = result
        .pop()
        .ok_or(invalid("WEBAUTHN_CHALLENGE_NOT_FOUND"))?;
    if num(&record, "expired")? != 0 {
        return Err(invalid("WEBAUTHN_CHALLENGE_EXPIRED"));
    }
    Ok(record)
}
