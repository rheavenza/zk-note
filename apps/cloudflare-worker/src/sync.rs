use super::*;
pub async fn push(req: &mut Request, db: &D1Database, account: &str) -> ApiResult<Response> {
    let request: PushRequest = parse(req, "INVALID_ENVELOPE").await?;
    let object = uuid(&request.object_id).map_err(|_| invalid("INVALID_ENVELOPE"))?;
    let mutation = uuid(&request.mutation_id).map_err(|_| invalid("INVALID_ENVELOPE"))?;
    if request.envelope.envelope_version != 1 {
        return Err(invalid("CRYPTO_UNSUPPORTED_VERSION"));
    }
    if request.envelope.object_id != request.object_id
        || request.expected_revision >= 9_007_199_254_740_991
    {
        return Err(invalid("INVALID_ENVELOPE"));
    }
    for v in [
        &request.envelope.wrapped_key.nonce,
        &request.envelope.wrapped_key.ciphertext,
        &request.envelope.payload.nonce,
        &request.envelope.payload.ciphertext,
    ] {
        Base64::decode_vec(v).map_err(|_| invalid("INVALID_ENVELOPE"))?;
    }
    let attempt = id();
    let result=batch(db,vec![
        ("INSERT INTO mutation_attempts(id,account_id,mutation_id,object_id,wire_object_id,expected_revision,object_kind,envelope,is_deleted,request_hash) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",vec![json!(attempt),json!(account),json!(mutation),json!(object),json!(request.object_id),json!(request.expected_revision),json!(request.object_kind),json!(encode(&request.envelope)?),json!(request.is_deleted),json!(digest(encode(&request)?.as_bytes()))]),
        ("SELECT status,response FROM mutation_attempts WHERE id=?1",vec![json!(attempt)]),
        ("DELETE FROM mutation_attempts WHERE id=?1",vec![json!(attempt)])
    ]).await?;
    let rows = result[1].results::<Value>()?;
    let row = rows.first().ok_or(ApiError(500, "SERVER_FAILURE"))?;
    let status = num(row, "status")? as u16;
    let value: Value = serde_json::from_str(text(row, "response")?)?;
    if status == 200 {
        let typed: PushResponse = serde_json::from_value(value)?;
        response(status, &typed)
    } else if value.get("error").is_some() {
        let typed: ConflictResponse = serde_json::from_value(value)?;
        response(status, &typed)
    } else {
        response(status, &value)
    }
}
pub async fn pull(req: &Request, db: &D1Database, account: &str) -> ApiResult<Response> {
    let mut after = 0u64;
    let mut limit = 50u32;
    if let Some(query) = req.url()?.query() {
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            match key {
                "after" | "since" | "cursor" => {
                    after = value.parse().map_err(|_| invalid("SYNC_CURSOR_INVALID"))?
                }
                "limit" => {
                    limit = value.parse().map_err(|_| invalid("SYNC_CURSOR_INVALID"))?;
                    limit = if limit == 0 { 50 } else { limit.min(500) };
                }
                _ => {}
            }
        }
    }
    if after > 9_007_199_254_740_991 {
        return Err(invalid("SYNC_CURSOR_INVALID"));
    }
    let mut result=rows(db,"SELECT object_id,revision,server_seq,object_kind,envelope,is_deleted FROM encrypted_objects WHERE account_id=?1 AND server_seq>?2 ORDER BY server_seq LIMIT ?3",&[json!(account),json!(after),json!(limit+1)]).await?;
    let has_more = result.len() > limit as usize;
    result.truncate(limit as usize);
    let changes = result
        .iter()
        .map(|row| {
            Ok(ObjectChange {
                object_id: text(row, "object_id")?.into(),
                revision: num(row, "revision")?,
                server_seq: num(row, "server_seq")?,
                object_kind: num(row, "object_kind")? as u16,
                is_deleted: num(row, "is_deleted")? != 0,
                envelope: serde_json::from_str(text(row, "envelope")?)?,
            })
        })
        .collect::<ApiResult<Vec<_>>>()?;
    response(
        200,
        &PullChangesResponse {
            next_cursor: changes.last().map(|c| c.server_seq).unwrap_or(after),
            changes,
            has_more,
        },
    )
}
