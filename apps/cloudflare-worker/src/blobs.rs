use super::*;
pub async fn route(
    req: &mut Request,
    env: &Env,
    db: &D1Database,
    account: &str,
    blob: &str,
) -> ApiResult<Response> {
    if blob.is_empty()
        || blob.len() > 128
        || !blob
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err(invalid("INVALID_BLOB_ID"));
    }
    let bucket = env.bucket("BLOBS")?;
    match req.method() {
        Method::Get | Method::Head => {
            let result = rows(
                db,
                "SELECT storage_key,size FROM blobs WHERE account_id=?1 AND blob_id=?2",
                &[json!(account), json!(blob)],
            )
            .await?;
            let row = result.first().ok_or(ApiError(404, "BLOB_NOT_FOUND"))?;
            let object = bucket
                .get(text(row, "storage_key")?)
                .execute()
                .await?
                .ok_or(ApiError(503, "SERVER_FAILURE"))?;
            let mut result = if req.method() == Method::Head {
                Response::empty()?
            } else {
                Response::from_stream(
                    object
                        .body()
                        .ok_or(ApiError(503, "SERVER_FAILURE"))?
                        .stream()?,
                )?
            };
            result
                .headers_mut()
                .set("content-type", "application/octet-stream")?;
            result
                .headers_mut()
                .set("content-length", &num(row, "size")?.to_string())?;
            Ok(result)
        }
        Method::Put => {
            for header in [
                "x-filename",
                "x-file-name",
                "x-mime-type",
                "x-mime",
                "x-content-type-original",
                "x-note-id",
                "x-note-title",
                "x-tag",
            ] {
                if req.headers().has(header)? {
                    return Err(invalid("PLAINTEXT_METADATA_FORBIDDEN"));
                }
            }
            let maximum = variable(env, "MAX_BLOB_SIZE", "1048576")
                .parse::<usize>()
                .map_err(|_| ApiError(500, "SERVER_FAILURE"))?
                .min(8 * 1024 * 1024);
            let quota = variable(env, "ACCOUNT_BLOB_QUOTA", "1073741824")
                .parse::<u64>()
                .map_err(|_| ApiError(500, "SERVER_FAILURE"))?;
            let bytes = body(req, maximum).await?;
            let size = bytes.len();
            // Every upload gets an immutable key. Never overwrite a published object's bytes.
            let key = format!("{account}/{blob}/{}", id());
            let reserved=rows(db,"INSERT INTO blob_uploads(storage_key,account_id,blob_id,size,expires_at) SELECT ?1,?2,?3,?4,datetime('now','+1 hour') FROM accounts WHERE id=?2 AND blob_bytes+reserved_bytes+?4<=?5 RETURNING storage_key",&[json!(key),json!(account),json!(blob),json!(size),json!(quota)]).await?;
            if reserved.is_empty() {
                return Err(ApiError(413, "QUOTA_EXCEEDED"));
            }
            if !matches!(bucket.put(&key, bytes).execute().await, Ok(Some(_))) {
                // Retain a retryable cleanup tombstone even if R2 reports failure after accepting bytes.
                let _ = cancel(db, &key).await;
                return Err(ApiError(503, "SERVER_FAILURE"));
            }
            let published=batch(db,vec![
                ("INSERT INTO blobs(account_id,blob_id,storage_key,size) SELECT account_id,blob_id,storage_key,size FROM blob_uploads WHERE storage_key=?1 AND expires_at>CURRENT_TIMESTAMP ON CONFLICT(account_id,blob_id) DO UPDATE SET storage_key=excluded.storage_key,size=excluded.size RETURNING storage_key",vec![json!(key)]),
                ("DELETE FROM blob_uploads WHERE storage_key=?1 AND EXISTS(SELECT 1 FROM blobs WHERE storage_key=?1)",vec![json!(key)])
            ]).await;
            match published {
                Ok(results) if !results[0].results::<Value>()?.is_empty() => {
                    response(201, &json!({"blob_id":blob,"size":size}))
                }
                // Do not delete R2 here: an ambiguous D1 response may conceal a committed pointer.
                _ => Err(ApiError(503, "SERVER_FAILURE")),
            }
        }
        Method::Delete => {
            let result = rows(
                db,
                "DELETE FROM blobs WHERE account_id=?1 AND blob_id=?2 RETURNING storage_key",
                &[json!(account), json!(blob)],
            )
            .await?;
            if result.is_empty() {
                return Err(ApiError(404, "BLOB_NOT_FOUND"));
            }
            // D1 trigger releases quota and records durable R2 cleanup atomically.
            response(200, &json!({"blob_id":blob,"deleted":true}))
        }
        _ => Err(ApiError(405, "METHOD_NOT_ALLOWED")),
    }
}
async fn cancel(db: &D1Database, key: &str) -> ApiResult<()> {
    batch(db,vec![
        ("INSERT INTO blob_garbage(storage_key,retry_forever) SELECT storage_key,1 FROM blob_uploads WHERE storage_key=?1 ON CONFLICT DO NOTHING",vec![json!(key)]),
        ("DELETE FROM blob_uploads WHERE storage_key=?1",vec![json!(key)])
    ]).await?;
    Ok(())
}
pub async fn reconcile(env: &Env) -> ApiResult<()> {
    let db = env.d1("DB")?;
    let bucket = env.bucket("BLOBS")?;
    // Bounded indexed work stays below the Workers Free D1 query limit.
    batch(&db,vec![
        ("INSERT INTO blob_garbage(storage_key,retry_forever) SELECT storage_key,1 FROM blob_uploads WHERE expires_at<=CURRENT_TIMESTAMP ORDER BY expires_at LIMIT 8 ON CONFLICT DO NOTHING",vec![]),
        ("DELETE FROM blob_uploads WHERE storage_key IN (SELECT storage_key FROM blob_uploads WHERE expires_at<=CURRENT_TIMESTAMP ORDER BY expires_at LIMIT 8)",vec![]),
        ("DELETE FROM webauthn_challenges WHERE challenge_id IN (SELECT challenge_id FROM webauthn_challenges WHERE expires_at<=CURRENT_TIMESTAMP ORDER BY expires_at LIMIT 100)",vec![])
    ]).await?;
    let garbage=rows(&db,"SELECT storage_key,retry_forever FROM blob_garbage WHERE next_attempt<=CURRENT_TIMESTAMP ORDER BY next_attempt LIMIT 8",&[]).await?;
    for row in garbage {
        let key = text(&row, "storage_key")?;
        // Immutable keys and transactional publication ensure garbage cannot become live.
        bucket.delete(key).await?;
        if num(&row, "retry_forever")? == 1 {
            run(&db,"UPDATE blob_garbage SET next_attempt=datetime('now','+1 day') WHERE storage_key=?1",&[json!(key)]).await?;
        } else {
            run(
                &db,
                "DELETE FROM blob_garbage WHERE storage_key=?1",
                &[json!(key)],
            )
            .await?;
        }
    }
    Ok(())
}
