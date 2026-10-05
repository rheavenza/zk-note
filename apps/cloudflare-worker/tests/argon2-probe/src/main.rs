use std::time::Instant;
use zk_108_argon2_probe::{hash, verify};
fn main() -> Result<(), String> {
    for (memory_kib, iterations) in [(47104, 1), (19456, 2), (12288, 3), (9216, 4), (7168, 5)] {
        for sample in 0..6 {
            let start = Instant::now();
            let encoded = hash(memory_kib, iterations)?;
            let hash_ms = start.elapsed().as_secs_f64() * 1000.0;
            let start = Instant::now();
            if !verify(&encoded, true) {
                return Err("verification failed".into());
            }
            let verify_ms = start.elapsed().as_secs_f64() * 1000.0;
            println!(
                "{}",
                serde_json::json!({"memory_kib":memory_kib,"iterations":iterations,"parallelism":1,"sample":sample,"hash_ms":hash_ms,"verify_ms":verify_ms})
            );
        }
    }
    Ok(())
}
