//! Operator provisioning exercises the real binary and configured SQLite migrations.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};
use uuid::Uuid;
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("zk-ssh-provision-{}", Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_zk-server"))
            .env("ZK_SERVER_DB_PATH", self.0.join("accounts.sqlite"))
            .env("ZK_SSH_AUTH_ORIGIN", "http://127.0.0.1:8080")
            .env("ZK_SERVER_HOST", "127.0.0.1")
            .env("ZK_SERVER_PORT", "8080")
            .args(args)
            .output()
            .expect("operator command")
    }
    fn key(&self, name: &str) -> PathBuf {
        let key = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::OsRng,
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let path = self.0.join(name);
        std::fs::write(&path, key.public_key().to_openssh().unwrap()).unwrap();
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}
#[test]
fn operator_creates_account_adds_machine_key_and_never_issues_bearer() {
    let fixture = Fixture::new();
    let first = fixture.key("desktop.pub");
    let output = fixture.run(&[
        "account",
        "create",
        "--ssh-key",
        text(&first),
        "--label",
        "desktop",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Fingerprint: SHA256:"));
    assert!(!stdout.contains("zk_sess_"));
    assert!(!stdout.contains("PRIVATE"));
    let account = stdout
        .lines()
        .find_map(|line| line.strip_prefix("Account: "))
        .unwrap();
    Uuid::parse_str(account).unwrap();
    let duplicate = fixture.run(&["account", "create", "--ssh-key", text(&first)]);
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("already registered"));
    let second = fixture.key("laptop.pub");
    assert!(fixture
        .run(&[
            "account",
            "add-ssh-key",
            account,
            "--ssh-key",
            text(&second),
            "--label",
            "laptop"
        ])
        .status
        .success());
    let unknown = fixture.key("unknown.pub");
    let result = fixture.run(&[
        "account",
        "add-ssh-key",
        &Uuid::new_v4().to_string(),
        "--ssh-key",
        text(&unknown),
    ]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("Unknown or inactive account"));
    let conn = rusqlite::Connection::open(fixture.0.join("accounts.sqlite")).unwrap();
    for (table, expected) in [
        ("accounts", 1),
        ("ssh_credentials", 2),
        ("sessions", 0),
        ("vaults", 0),
    ] {
        let n: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, expected, "{table}");
    }
    let version: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(version, 10);
}
#[test]
fn malformed_private_non_public_and_oversized_inputs_fail_without_reflection() {
    let fixture = Fixture::new();
    let no_extension = fixture.key("id_ed25519");
    assert!(!fixture
        .run(&["account", "create", "--ssh-key", text(&no_extension)])
        .status
        .success());
    for (name, content) in [
        (
            "private.pub",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nprivate-sentinel\n".to_string(),
        ),
        (
            "malformed.pub",
            "ssh-ed25519 invalid-key-sentinel".to_string(),
        ),
        ("oversized.pub", "oversized-sentinel".repeat(500)),
    ] {
        let path = fixture.0.join(name);
        std::fs::write(&path, content).unwrap();
        let result = fixture.run(&["account", "create", "--ssh-key", text(&path)]);
        assert!(!result.status.success());
        let output = format!(
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(output.contains("PUBLIC .pub file"));
        assert!(!output.contains("sentinel"));
    }
}
