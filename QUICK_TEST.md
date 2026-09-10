# 5-Minute Human Smoke Test (`QUICK_TEST.md`)

> **Objective:** Quick sanity check of the core system abstraction.  
> Builds the client and server, verifies note encryption & decryption, checks zero plaintext on disk, and confirms the server starts with security headers.  
> **Estimated Time:** 3 to 5 minutes.

---

### Step 1: Build Client & Server (1 command)

```bash
cargo build --bin zk-note --bin zk-server
```

---

### Step 2: Test Encrypted Note Lifecycle in CLI

Set an isolated test folder so your existing notes aren't touched:

```bash
export ZK_NOTE_DIR="/tmp/quick-test"
rm -rf "$ZK_NOTE_DIR"
```

#### 2.1 Initialize Vault
```bash
./target/debug/zk-note init --passphrase "mypass123" --test-kdf
```
*Expected:* Displays "VAULT CREATED SUCCESSFULLY" and outputs your recovery key.

#### 2.2 Create an Encrypted Note
```bash
./target/debug/zk-note new -t "Secret Blueprint" -b "This body is encrypted with ChaCha20-Poly1305." -g "classified"
```
*Expected:* Outputs created note UUID.

#### 2.3 List & Read Note
```bash
./target/debug/zk-note list
./target/debug/zk-note show $(./target/debug/zk-note list --json | jq -r '.[0].id')
```
*Expected:* Prints the decrypted title, tags, revision (`1`), and body.

#### 2.4 Verify Zero Plaintext on Disk (Core Requirement)
```bash
grep -i "Secret Blueprint" "$ZK_NOTE_DIR/notes.db" || echo "PASS: Zero plaintext in database!"
```
*Expected:* Outputs `PASS: Zero plaintext in database!`. (Only opaque base64 ciphertext exists in SQLite).

---

### Step 3: Test Sync Server & Security Headers

#### 3.1 Start Server in Background
```bash
PORT=8080 cargo run -p zk-server &
SERVER_PID=$!
sleep 1
```

#### 3.2 Verify Health & Security Headers
```bash
curl -i http://localhost:8080/health
```
*Expected:* 
- HTTP `200 OK` with `{"status":"ok",...}`
- Strict security headers present: `content-security-policy`, `x-frame-options: DENY`, `x-content-type-options: nosniff`.

#### 3.3 Verify Auth Protection
```bash
curl -i http://localhost:8080/v1/sync/changes
```
*Expected:* HTTP `401 Unauthorized` with `{"code":"AUTH_REQUIRED",...}`.

#### 3.4 Stop Server
```bash
kill $SERVER_PID
```

---

### Step 4: Done & Clean Up

```bash
rm -rf "$ZK_NOTE_DIR"
echo "All quick smoke tests passed!"
```
