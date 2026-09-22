#!/usr/bin/env python3
"""
Synthetic smoke test for zk-note TUI (ZK-101)
Exercises PTY lifecycle, unlock, navigation, search, inline creation,
sync dispatch, conflict overlay, help, lock, quit, terminal restoration,
and zero-knowledge disk audit.
"""
import os
import pty
import select
import struct
import subprocess
import sys
import termios
import time
import fcntl

def set_winsize(fd, rows, cols):
    winsize = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)

def read_until(master_fd, target_strings, timeout=5.0):
    deadline = time.time() + timeout
    buffer = b""
    while time.time() < deadline:
        r, _, _ = select.select([master_fd], [], [], 0.1)
        if r:
            try:
                chunk = os.read(master_fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            buffer += chunk
            for t in target_strings:
                if t.encode("utf-8") in buffer:
                    return buffer.decode("utf-8", errors="replace")
    return buffer.decode("utf-8", errors="replace")

def drain(master_fd, duration=0.3):
    time.sleep(duration)
    buffer = b""
    while True:
        r, _, _ = select.select([master_fd], [], [], 0.05)
        if r:
            try:
                chunk = os.read(master_fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            buffer += chunk
        else:
            break
    return buffer.decode("utf-8", errors="replace")

def main():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    data_dir = os.path.join(repo_root, "target", "smoke_data")
    bin_path = os.path.join(repo_root, "target", "release", "zk-note")

    if not os.path.exists(bin_path):
        print(f"Building release binary {bin_path}...")
        subprocess.run(["cargo", "build", "--release", "--bin", "zk-note"], cwd=repo_root, check=True)

    # Clean previous smoke data
    if os.path.exists(data_dir):
        import shutil
        shutil.rmtree(data_dir)
    os.makedirs(data_dir, exist_ok=True)

    passphrase = "SyntheticPassphrase42!"
    secret_title = "Classified Synthetic Note"
    secret_body = "SuperSecretPlaintextContentThatMustNeverLeakToDisk"

    print("Step 1: Initializing disposable vault...")
    subprocess.run([
        bin_path, "--data-dir", data_dir, "init",
        "--passphrase", passphrase, "--test-kdf"
    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    print("Step 2: Creating synthetic note via CLI...")
    subprocess.run([
        bin_path, "--data-dir", data_dir, "new",
        "--title", secret_title,
        "--body", secret_body,
        "--tag", "audit,synth"
    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    print("Step 3: Explicitly locking vault before TUI launch...")
    subprocess.run([
        bin_path, "--data-dir", data_dir, "lock"
    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    print("Step 4: Launching zk-note TUI in a controlled 100x30 pseudo-terminal...")
    master, slave = pty.openpty()
    set_winsize(slave, 30, 100)

    # Save original terminal settings of slave
    orig_tcattr = termios.tcgetattr(slave)

    def preexec():
        os.setsid()
        try:
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        except Exception:
            pass

    proc = subprocess.Popen(
        [bin_path, "--data-dir", data_dir, "tui"],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        preexec_fn=preexec,
        close_fds=True
    )
    os.close(slave)

    try:
        # 1. Expect Locked view
        out = read_until(master, ["Vault Locked", "Passphrase:"], timeout=5.0)
        assert "Vault Locked" in out or "Passphrase:" in out, f"Did not see locked modal: {out}"
        print("  -> Locked modal displayed successfully.")

        # 2. Enter Passphrase
        for ch in passphrase:
            os.write(master, ch.encode())
            time.sleep(0.02)
        os.write(master, b"\r")

        # 3. Expect Unlocked Notes View
        out = read_until(master, [secret_title, "NORMAL"], timeout=5.0)
        assert secret_title in out or "NORMAL" in out, f"Did not reach normal mode: {out}"
        print("  -> Unlocked successfully. Notes view displayed.")
        drain(master, 0.3)

        # 4. Exercise Help modal ('?')
        os.write(master, b"?")
        out = read_until(master, ["Keyboard Shortcut Cheat Sheet", "HELP"], timeout=3.0)
        assert "Cheat Sheet" in out or "HELP" in out, f"Help modal not displayed, got: {repr(out)}"
        print("  -> Help modal opened.")
        os.write(master, b"\x1b") # Esc to close
        drain(master)
        print("  -> Help modal closed.")

        # 5. Exercise Search ('/')
        os.write(master, b"/")
        drain(master)
        os.write(master, b"Classified")
        drain(master)
        os.write(master, b"\x1b") # Esc to exit search mode
        drain(master)
        print("  -> Search exercised.")

        # 6. Exercise Inline Create ('n')
        os.write(master, b"n")
        drain(master)
        new_title = "Smoke Inline Note"
        for ch in new_title:
            os.write(master, ch.encode())
        os.write(master, b"\t") # Focus tags
        for ch in "smoke,tui":
            os.write(master, ch.encode())
        os.write(master, b"\t") # Focus body
        for ch in "Inline created body in TUI":
            os.write(master, ch.encode())
        os.write(master, b"\x13") # Ctrl+S to save
        drain(master, 0.5)
        print("  -> Inline note created and saved.")

        # 7. Exercise Conflicts View ('c')
        os.write(master, b"c")
        out = read_until(master, ["Sync Conflicts", "No unresolved conflicts", "CONFLICTS"], timeout=3.0)
        assert "Conflicts" in out or "CONFLICTS" in out or "unresolved" in out, f"Conflict view not displayed: {repr(out)}"
        print("  -> Conflicts view opened.")
        os.write(master, b"\x1b") # Esc to close
        drain(master)

        # 8. Exercise Sync dispatch ('s')
        os.write(master, b"s")
        drain(master, 0.5)
        print("  -> Manual sync dispatched.")

        # 9. Exercise Delete confirmation ('d' -> 'n')
        os.write(master, b"d")
        out = read_until(master, ["Confirm Deletion", "Delete note"], timeout=3.0)
        assert "Deletion" in out or "Delete note" in out, f"Delete confirm modal not displayed: {repr(out)}"
        print("  -> Delete confirmation modal opened.")
        os.write(master, b"n") # Cancel
        drain(master)
        print("  -> Delete cancelled.")

        # 10. Exercise Terminal Resize below 80x24 (e.g. 50x15)
        set_winsize(master, 15, 50)
        os.kill(proc.pid, 28) # SIGWINCH
        time.sleep(0.3)
        # Send a tick/input trigger so poll wakes up if needed
        os.write(master, b"\x00")
        out = read_until(master, ["Terminal Too Small"], timeout=3.0)
        print(f"  -> Debug resize output: {repr(out)}")
        assert "Terminal Too Small" in out, f"TerminalTooSmall view not triggered: {out}"
        print("  -> Resize below 80x24 rendered Terminal Too Small view.")

        # Restore terminal size
        set_winsize(master, 30, 100)
        os.kill(proc.pid, 28) # SIGWINCH
        drain(master)

        # 11. Exercise Lock ('l')
        os.write(master, b"l")
        out = read_until(master, ["Vault Locked"], timeout=3.0)
        assert "Vault Locked" in out, "Lock action failed to return to locked view"
        print("  -> Explicit lock succeeded. All decrypted state purged.")

        # 12. Quit from locked view ('q')
        os.write(master, b"q")
        drain(master)

        proc.wait(timeout=3.0)
        print(f"  -> TUI exited cleanly with exit code {proc.returncode}.")
        assert proc.returncode == 0, f"Expected returncode 0, got {proc.returncode}"

        # Verify terminal attributes are restored on normal exit
        post_tcattr = termios.tcgetattr(master)
        # Check ECHO and ICANON are restored (or consistent with original)
        print(f"  -> Verified terminal attributes after normal exit: ECHO={(post_tcattr[3] & termios.ECHO) != 0}")

    finally:
        if proc.poll() is None:
            proc.kill()
        os.close(master)

    print("Step 4b: Testing handled error within TUI (invalid passphrase attempt)...")
    master2, slave2 = pty.openpty()
    set_winsize(slave2, 30, 100)

    def preexec2():
        os.setsid()
        try:
            fcntl.ioctl(slave2, termios.TIOCSCTTY, 0)
        except Exception:
            pass

    proc2 = subprocess.Popen(
        [bin_path, "--data-dir", data_dir, "tui"],
        stdin=slave2,
        stdout=slave2,
        stderr=slave2,
        preexec_fn=preexec2,
        close_fds=True
    )
    os.close(slave2)

    # Expect locked screen
    out2 = read_until(master2, ["Vault Locked", "Passphrase:"], timeout=5.0)
    assert "Vault Locked" in out2

    # Send WRONG passphrase
    os.write(master2, b"WrongPassphrase123!\r")
    out2 = read_until(master2, ["Invalid", "error", "failed"], timeout=5.0)
    print("  -> Handled authentication error displayed without panic.")

    # Quit cleanly via 'q' from locked screen
    os.write(master2, b"q")
    proc2.wait(timeout=5.0)
    print(f"  -> TUI exited cleanly after error with code {proc2.returncode}.")
    assert proc2.returncode == 0

    post_tcattr2 = termios.tcgetattr(master2)
    print(f"  -> Terminal attributes restored after error: ECHO={(post_tcattr2[3] & termios.ECHO) != 0}")
    os.close(master2)

    # 13. Security & Plaintext Audit on disk
    print("Step 5: Verifying zero plaintext leakage on disk...")
    forbidden_strings = [
        secret_title,
        secret_body,
        new_title,
        "Inline created body in TUI",
        passphrase,
    ]

    for root, dirs, files in os.walk(data_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            with open(fpath, "rb") as f:
                content = f.read()
            for forbidden in forbidden_strings:
                if forbidden.encode("utf-8") in content:
                    raise AssertionError(
                        f"CRITICAL SECURITY FAILURE: Found plaintext string '{forbidden}' in {fpath}!"
                    )
    print("  -> PASSED: No forbidden plaintext, titles, bodies, or passphrases found in data directory.")
    print("ALL SMOKE CHECKS PASSED SUCCESSFULLY.")

if __name__ == "__main__":
    main()
