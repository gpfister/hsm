#!/usr/bin/env python3
"""
test_at_client.py - Comprehensive AT Protocol Test Runner & Cryptographic Verifier

Validates communication over the virtual PTY (or physical dongle CDC-ACM serial port),
testing AT commands, state machine transitions, ECDSA P-256 key generation,
signing, OpenSSL signature verification, 3-of-5 Shamir threshold initialization,
custodian turn-by-turn share entry and quorum unlock, duplicate share rejection,
BIP-39 word commitment issuance, automatic self-locking after sensitive operations,
and dual-device blind ECDH migration handshakes.
"""

import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
import time
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import serialization, hashes

# Ensure script dir is in path to import bip39_words
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from bip39_words import BIP39_WORDLIST
except ImportError:
    BIP39_WORDLIST = []


def send_and_receive(fd, cmd: str, timeout: float = 2.0) -> str:
    """Sends an AT command terminated by CRLF and accumulates response until OK or ERROR."""
    os.write(fd, (cmd + "\r\n").encode("ascii"))

    start_time = time.time()
    resp_buf = b""
    while time.time() - start_time < timeout:
        try:
            chunk = os.read(fd, 256)
            if chunk:
                resp_buf += chunk
                text = resp_buf.decode("ascii", errors="replace")
                if "OK\r\n" in text or "+CME ERROR:" in text:
                    return text
        except (BlockingIOError, OSError):
            pass
        time.sleep(0.02)
    return resp_buf.decode("ascii", errors="replace")


def run_dual_device_migration_test(source_fd, script_dir: str) -> bool:
    """Spins up a secondary mock HSM PTY to test dual-device blind migration."""
    target_pty_path = "/tmp/mock-hsm-target-pty"
    target_proc = None

    if os.path.exists(target_pty_path) or os.path.islink(target_pty_path):
        try:
            os.unlink(target_pty_path)
        except OSError:
            pass

    try:
        mock_py = os.path.join(script_dir, "mock_hsm_pty.py")
        target_proc = subprocess.Popen(
            [sys.executable, mock_py, "--pty-path", target_pty_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait for target symlink
        for _ in range(50):
            if os.path.exists(target_pty_path):
                break
            time.sleep(0.05)

        if not os.path.exists(target_pty_path):
            print("    [FAIL] Failed to start secondary target Mock HSM PTY.")
            return False

        target_fd = os.open(target_pty_path, os.O_RDWR | os.O_NONBLOCK)

        # 1. Target Ephemeral ECDH Init
        resp = send_and_receive(target_fd, "AT+MIGRATE_TARGET_INIT")
        if "+MIGRATE_TARGET_INIT:" not in resp or "OK" not in resp:
            print(f"    [FAIL] Target AT+MIGRATE_TARGET_INIT failed: {resp!r}")
            os.close(target_fd)
            return False

        if 'PUB="' in resp:
            target_pub_hex = resp.split('PUB="')[1].split('"')[0]
        else:
            target_pub_hex = resp.split("+MIGRATE_TARGET_INIT:")[1].strip().split()[0]

        # 2. Source Quorum Unlock & Wrap
        # Authenticate Source with PIN for migration
        send_and_receive(source_fd, "AT+AUTH=123456")
        wrap_cmd = f"AT+MIGRATE_WRAP=2,{target_pub_hex}"
        resp = send_and_receive(source_fd, wrap_cmd)
        if "+MIGRATE_WRAP:" not in resp or "OK" not in resp:
            print(f"    [FAIL] Source AT+MIGRATE_WRAP failed: {resp!r}")
            os.close(target_fd)
            return False

        wrap_payload = resp.split("+MIGRATE_WRAP:")[1].strip().split()[0]
        wrap_parts = wrap_payload.split(",")
        if len(wrap_parts) != 3:
            print(f"    [FAIL] Malformed +MIGRATE_WRAP response: {wrap_payload}")
            os.close(target_fd)
            return False

        source_pub_hex, ct_hex, tag_hex = wrap_parts[0], wrap_parts[1], wrap_parts[2]

        # Assert Source automatically self-locked
        status_resp = send_and_receive(source_fd, "AT+STATUS?")
        if "AUTH=0" not in status_resp:
            print(f"    [FAIL] Source did not auto self-lock after wrap: {status_resp!r}")
            os.close(target_fd)
            return False

        # 3. Target Unwrap & Persistent Storage
        unwrap_cmd = f"AT+MIGRATE_UNWRAP=2,{source_pub_hex},{ct_hex},{tag_hex}"
        resp = send_and_receive(target_fd, unwrap_cmd)
        if "OK" not in resp:
            print(f"    [FAIL] Target AT+MIGRATE_UNWRAP failed: {resp!r}")
            os.close(target_fd)
            return False

        # Assert Target automatically self-locked
        status_resp = send_and_receive(target_fd, "AT+STATUS?")
        if "AUTH=0" not in status_resp:
            print(f"    [FAIL] Target did not auto self-lock after unwrap: {status_resp!r}")
            os.close(target_fd)
            return False

        # 4. Verify Migrated Public Key Matches Source Public Key Exactly
        source_pub_resp = send_and_receive(source_fd, "AT+PUBKEY=2")
        target_pub_resp = send_and_receive(target_fd, "AT+PUBKEY=2")

        if "+PUBKEY: 2,PUB=\"" not in source_pub_resp or "+PUBKEY: 2,PUB=\"" not in target_pub_resp:
            print(f"    [FAIL] Failed to retrieve public keys: source={source_pub_resp!r}, target={target_pub_resp!r}")
            os.close(target_fd)
            return False

        s_pub = source_pub_resp.split('PUB="')[1].split('"')[0]
        t_pub = target_pub_resp.split('PUB="')[1].split('"')[0]

        if s_pub != t_pub:
            print(f"    [FAIL] Migrated key mismatch: Source={s_pub} vs Target={t_pub}")
            os.close(target_fd)
            return False

        # 5. Verify Target Can Sign With Migrated Key
        send_and_receive(target_fd, "AT+AUTH=123456")
        test_payload = b"Blind-Migration-Verification-Vector"
        mig_digest = hashlib.sha256(test_payload).digest()
        sign_resp = send_and_receive(target_fd, f"AT+SIGN=2,{mig_digest.hex().upper()}")

        if "+SIGN:" not in sign_resp or "OK" not in sign_resp:
            print(f"    [FAIL] Target signing with migrated key failed: {sign_resp!r}")
            os.close(target_fd)
            return False

        mig_sig_raw = sign_resp.split("+SIGN:")[1].split()[0]
        r_int = int(mig_sig_raw[:64], 16)
        s_int = int(mig_sig_raw[64:], 16)
        der_sig = utils.encode_dss_signature(r_int, s_int)

        pub_obj = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(t_pub))
        pub_obj.verify(der_sig, mig_digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))

        os.close(target_fd)
        return True

    finally:
        if target_proc:
            try:
                target_proc.terminate()
                target_proc.wait(timeout=1.0)
            except Exception:
                try:
                    target_proc.kill()
                except Exception:
                    pass
        if os.path.exists(target_pty_path) or os.path.islink(target_pty_path):
            try:
                os.unlink(target_pty_path)
            except OSError:
                pass


def run_tests(port_path: str, skip_migration: bool = False) -> bool:
    print(f"==================================================")
    print(f"[TEST RUNNER] Connecting to HSM port: {port_path}")
    print(f"==================================================")

    if not os.path.exists(port_path):
        print(f"[FAIL] Port {port_path} does not exist!")
        return False

    try:
        fd = os.open(port_path, os.O_RDWR | os.O_NONBLOCK)
    except Exception as e:
        print(f"[FAIL] Could not open port {port_path}: {e}")
        return False

    script_dir = os.path.dirname(os.path.abspath(__file__))

    try:
        # 1. AT Ping
        print("  [1/12] Testing AT link ping...")
        resp = send_and_receive(fd, "AT")
        if "OK" not in resp:
            print(f"  [FAIL] AT ping failed. Got: {resp!r}")
            return False
        print("  [PASS] AT -> OK")

        # 2. AT+INFO?
        print("  [2/12] Testing AT+INFO? query...")
        resp = send_and_receive(fd, "AT+INFO?")
        if "+INFO:" not in resp or "OK" not in resp:
            print(f"  [FAIL] AT+INFO? failed. Got: {resp!r}")
            return False
        print(f"  [PASS] {resp.strip()}")

        # 3. AT+STATUS?
        print("  [3/12] Testing AT+STATUS? query...")
        resp = send_and_receive(fd, "AT+STATUS?")
        if "+STATUS:" not in resp or "OK" not in resp:
            print(f"  [FAIL] AT+STATUS? failed. Got: {resp!r}")
            return False
        print(f"  [PASS] {resp.strip()}")

        # 4. Auth & Lockout Check
        print("  [4/12] Testing authentication & error handling...")
        resp = send_and_receive(fd, "AT+RESET")
        if "OK" not in resp:
            print(f"  [FAIL] AT+RESET failed. Got: {resp!r}")
            return False

        # Wrong PIN
        resp = send_and_receive(fd, "AT+AUTH=wrongpin")
        if "+CME ERROR: 2" not in resp:
            print(f"  [FAIL] Wrong PIN should return +CME ERROR: 2. Got: {resp!r}")
            return False

        # Status after 1 failure -> retries=2
        resp = send_and_receive(fd, "AT+STATUS?")
        if "RETRIES=2" not in resp:
            print(f"  [FAIL] Retries should be 2. Got: {resp!r}")
            return False

        # Valid PIN
        resp = send_and_receive(fd, "AT+AUTH=123456")
        if "OK" not in resp:
            print(f"  [FAIL] Valid PIN failed. Got: {resp!r}")
            return False
        print("  [PASS] PIN authentication succeeded and unlocked session.")

        # 5. Shamir 3-of-5 Threshold Initialization (AT+INIT=1)
        print("  [5/12] Testing Shamir threshold initialization (AT+INIT=1)...")
        resp = send_and_receive(fd, "AT+INIT=1")
        if "+INIT: 1," not in resp or "OK" not in resp:
            print(f"  [FAIL] AT+INIT=1 failed. Got: {resp!r}")
            return False

        shares = {}
        for line in resp.strip().split("\n"):
            line = line.strip()
            if line.startswith("+INIT:"):
                part = line[6:].strip()
                s_idx, s_hex = part.split(",")
                shares[int(s_idx)] = s_hex.strip()

        if len(shares) != 5:
            print(f"  [FAIL] Expected 5 shares from AT+INIT=1, got {len(shares)}")
            return False

        for i in range(1, 6):
            if len(shares[i]) != 64:
                print(f"  [FAIL] Share {i} invalid length: {len(shares[i])} (expected 64)")
                return False

        # Verify device entered locked state upon initialization
        status_resp = send_and_receive(fd, "AT+STATUS?")
        if "AUTH=0" not in status_resp:
            print(f"  [FAIL] Device must be in locked state after AT+INIT=1. Got: {status_resp!r}")
            return False
        print(f"  [PASS] 5 Shamir shares generated (3-of-5 threshold) over GF(256).")

        # 6. Duplicate Share Rejection Verification (+CME ERROR: 103)
        print("  [6/12] Testing duplicate share rejection (+CME ERROR: 103)...")
        # Submit share 1
        resp = send_and_receive(fd, f"AT+SHARE=1,{shares[1]}")
        if "+SHARE: 1/3 ACCEPTED" not in resp or "OK" not in resp:
            print(f"  [FAIL] Initial share 1 submission failed: {resp!r}")
            return False

        # Re-submit duplicate share 1
        dup_resp = send_and_receive(fd, f"AT+SHARE=1,{shares[1]}")
        if "+CME ERROR: 103" not in dup_resp:
            print(f"  [FAIL] Duplicate share must return +CME ERROR: 103. Got: {dup_resp!r}")
            return False
        print("  [PASS] Duplicate share presentation rejected (+CME ERROR: 103).")

        # 7. Custodian Turn-by-Turn Entry, Quorum Unlock, and Ephemeral Word Commitment
        print("  [7/12] Testing turn-by-turn share submission, quorum unlock, & BIP-39 word commitment...")
        words = []
        if 'WORD="' in resp:
            words.append(resp.split('WORD="')[1].split('"')[0])

        # Submit share 2
        resp2 = send_and_receive(fd, f"AT+SHARE=2,{shares[2]}")
        if "+SHARE: 2/3 ACCEPTED" not in resp2 or "OK" not in resp2:
            print(f"  [FAIL] Share 2 submission failed: {resp2!r}")
            return False
        if 'WORD="' in resp2:
            words.append(resp2.split('WORD="')[1].split('"')[0])

        # Submit share 3 (Quorum met)
        resp3 = send_and_receive(fd, f"AT+SHARE=3,{shares[3]}")
        if "QUORUM_MET" not in resp3 or "OK" not in resp3:
            print(f"  [FAIL] 3rd share should meet quorum. Got: {resp3!r}")
            return False
        if 'WORD="' in resp3:
            words.append(resp3.split('WORD="')[1].split('"')[0])

        # Assert Quorum Unlocked Session
        status_resp = send_and_receive(fd, "AT+STATUS?")
        if "AUTH=1" not in status_resp:
            print(f"  [FAIL] Quorum met but AUTH != 1: {status_resp!r}")
            return False

        # Verify commitment words
        if len(words) == 3:
            for w in words:
                if BIP39_WORDLIST and w not in BIP39_WORDLIST:
                    print(f"  [FAIL] Commitment word '{w}' is not in BIP-39 wordlist!")
                    return False
            # Verify AT+COMMIT
            commit_resp = send_and_receive(fd, f"AT+COMMIT={','.join(words)}")
            if "OK" not in commit_resp:
                print(f"  [FAIL] AT+COMMIT failed: {commit_resp!r}")
                return False
            print(f"  [PASS] 3-of-5 Quorum unlocked. Issued BIP-39 words: {', '.join(words)}")
        else:
            print("  [PASS] 3-of-5 Quorum unlocked session.")

        # 8. Keypair Generation & Auto Self-Lock State Assertion
        print("  [8/12] Testing keypair generation (AT+KEYGEN=2,EC_P256) & auto self-lock assertion...")
        resp = send_and_receive(fd, "AT+KEYGEN=2,EC_P256")
        if "+KEYGEN: 2,PUB=\"" not in resp or "OK" not in resp:
            print(f"  [FAIL] Keygen failed. Got: {resp!r}")
            return False
        pub_hex = resp.split('PUB="')[1].split('"')[0]
        if len(pub_hex) != 130 or not pub_hex.startswith("04"):
            print(f"  [FAIL] Unexpected public key hex format: {pub_hex}")
            return False

        # Assert device automatically transitioned to locked state post-keygen
        status_resp = send_and_receive(fd, "AT+STATUS?")
        if "AUTH=0" not in status_resp:
            print(f"  [FAIL] Device did not auto self-lock after key generation. Got: {status_resp!r}")
            return False

        # Assert sensitive crypto rejected while auto self-locked
        test_payload = b"Auto-Lock-Assertion-Test-Vector"
        dummy_hash = hashlib.sha256(test_payload).hexdigest().upper()
        sign_resp = send_and_receive(fd, f"AT+SIGN=2,{dummy_hash}")
        if "+CME ERROR: 1" not in sign_resp:
            print(f"  [FAIL] AT+SIGN while self-locked should return +CME ERROR: 1. Got: {sign_resp!r}")
            return False
        print(f"  [PASS] Key generated and device automatically self-locked (+CME ERROR: 1 verified).")

        # 9. Public Key Readout (AT+PUBKEY=2) & Re-auth
        print("  [9/12] Testing public key readout (AT+PUBKEY=2)...")
        resp = send_and_receive(fd, "AT+PUBKEY=2")
        if pub_hex not in resp or "OK" not in resp:
            print(f"  [FAIL] AT+PUBKEY did not match generated public key. Got: {resp!r}")
            return False
        print("  [PASS] Public key matches generated point.")

        # 10. TRNG Random Bytes (AT+RANDOM=32)
        print("  [10/12] Testing TRNG random bytes (AT+RANDOM=32)...")
        resp = send_and_receive(fd, "AT+RANDOM=32")
        if "+RANDOM:" not in resp or "OK" not in resp:
            print(f"  [FAIL] Random generation failed. Got: {resp!r}")
            return False
        rand_hex = resp.split("+RANDOM:")[1].split()[0]
        if len(rand_hex) != 64:
            print(f"  [FAIL] Random hex length unexpected: {len(rand_hex)}")
            return False
        print(f"  [PASS] Random 32 bytes: {rand_hex[:16]}...")

        # 11. ECDSA Signing & Cryptographic Verification
        print("  [11/12] Testing ECDSA signing & verification post re-auth...")
        # Re-authenticate to sign
        auth_resp = send_and_receive(fd, "AT+AUTH=123456")
        if "OK" not in auth_resp:
            print(f"  [FAIL] Re-auth failed. Got: {auth_resp!r}")
            return False

        test_payload = b"nRF52840-HSM-ECDSA-Verification-Vector"
        digest = hashlib.sha256(test_payload).digest()
        digest_hex = digest.hex().upper()

        resp = send_and_receive(fd, f"AT+SIGN=2,{digest_hex}")
        if "+SIGN:" not in resp or "OK" not in resp:
            print(f"  [FAIL] Signing failed. Got: {resp!r}")
            return False
        sig_raw_hex = resp.split("+SIGN:")[1].split()[0]
        if len(sig_raw_hex) != 128:
            print(f"  [FAIL] Raw signature length invalid (expected 128 hex chars, got {len(sig_raw_hex)})")
            return False

        r_int = int(sig_raw_hex[:64], 16)
        s_int = int(sig_raw_hex[64:], 16)
        der_signature = utils.encode_dss_signature(r_int, s_int)

        pub_key_obj = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), bytes.fromhex(pub_hex)
        )
        pub_key_obj.verify(der_signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        print("  [PASS] Python cryptography verified raw R || S signature.")

        # OpenSSL external verification
        openssl_bin = None
        for p in ["/opt/homebrew/bin/openssl", "/usr/bin/openssl", "openssl"]:
            if subprocess.run(["which", p], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                openssl_bin = p
                break

        if openssl_bin:
            pub_pem = pub_key_obj.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as fp_pem, \
                 tempfile.NamedTemporaryFile(suffix=".sig", delete=False) as fp_sig, \
                 tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as fp_dat:
                fp_pem.write(pub_pem); fp_pem.flush()
                fp_sig.write(der_signature); fp_sig.flush()
                fp_dat.write(digest); fp_dat.flush()

                verify_cmd = [
                    openssl_bin, "pkeyutl", "-verify",
                    "-pubin", "-inkey", fp_pem.name,
                    "-sigfile", fp_sig.name,
                    "-in", fp_dat.name
                ]
                proc = subprocess.run(verify_cmd, capture_output=True, text=True)
                os.unlink(fp_pem.name)
                os.unlink(fp_sig.name)
                os.unlink(fp_dat.name)

                if proc.returncode != 0 or "Signature Verified Successfully" not in proc.stdout:
                    print(f"  [FAIL] OpenSSL pkeyutl verify failed: {proc.stderr} {proc.stdout}")
                    return False
                print(f"  [PASS] OpenSSL pkeyutl verified signature: {proc.stdout.strip()}")

        # 12. Dual-Device Blind Migration Handshake
        if skip_migration:
            print("  [12/12] [SKIPPED] Skipping dual-device blind migration scenario as requested.")
        else:
            print("  [12/12] Testing dual-device blind migration handshake (ECDH + AES-256-GCM)...")
            if not run_dual_device_migration_test(fd, script_dir):
                print("  [FAIL] Dual-device migration handshake failed.")
                return False
            print("  [PASS] Dual-device blind migration completed: target private key verified via signature.")

        print("==================================================")
        print("[SUCCESS] All AT Protocol & Ceremony checks passed!")
        print("==================================================")
        send_and_receive(fd, "AT+LOCK")
        return True

    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description="AT Protocol Test Runner")
    parser.add_argument("--port", default=os.environ.get("NRF52840_HSM_PORT", "/tmp/mock-hsm-pty"))
    parser.add_argument("--skip-migration", action="store_true", help="Skip dual-device blind migration scenario")
    args = parser.parse_args()

    success = run_tests(args.port, skip_migration=args.skip_migration)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
