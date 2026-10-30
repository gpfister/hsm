#!/usr/bin/env python3
"""
test_at_client.py - Comprehensive AT Protocol Test Runner & Cryptographic Verifier

Validates communication over the virtual PTY (or physical dongle CDC-ACM serial port),
testing AT commands, state machine transitions, ECDSA P-256 key generation,
signing, and OpenSSL signature verification.
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


def run_tests(port_path: str) -> bool:
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

    try:
        # 1. AT Ping
        print("  [1/9] Testing AT link ping...")
        resp = send_and_receive(fd, "AT")
        if "OK" not in resp:
            print(f"  [FAIL] AT ping failed. Got: {resp!r}")
            return False
        print("  [PASS] AT -> OK")

        # 2. AT+INFO?
        print("  [2/9] Testing AT+INFO? query...")
        resp = send_and_receive(fd, "AT+INFO?")
        if "+INFO:" not in resp or "OK" not in resp:
            print(f"  [FAIL] AT+INFO? failed. Got: {resp!r}")
            return False
        print(f"  [PASS] {resp.strip()}")

        # 3. AT+STATUS?
        print("  [3/9] Testing AT+STATUS? query...")
        resp = send_and_receive(fd, "AT+STATUS?")
        if "+STATUS:" not in resp or "OK" not in resp:
            print(f"  [FAIL] AT+STATUS? failed. Got: {resp!r}")
            return False
        print(f"  [PASS] {resp.strip()}")

        # 4. Auth & Lockout Check
        print("  [4/9] Testing authentication & error handling...")
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

        # 5. AT+KEYGEN=2,EC_P256
        print("  [5/9] Testing keypair generation (AT+KEYGEN=2,EC_P256)...")
        resp = send_and_receive(fd, "AT+KEYGEN=2,EC_P256")
        if "+KEYGEN: 2,PUB=\"" not in resp or "OK" not in resp:
            print(f"  [FAIL] Keygen failed. Got: {resp!r}")
            return False
        pub_hex = resp.split('PUB="')[1].split('"')[0]
        if len(pub_hex) != 130 or not pub_hex.startswith("04"):
            print(f"  [FAIL] Unexpected public key hex format: {pub_hex}")
            return False
        print(f"  [PASS] Generated Slot 2 EC P-256 key: {pub_hex[:16]}...{pub_hex[-8:]}")

        # 6. AT+PUBKEY=2
        print("  [6/9] Testing public key readout (AT+PUBKEY=2)...")
        resp = send_and_receive(fd, "AT+PUBKEY=2")
        if pub_hex not in resp or "OK" not in resp:
            print(f"  [FAIL] AT+PUBKEY did not match generated public key. Got: {resp!r}")
            return False
        print("  [PASS] Public key matches generated point.")

        # 7. AT+RANDOM=32
        print("  [7/9] Testing TRNG random bytes (AT+RANDOM=32)...")
        resp = send_and_receive(fd, "AT+RANDOM=32")
        if "+RANDOM:" not in resp or "OK" not in resp:
            print(f"  [FAIL] Random generation failed. Got: {resp!r}")
            return False
        rand_hex = resp.split("+RANDOM:")[1].split()[0]
        if len(rand_hex) != 64:
            print(f"  [FAIL] Random hex length unexpected: {len(rand_hex)}")
            return False
        print(f"  [PASS] Random 32 bytes: {rand_hex[:16]}...")

        # 8. AT+SIGN=2,<hash> and Signature Verification
        print("  [8/9] Testing ECDSA signing (AT+SIGN=2,<sha256>)...")
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
        else:
            print("  [SKIP] OpenSSL not found; skipped external CLI verification.")

        # 9. Session Lock Verification
        print("  [9/9] Testing session lock & access control...")
        resp = send_and_receive(fd, "AT+LOCK")
        if "OK" not in resp:
            print(f"  [FAIL] AT+LOCK failed. Got: {resp!r}")
            return False

        # Attempt to sign while locked
        resp = send_and_receive(fd, f"AT+SIGN=2,{digest_hex}")
        if "+CME ERROR: 1" not in resp:
            print(f"  [FAIL] Signing while locked should return +CME ERROR: 1. Got: {resp!r}")
            return False
        print("  [PASS] Cryptographic signing rejected when session is locked (+CME ERROR: 1).")

        print("==================================================")
        print("[SUCCESS] All AT Protocol & Crypto checks passed!")
        print("==================================================")
        return True

    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description="AT Protocol Test Runner")
    parser.add_argument("--port", default=os.environ.get("NRF52840_HSM_PORT", "/tmp/mock-hsm-pty"))
    args = parser.parse_args()

    success = run_tests(args.port)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
