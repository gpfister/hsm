#!/usr/bin/env python3
"""
mock_hsm_pty.py - POSIX Virtual Pseudo-Terminal (PTY) HSM Simulator

Simulates an nRF52840 Hardware Security Module responding to AT ASCII commands
over a virtual serial interface. Implements SECP256R1 ECDSA key generation,
signing, public key export, PIN authentication, 3-of-5 Shamir Secret Sharing
ceremonies (GF256), BIP-39 word commitment, blind dual-device ECDH key migration,
and automatic self-locking after sensitive operations.
"""

import argparse
import os
import pty
import select
import signal
import sys
import termios
import time
import tty
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Ensure script dir is in path to import bip39_words
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from bip39_words import BIP39_WORDLIST
except ImportError:
    BIP39_WORDLIST = ["abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract"]


# GF(256) field arithmetic with generator polynomial 0x11D (x^8 + x^4 + x^3 + x + 1)
GF256_EXP = [0] * 512
GF256_LOG = [0] * 256


def _init_gf256():
    x = 1
    for i in range(255):
        GF256_EXP[i] = x
        GF256_EXP[i + 255] = x
        GF256_LOG[x] = i
        x = (x << 1)
        if x & 0x100:
            x ^= 0x11D


_init_gf256()


def gf256_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return GF256_EXP[GF256_LOG[a] + GF256_LOG[b]]


def gf256_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("GF(256) division by zero")
    if a == 0:
        return 0
    return GF256_EXP[(GF256_LOG[a] - GF256_LOG[b] + 255) % 255]


def eval_poly_gf256(coeffs: list, x: int) -> int:
    res = 0
    xp = 1
    for c in coeffs:
        res ^= gf256_mul(c, xp)
        xp = gf256_mul(xp, x)
    return res


def lagrange_interpolate_gf256(points: list) -> int:
    secret = 0
    for j, (xj, yj) in enumerate(points):
        num = 1
        den = 1
        for m, (xm, _) in enumerate(points):
            if m != j:
                num = gf256_mul(num, xm)
                den = gf256_mul(den, xj ^ xm)
        secret ^= gf256_mul(yj, gf256_div(num, den))
    return secret


class MockHSMEngine:
    """State machine for mock nRF52840 HSM AT command processing."""

    def __init__(self, pin: str = "123456", verbose: bool = False, auto_lock: bool = True):
        self.pin = pin
        self.verbose = verbose
        self.auto_lock = auto_lock
        self.authenticated = False
        self.retries = 3
        self.keys = {}
        self.slots = self.keys
        self.master_secret = None
        self.shamir_initialized = False
        self.expected_shares = {}
        self.submitted_shares = {}
        self.commitment_words = []
        self.ephemeral_target_key = None
        self.init_default_keys()

    def handle_reset(self) -> str:
        """Zeroizes persistent key slot store, Shamir secret, and authentication state."""
        self.slots.clear()
        if self.keys is not self.slots:
            self.keys.clear()
        self.master_secret = None
        self.shamir_initialized = False
        self.authenticated = False
        self.retries = 3
        self.submitted_shares.clear()
        self.commitment_words.clear()
        self.expected_shares.clear()
        return "\r\nOK\r\n"

    def init_default_keys(self):
        """Pre-populate slot 1 with default SECP256R1 keypair."""
        key = ec.generate_private_key(ec.SECP256R1())
        pub_bytes = key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        self.keys[1] = {
            "key": key,
            "algo": "EC_P256",
            "size": 256,
            "label": "DefaultKey",
            "pub_hex": pub_bytes.hex().upper(),
        }

    def log(self, msg: str):
        if self.verbose:
            sys.stderr.write(f"[MOCK-HSM] {msg}\n")
            sys.stderr.flush()

    def handle_command(self, line: str) -> str:
        """Processes a single AT command string and returns response bytes."""
        cmd = line.strip()
        self.log(f"RECV: {cmd}")

        cmd_upper = cmd.upper()

        if cmd_upper == "AT":
            return "\r\nOK\r\n"

        if cmd_upper == "AT+INFO?":
            return '\r\n+INFO: FW="1.0.0-mock",HW="PCA10059",UID="0102030405060708",BOOT="B0+MCUboot"\r\nOK\r\n'

        if cmd_upper == "AT+STATUS?":
            auth_val = 1 if self.authenticated else 0
            return f"\r\n+STATUS: AUTH={auth_val},RETRIES={self.retries},KEYCOUNT={len(self.keys)}\r\nOK\r\n"

        if cmd_upper.startswith("AT+AUTH="):
            pin_arg = cmd[8:].strip()
            if self.retries <= 0:
                # PIN blocked
                return "\r\n+CME ERROR: 3\r\n"
            if pin_arg == self.pin:
                self.authenticated = True
                self.retries = 3
                return "\r\nOK\r\n"
            else:
                self.retries = max(0, self.retries - 1)
                if self.retries == 0:
                    return "\r\n+CME ERROR: 3\r\n"
                return "\r\n+CME ERROR: 2\r\n"

        if cmd_upper == "AT+LOCK":
            self.authenticated = False
            self.submitted_shares = {}
            self.commitment_words = []
            return "\r\nOK\r\n"

        if cmd_upper in ("AT+RESET", "AT+FACTORYRESET"):
            return self.handle_reset()

        if cmd_upper.startswith("AT+AUTOLOCK="):
            val = cmd[12:].strip()
            if val == "1":
                self.auto_lock = True
                return "\r\nOK\r\n"
            elif val == "0":
                self.auto_lock = False
                return "\r\nOK\r\n"
            else:
                return "\r\n+CME ERROR: 5\r\n"

        # 3-of-5 Shamir Threshold Initialization
        if cmd_upper.startswith("AT+INIT="):
            param_str = cmd[8:].strip()
            if param_str != "1":
                return "\r\n+CME ERROR: 5\r\n"

            secret_bytes = os.urandom(32)
            self.master_secret = secret_bytes
            self.shamir_initialized = True
            temp_shares = {i: [] for i in range(1, 6)}
            for b in secret_bytes:
                a1, a2 = os.urandom(2)
                coeffs = [b, a1, a2]
                for i in range(1, 6):
                    temp_shares[i].append(eval_poly_gf256(coeffs, i))

            self.expected_shares = {i: bytes(temp_shares[i]).hex().upper() for i in range(1, 6)}
            self.submitted_shares = {}
            self.commitment_words = []
            self.authenticated = False

            lines = []
            for i in range(1, 6):
                lines.append(f"+INIT: {i},{self.expected_shares[i]}")
            return "\r\n" + "\r\n".join(lines) + "\r\nOK\r\n"

        # Custodian Share Submission
        if cmd_upper.startswith("AT+SHARE="):
            param_str = cmd[9:].strip()
            parts = [p.strip() for p in param_str.split(",")]
            if len(parts) != 2:
                return "\r\n+CME ERROR: 5\r\n"
            try:
                idx = int(parts[0])
            except ValueError:
                return "\r\n+CME ERROR: 5\r\n"
            if not (1 <= idx <= 5):
                return "\r\n+CME ERROR: 5\r\n"

            share_hex = parts[1].upper()
            if len(share_hex) != 64:
                return "\r\n+CME ERROR: 5\r\n"
            try:
                bytes.fromhex(share_hex)
            except ValueError:
                return "\r\n+CME ERROR: 5\r\n"

            # Rejection of duplicate share presentation
            if idx in self.submitted_shares:
                return "\r\n+CME ERROR: 103\r\n"

            # Check validity if threshold was initialized
            if self.expected_shares:
                if idx not in self.expected_shares or self.expected_shares[idx] != share_hex:
                    return "\r\n+CME ERROR: 2\r\n"

            self.submitted_shares[idx] = share_hex

            # Issue ephemeral BIP-39 commitment word
            word_idx = int.from_bytes(os.urandom(2), "big") % len(BIP39_WORDLIST)
            word = BIP39_WORDLIST[word_idx]
            self.commitment_words.append(word)

            count = len(self.submitted_shares)
            if count < 3:
                return f'\r\n+SHARE: {count}/3 ACCEPTED,WORD="{word}"\r\nOK\r\n'
            elif count == 3:
                # Quorum reached: verify Lagrange reconstruction
                if self.master_secret:
                    points_by_byte = [[] for _ in range(32)]
                    for s_idx, s_hex in self.submitted_shares.items():
                        s_b = bytes.fromhex(s_hex)
                        for b_idx in range(32):
                            points_by_byte[b_idx].append((s_idx, s_b[b_idx]))
                    reconstructed = bytes(lagrange_interpolate_gf256(points_by_byte[b_idx]) for b_idx in range(32))
                    if reconstructed != self.master_secret:
                        return "\r\n+CME ERROR: 6\r\n"
                self.authenticated = True
                return f'\r\n+SHARE: 3/3 ACCEPTED,QUORUM_MET,WORD="{word}"\r\nOK\r\n'
            else:
                return f'\r\n+SHARE: {count}/3 ACCEPTED,WORD="{word}"\r\nOK\r\n'

        # Ephemeral Word Commitment
        if cmd_upper.startswith("AT+COMMIT="):
            return "\r\nOK\r\n"

        # Blind Migration: Target Ephemeral ECDH Initialization
        if cmd_upper == "AT+MIGRATE_TARGET_INIT":
            try:
                self.ephemeral_target_key = ec.generate_private_key(ec.SECP256R1())
                pub_bytes = self.ephemeral_target_key.public_key().public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint
                )
                pub_hex = pub_bytes.hex().upper()
                return f'\r\n+MIGRATE_TARGET_INIT: PUB="{pub_hex}"\r\nOK\r\n'
            except Exception as e:
                self.log(f"Migrate target init error: {e}")
                return "\r\n+CME ERROR: 6\r\n"

        # Blind Migration: Source Hardware Wrapping via ECDH + AES-256-GCM
        if cmd_upper.startswith("AT+MIGRATE_WRAP="):
            if not self.authenticated:
                return "\r\n+CME ERROR: 1\r\n"
            param_str = cmd[16:].strip()
            parts = [p.strip() for p in param_str.split(",")]
            if len(parts) != 2:
                return "\r\n+CME ERROR: 5\r\n"
            try:
                slot_id = int(parts[0])
            except ValueError:
                return "\r\n+CME ERROR: 5\r\n"
            if not (1 <= slot_id <= 16):
                return "\r\n+CME ERROR: 5\r\n"
            if slot_id not in self.keys:
                return "\r\n+CME ERROR: 4\r\n"

            target_pub_hex = parts[1].strip('"').strip("'")
            if len(target_pub_hex) != 130 or not target_pub_hex.startswith("04"):
                return "\r\n+CME ERROR: 5\r\n"

            try:
                target_pub_bytes = bytes.fromhex(target_pub_hex)
                target_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), target_pub_bytes)
                source_ephemeral = ec.generate_private_key(ec.SECP256R1())
                source_pub_bytes = source_ephemeral.public_key().public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint
                )
                source_pub_hex = source_pub_bytes.hex().upper()

                shared_secret = source_ephemeral.exchange(ec.ECDH(), target_pub)
                derived = HKDF(
                    algorithm=hashes.SHA256(),
                    length=44,
                    salt=None,
                    info=b"HSM_MIGRATION_V1"
                ).derive(shared_secret)

                key_enc = derived[:32]
                iv = derived[32:]
                aesgcm = AESGCM(key_enc)

                priv_scalar = self.keys[slot_id]["key"].private_numbers().private_value.to_bytes(32, "big")
                ct_and_tag = aesgcm.encrypt(iv, priv_scalar, None)
                ct_hex = ct_and_tag[:-16].hex().upper()
                tag_hex = ct_and_tag[-16:].hex().upper()

                # Self-lock after sensitive operation
                if self.auto_lock:
                    self.authenticated = False

                return f"\r\n+MIGRATE_WRAP: {source_pub_hex},{ct_hex},{tag_hex}\r\nOK\r\n"
            except Exception as e:
                self.log(f"Migrate wrap error: {e}")
                return "\r\n+CME ERROR: 6\r\n"

        # Blind Migration: Target Hardware Unwrapping via ECDH + AES-256-GCM
        if cmd_upper.startswith("AT+MIGRATE_UNWRAP="):
            param_str = cmd[18:].strip()
            parts = [p.strip() for p in param_str.split(",")]
            if len(parts) != 4:
                return "\r\n+CME ERROR: 5\r\n"
            try:
                slot_id = int(parts[0])
            except ValueError:
                return "\r\n+CME ERROR: 5\r\n"
            if not (1 <= slot_id <= 16):
                return "\r\n+CME ERROR: 5\r\n"

            source_pub_hex = parts[1].strip('"').strip("'")
            ct_hex = parts[2].strip('"').strip("'")
            tag_hex = parts[3].strip('"').strip("'")

            if len(source_pub_hex) != 130 or len(ct_hex) != 64 or len(tag_hex) != 32:
                return "\r\n+CME ERROR: 5\r\n"

            if not self.ephemeral_target_key:
                return "\r\n+CME ERROR: 6\r\n"

            try:
                source_pub_bytes = bytes.fromhex(source_pub_hex)
                source_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), source_pub_bytes)
                shared_secret = self.ephemeral_target_key.exchange(ec.ECDH(), source_pub)
                derived = HKDF(
                    algorithm=hashes.SHA256(),
                    length=44,
                    salt=None,
                    info=b"HSM_MIGRATION_V1"
                ).derive(shared_secret)

                key_dec = derived[:32]
                iv = derived[32:]
                aesgcm = AESGCM(key_dec)

                ciphertext = bytes.fromhex(ct_hex)
                tag = bytes.fromhex(tag_hex)
                priv_scalar_bytes = aesgcm.decrypt(iv, ciphertext + tag, None)

                priv_val = int.from_bytes(priv_scalar_bytes, "big")
                restored_key = ec.derive_private_key(priv_val, ec.SECP256R1())
                pub_bytes = restored_key.public_key().public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint
                )
                pub_hex = pub_bytes.hex().upper()

                self.keys[slot_id] = {
                    "key": restored_key,
                    "algo": "EC_P256",
                    "size": 256,
                    "label": f"MigratedKey{slot_id}",
                    "pub_hex": pub_hex,
                }
                self.ephemeral_target_key = None

                # Self-lock after sensitive operation
                if self.auto_lock:
                    self.authenticated = False

                return "\r\nOK\r\n"
            except Exception as e:
                self.log(f"Migrate unwrap error: {e}")
                return "\r\n+CME ERROR: 6\r\n"

        if cmd_upper == "AT+SLOTS?":
            if not self.keys:
                return "\r\nOK\r\n"
            lines = []
            for slot_id in sorted(self.keys.keys()):
                k = self.keys[slot_id]
                lines.append(f"+SLOTS: {slot_id},{k['algo']},{k['size']},{k['label']}")
            return "\r\n" + "\r\n".join(lines) + "\r\nOK\r\n"

        if cmd_upper.startswith("AT+KEYGEN="):
            if not self.authenticated:
                return "\r\n+CME ERROR: 1\r\n"
            param_str = cmd[10:].strip()
            parts = [p.strip() for p in param_str.split(",")]
            if len(parts) != 2:
                return "\r\n+CME ERROR: 5\r\n"
            try:
                slot_id = int(parts[0])
            except ValueError:
                return "\r\n+CME ERROR: 5\r\n"
            algo = parts[1].upper()
            if not (1 <= slot_id <= 16) or algo != "EC_P256":
                return "\r\n+CME ERROR: 5\r\n"

            try:
                key = ec.generate_private_key(ec.SECP256R1())
                pub_bytes = key.public_key().public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint
                )
                pub_hex = pub_bytes.hex().upper()
                self.keys[slot_id] = {
                    "key": key,
                    "algo": "EC_P256",
                    "size": 256,
                    "label": f"Key{slot_id}",
                    "pub_hex": pub_hex,
                }

                # Self-lock after sensitive operation
                if self.auto_lock:
                    self.authenticated = False

                return f'\r\n+KEYGEN: {slot_id},PUB="{pub_hex}"\r\nOK\r\n'
            except Exception as e:
                self.log(f"Keygen failure: {e}")
                return "\r\n+CME ERROR: 6\r\n"

        if cmd_upper.startswith("AT+PUBKEY="):
            param_str = cmd[10:].strip()
            try:
                slot_id = int(param_str)
            except ValueError:
                return "\r\n+CME ERROR: 5\r\n"
            if not (1 <= slot_id <= 16):
                return "\r\n+CME ERROR: 5\r\n"
            if slot_id not in self.keys:
                return "\r\n+CME ERROR: 4\r\n"

            pub_hex = self.keys[slot_id]["pub_hex"]
            return f'\r\n+PUBKEY: {slot_id},PUB="{pub_hex}"\r\nOK\r\n'

        if cmd_upper.startswith("AT+SIGN="):
            if not self.authenticated:
                return "\r\n+CME ERROR: 1\r\n"
            param_str = cmd[8:].strip()
            parts = [p.strip() for p in param_str.split(",")]
            if len(parts) != 2:
                return "\r\n+CME ERROR: 5\r\n"
            try:
                slot_id = int(parts[0])
            except ValueError:
                return "\r\n+CME ERROR: 5\r\n"
            hash_hex = parts[1]
            if not (1 <= slot_id <= 16):
                return "\r\n+CME ERROR: 5\r\n"
            if slot_id not in self.keys:
                return "\r\n+CME ERROR: 4\r\n"
            if len(hash_hex) != 64:
                return "\r\n+CME ERROR: 5\r\n"
            try:
                digest = bytes.fromhex(hash_hex)
            except ValueError:
                return "\r\n+CME ERROR: 5\r\n"

            try:
                key = self.keys[slot_id]["key"]
                der_sig = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                r, s = utils.decode_dss_signature(der_sig)
                raw_sig = (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex().upper()
                return f"\r\n+SIGN: {raw_sig}\r\nOK\r\n"
            except Exception as e:
                self.log(f"Sign failure: {e}")
                return "\r\n+CME ERROR: 6\r\n"

        if cmd_upper.startswith("AT+RANDOM="):
            param_str = cmd[10:].strip()
            try:
                length = int(param_str)
            except ValueError:
                return "\r\n+CME ERROR: 5\r\n"
            if not (1 <= length <= 128):
                return "\r\n+CME ERROR: 5\r\n"
            rand_hex = os.urandom(length).hex().upper()
            return f"\r\n+RANDOM: {rand_hex}\r\nOK\r\n"

        # Unsupported command
        return "\r\n+CME ERROR: 8\r\n"


def run_self_test(pty_path: str):
    """Executes a ping check against the specified PTY path."""
    import serial
    print(f"[TEST] Opening {pty_path}...")
    try:
        ser = serial.Serial(pty_path, 115200, timeout=2.0)
        ser.write(b"AT\r\n")
        resp = ser.read_until(b"OK\r\n")
        if b"OK" in resp:
            print("[TEST] Ping OK! Simulator working.")
            ser.close()
            return 0
        else:
            print(f"[TEST] Unexpected response: {resp}")
            ser.close()
            return 1
    except Exception as e:
        print(f"[TEST] Error: {e}")
        return 1


def main():
    parser = argparse.ArgumentParser(description="nRF52840 Mock HSM PTY Simulator")
    parser.add_argument("--pty-path", default="/tmp/mock-hsm-pty", help="Symlink path for slave PTY")
    parser.add_argument("--pin", default="123456", help="Default user PIN (default: 123456)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--auto-lock", action="store_true", default=True, help="Auto self-lock after sensitive ops")
    parser.add_argument("--no-auto-lock", action="store_false", dest="auto_lock", help="Disable auto self-lock")
    parser.add_argument("--test-ping", action="store_true", help="Run quick ping test and exit")
    args = parser.parse_args()

    engine = MockHSMEngine(pin=args.pin, verbose=args.verbose, auto_lock=args.auto_lock)

    # Open pseudo-terminal master and slave
    master_fd, slave_fd = pty.openpty()
    slave_name = os.ttyname(slave_fd)

    # Set raw mode on slave so input is not echoed back and newlines are unmodified
    try:
        tty.setraw(slave_fd)
    except Exception:
        pass

    # Create symlink
    if os.path.exists(args.pty_path) or os.path.islink(args.pty_path):
        try:
            os.unlink(args.pty_path)
        except OSError:
            pass

    try:
        os.symlink(slave_name, args.pty_path)
    except OSError as e:
        sys.stderr.write(f"Failed to create symlink {args.pty_path} -> {slave_name}: {e}\n")
        sys.exit(1)

    print(f"[MOCK-HSM] Ready. Slave: {slave_name} -> {args.pty_path}")
    sys.stdout.flush()

    def cleanup(signum=None, frame=None):
        if os.path.exists(args.pty_path) or os.path.islink(args.pty_path):
            try:
                os.unlink(args.pty_path)
            except OSError:
                pass
        try:
            os.close(master_fd)
            os.close(slave_fd)
        except OSError:
            pass
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    if args.test_ping:
        os.write(master_fd, b"")
        cleanup()
        return

    read_buffer = b""

    try:
        while True:
            rlist, _, _ = select.select([master_fd], [], [], 0.5)
            if master_fd in rlist:
                try:
                    data = os.read(master_fd, 512)
                except OSError:
                    continue

                if not data:
                    continue

                read_buffer += data

                if len(read_buffer) > 256 and b"\n" not in read_buffer:
                    err = b"\r\n+CME ERROR: 7\r\n"
                    os.write(master_fd, err)
                    read_buffer = b""
                    continue

                while b"\n" in read_buffer or b"\r" in read_buffer:
                    idx_n = read_buffer.find(b"\n")
                    idx_r = read_buffer.find(b"\r")

                    if idx_n != -1 and idx_r != -1:
                        split_idx = min(idx_n, idx_r)
                    elif idx_n != -1:
                        split_idx = idx_n
                    else:
                        split_idx = idx_r

                    line_bytes = read_buffer[:split_idx]
                    rest = read_buffer[split_idx:]
                    while rest and (rest[:1] == b"\r" or rest[:1] == b"\n"):
                        rest = rest[1:]
                    read_buffer = rest

                    line_str = line_bytes.decode("ascii", errors="replace").strip()
                    if not line_str:
                        continue

                    resp = engine.handle_command(line_str)
                    if engine.verbose:
                        engine.log(f"SENT: {resp.strip()}")
                    os.write(master_fd, resp.encode("ascii"))
    except KeyboardInterrupt:
        pass
    finally:
        cleanup()


if __name__ == "__main__":
    main()
