#!/usr/bin/env python3
"""
mock_hsm_pty.py - POSIX Virtual Pseudo-Terminal (PTY) HSM Simulator

Simulates an nRF52840 Hardware Security Module responding to AT ASCII commands
over a virtual serial interface. Implements SECP256R1 ECDSA key generation,
signing, public key export, PIN authentication, and status telemetry.
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


class MockHSMEngine:
    """State machine for mock nRF52840 HSM AT command processing."""

    def __init__(self, pin: str = "123456", verbose: bool = False):
        self.pin = pin
        self.verbose = verbose
        self.authenticated = False
        self.retries = 3
        self.keys = {}
        self.init_default_keys()

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
            return "\r\nOK\r\n"

        if cmd_upper == "AT+RESET":
            self.authenticated = False
            self.retries = 3
            return "\r\nOK\r\n"

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
    parser.add_argument("--test-ping", action="store_true", help="Run quick ping test and exit")
    args = parser.parse_args()

    engine = MockHSMEngine(pin=args.pin, verbose=args.verbose)

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
        # Perform quick internal test
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
                    # Client disconnected or error
                    continue

                if not data:
                    continue

                read_buffer += data

                # Check maximum buffer length (256 bytes per command)
                if len(read_buffer) > 256 and b"\n" not in read_buffer:
                    err = b"\r\n+CME ERROR: 7\r\n"
                    os.write(master_fd, err)
                    read_buffer = b""
                    continue

                # Process complete lines
                while b"\n" in read_buffer or b"\r" in read_buffer:
                    # Find first newline delimiter
                    idx_n = read_buffer.find(b"\n")
                    idx_r = read_buffer.find(b"\r")

                    if idx_n != -1 and idx_r != -1:
                        split_idx = min(idx_n, idx_r)
                    elif idx_n != -1:
                        split_idx = idx_n
                    else:
                        split_idx = idx_r

                    line_bytes = read_buffer[:split_idx]
                    # Advance past delimiter and any adjacent \r / \n
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
