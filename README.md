# ncs-nrf52840dongle-kms

Multi-repo workspace for building an open-source Hardware Security Module (HSM) on an **nRF52840 USB Dongle** (`PCA10059`), featuring dual-stage secure boot, dual USB CDC-ACM serial interfaces, cross-platform host tooling, and Cryptoki PKCS#11 support.

---

## Sub-Repositories

- **[`nrf52840-hsm-firmware/`](file:///Users/gpfister/Development/Projects/gpfister/nrf52840-hsm/nrf52840-hsm-firmware)**: NCS v3.4.1 / Zephyr RTOS firmware with dual-stage secure boot (B0 + MCUboot), ARM CryptoCell CC310 hardware cryptography, dynamic BLE MAC address USB serial descriptor, and dual CDC-ACM interfaces (Console & AT protocol).
- **[`nrf52840-hsm-cli/`](file:///Users/gpfister/Development/Projects/gpfister/nrf52840-hsm/nrf52840-hsm-cli)**: Cross-platform Go CLI & TUI executable `hsmutil` built with Cobra and BubbleTea. Supports device autodiscovery, multi-dongle targeting (`--serial`), key management, and PKCS#11 diagnostics.
- **[`nrf52840-hsm-libpkcs11/`](file:///Users/gpfister/Development/Projects/gpfister/nrf52840-hsm/nrf52840-hsm-libpkcs11)**: Cryptoki PKCS#11 v2.40 shared provider library (`.dylib`, `.so`, `.dll`) for OpenSC, OpenSSL, and OpenSSH.
- **[`nrf52840-hsm-obsidian/`](file:///Users/gpfister/Development/Projects/gpfister/nrf52840-hsm/nrf52840-hsm-obsidian)**: Centralized Obsidian documentation vault containing system architecture, ADRs, feature specifications, and session trajectories.
- **[`rpi-z2w-yocto-hsm/`](file:///Users/gpfister/Development/Projects/gpfister/nrf52840-hsm/rpi-z2w-yocto-hsm)**: Yocto 6.1 (Blacksail) air-gapped embedded Linux operating system for Raspberry Pi Zero 2 W / 3 / 4 / 5 with kernel hardening, nftables total drop firewall, dual-slot RAUC A/B updates, and deterministic `/dev/tty.hsm*` driver.

---

## Key Capabilities & Architecture

### USB Device Identification & Deterministic Topology
- **Hardware BLE Address Serial Number**: Dynamically extracts the factory-burned 48-bit Bluetooth Device Address from Nordic Factory Information Configuration Registers (`NRF_FICR->DEVICEADDR[1:0]`), formatted as 12 hex digits (`%04X%08X`) for `iSerialNumber`.
- **Interface Protocol Tagging**: Linker-level USB descriptor traversal patches `bInterfaceProtocol` to `0x01` (Zephyr Console) on Interface 0 and `0x02` (HSM AT API) on Interface 2.
- **Deterministic macOS Device Nodes**: macOS `AppleUSBCDC` driver synthesizes predictable BSD paths based on hardware serial and interface index:
  - `/dev/tty.usbmodem<BLE_ADDR>1`: Zephyr kernel console and logger (`cdc_acm_uart0`).
  - `/dev/tty.usbmodem<BLE_ADDR>3`: HSM AT command & crypto interface (`cdc_acm_uart1`).
- **Multi-Device Targeting & Disambiguation**: Connect multiple dongles concurrently without collisions.
  - `hsmutil devices`: Enumerate all connected dongles, BLE addresses, and port paths.
  - `hsmutil <command> --serial <BLE_ADDR>` (shorthand `-s`) or `--port <PATH>` (`-p`).
  - Auto-discovery safety: When multiple dongles are plugged in without targeting flags, `hsmutil` refuses ambiguous auto-discovery and returns an informative table of detected devices rather than guessing arbitrarily.
  - `export NRF52840_HSM_SERIAL=<BLE_ADDR>` for CLI and PKCS#11 provider.
- **Factory Reset Zeroization & Safeguards**:
  - `hsmutil reset [-y/--yes]`: Irreversible hardware factory reset zeroizing all 32 CryptoCell CC310 keys, wiping Shamir Secret Sharing master secrets from RAM and NVS, and reverting device to unconfigured state (LED breathing BLUE).
  - Protected by interactive stdin confirmation prompt `(yes/no)` or `-y`/`--yes` bypass for CI/CD scripting.

> [!NOTE]
> **Firmware DFU Streaming Migration**: Current firmware runs the pure AT command interface (`AT`, `AT+INFO`, `AT+AUTH`, `AT+KEYGEN`, `AT+SIGN`, etc.) on the dedicated CDC-ACM UART1 interface. Dual-stage MCUboot signing and candidate partition images (`zephyr.signed.bin`, `merged.hex`) are fully operational. DFU streaming migration (`AT+DFU_CHUNK` and `AT+DFU_APPLY`) will be addressed in a follow-up feature task.

---

## Quick Start

### Root Orchestration Commands

```bash
# Display help and target list
make help

# Check status across all sub-repositories and branches
make status

# Build production firmware with sysbuild and MCUboot signing
make firmware-build

# Program device via Segger J-Link (S/N: 802007333)
make firmware-flash

# Build hsmutil host executable
make cli-build

# Cross-compile hsmutil for all 5 target architectures
make cli-build-all

# Build PKCS#11 shared library provider
make libpkcs11-build

# Run PKCS#11 unit tests
make libpkcs11-test
```

### Multi-Dongle Discovery

```bash
# List all connected nRF52840 HSM dongles
./nrf52840-hsm-cli/bin/hsmutil devices

# Query specific dongle by hardware BLE address
./nrf52840-hsm-cli/bin/hsmutil info -s FD54E793A75540C9
```
