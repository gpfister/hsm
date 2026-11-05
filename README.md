# Open-Source USB Hardware Security Module (HSM)

Multi-repo workspace coordinating firmware, shared cryptographic libraries, host CLI tools, and air-gapped appliances for Hardware Security Module (HSM) operations. Currently targeting the **nRF52840 USB Dongle** (`PCA10059`), the system features dual-stage secure boot, dual USB CDC-ACM serial interfaces, cross-platform host administration tooling, and Cryptoki PKCS#11 support.

---

## Sub-Repositories

- **Embedded Firmware ([`hsm-ncs-firmware/`](file:///Users/gpfister/Development/Projects/gpfister/nrf52840-hsm/hsm-ncs-firmware))**: NCS v3.4.1 / Zephyr RTOS firmware targeting the nRF52840 USB Dongle (`PCA10059`) with dual-stage secure boot (B0 + MCUboot), ARM CryptoCell CC310 hardware cryptography, dynamic BLE MAC address USB serial descriptor, and dual CDC-ACM interfaces (Console & AT protocol).
- **Host CLI & Administration ([`hsm-cli/`](file:///Users/gpfister/Development/Projects/gpfister/nrf52840-hsm/hsm-cli))**: Cross-platform Go CLI & TUI executable `hsmutil` built with Cobra and BubbleTea. Supports device autodiscovery, multi-dongle targeting (`--serial`), key management, and PKCS#11 diagnostics.
- **PKCS#11 Cryptographic Provider ([`hsm-libpkcs11/`](file:///Users/gpfister/Development/Projects/gpfister/nrf52840-hsm/hsm-libpkcs11))**: Cryptoki PKCS#11 v2.40 shared provider library (`.dylib`, `.so`, `.dll`) for OpenSC, OpenSSL, and OpenSSH.
- **Documentation & Knowledge Vault ([`hsm-obsidian/`](file:///Users/gpfister/Development/Projects/gpfister/nrf52840-hsm/hsm-obsidian))**: Centralized Obsidian documentation vault containing system architecture, ADRs, feature specifications, and session trajectories.
- **Air-Gapped Appliance Operating System ([`hsm-yocto-offgrid-rpi/`](file:///Users/gpfister/Development/Projects/gpfister/nrf52840-hsm/hsm-yocto-offgrid-rpi))**: Yocto 6.1 (Blacksail) air-gapped embedded Linux operating system for Raspberry Pi Zero 2 W / 3 / 4 / 5 with kernel hardening, nftables total drop firewall, dual-slot RAUC A/B updates, and deterministic `/dev/tty.hsm*` driver.

---

## Key Capabilities & Architecture

### USB Device Identification & Deterministic Topology
- **Hardware BLE Address Serial Number**: Dynamically extracts the factory-burned 48-bit Bluetooth Device Address from Nordic Factory Information Configuration Registers (`NRF_FICR->DEVICEADDR[1:0]`), formatted as 12 hex digits (`%04X%08X`) for `iSerialNumber`.
- **Interface Protocol Tagging**: Linker-level USB descriptor traversal patches `bInterfaceProtocol` and IAD `bFunctionProtocol` to `0x01` (ITU-T V.250 AT command protocol per ADR-0013) for both Interface 0 and Interface 2, ensuring native zero-driver macOS `AppleUSBACMControl` dual enumeration.
- **Deterministic macOS Device Nodes**: macOS `AppleUSBCDC` driver synthesizes predictable BSD paths based on hardware serial and interface index:
  - `/dev/tty.usbmodem<BLE_ADDR>1`: Zephyr kernel console and logger (`cdc_acm_uart0`).
  - `/dev/tty.usbmodem<BLE_ADDR>3`: HSM AT command & crypto interface (`cdc_acm_uart1`).
- **Multi-Device Targeting & Disambiguation**: Connect multiple HSM USB dongles concurrently without collisions.
  - `hsmutil devices`: Enumerate all connected dongles, BLE addresses, and port paths.
  - `hsmutil <command> --serial <BLE_ADDR>` (shorthand `-s`) or `--port <PATH>` (`-p`).
  - Auto-discovery safety: When multiple dongles are plugged in without targeting flags, `hsmutil` refuses ambiguous auto-discovery and returns an informative table of detected devices rather than guessing arbitrarily.
  - `export NRF52840_HSM_SERIAL=<BLE_ADDR>` for CLI and PKCS#11 provider.
- **Factory Reset Zeroization & Safeguards**:
  - `hsmutil reset [-y/--yes]`: Irreversible hardware factory reset zeroizing all 32 CryptoCell CC310 keys, wiping Shamir Secret Sharing master secrets from RAM and NVS, and reverting device to unconfigured state (LED breathing BLUE).
  - Protected by interactive stdin confirmation prompt `(yes/no)` or `-y`/`--yes` bypass for CI/CD scripting.
- **Firmware DFU Streaming (`AT+DFU_INFO?`, `AT+DFU_CHUNK`, `AT+DFU_APPLY`)**:
  - Native streaming DFU protocol allowing chunked firmware uploads (256 bytes per chunk) into the secondary MCUboot partition slot with 4-byte flash word boundary alignment, automatic signature validation, and deferred reboot swap.
  - Fully integrated into `hsmutil firmware update --file <path>`.

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

### Parallel Development & Git Worktrees

The workspace provides unified multi-repository worktree orchestration, enabling multiple features, bugfixes, or experiments to be developed in parallel without switching branches in your main checkout:

```bash
# List all active worktrees across workspace and sub-repositories
make worktree-list   # or 'make wt'

# Create a parallel worktree across root and all sub-repos (in .worktrees/<name>)
make worktree-add NAME=feature-crypto

# Switch to the parallel worktree
cd .worktrees/feature-crypto

# Remove worktree and clean up git references when finished
make worktree-rm NAME=feature-crypto
```

### Multi-Dongle Discovery

```bash
# List all connected HSM USB dongles
./hsm-cli/bin/hsmutil devices

# Query specific dongle by hardware BLE address
./hsm-cli/bin/hsmutil info -s FD54E793A75540C9
```
