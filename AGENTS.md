# AGENTS.md — nRF52840 Dongle HSM Workspace Coordinator

Welcome to the **ncs-nrf52840dongle-kms** workspace. This repository coordinates an open-source, dual-stage secure boot Hardware Security Module (HSM) on an nRF52840 USB Dongle (`PCA10059`), compatible with the YubiHSM 2 API. It brings together firmware built with the nRF Connect SDK (NCS), a cross-platform Go CLI/TUI (`hsmutil`), an Obsidian knowledge vault, and Antigravity plugins.

---

## 1. Workspace Layout & Sub-Repositories

This workspace operates as an orchestrated multi-repository project:

```text
ncs-nrf52840dongle-kms/
├── AGENTS.md                         # This file: Project instructions & standards
├── README.md                         # Human-facing workspace overview
├── Makefile                          # Root orchestration (sync, pull, build, flash)
├── .gitignore                        # Global ignore (ignores subrepos and private keys)
├── keys/                             # Cryptographic signing keys (root-ec-p256.pem)
├── scripts/                          # Key generation and helper scripts
├── .agents/                          # Antigravity agent configuration
│   └── plugins.json                  # References companion plugins in ../agentic/
├── nrf52840-hsm-firmware/            # Git Repo: Zephyr / NCS firmware workspace
├── nrf52840-hsm-cli/                 # Git Repo: Cross-platform Go CLI (`hsmutil`)
├── nrf52840-hsm-libpkcs11/           # Git Repo: PKCS#11 v2.40 shared library provider
├── nrf52840-hsm-obsidian/            # Git Repo: Obsidian documentation vault
└── rpi-z2w-yocto-hsm/                # Git Repo: Yocto 6.1 (Blacksail) air-gapped embedded Linux OS
```

---

## 2. Subsystem Summary

### 2.1 Firmware (`nrf52840-hsm-firmware`)
- **Framework**: nRF Connect SDK v3.4.1 / Zephyr RTOS with sysbuild.
- **Target Board**: `nrf52840dongle/nrf52840` (`PCA10059`).
- **Secure Boot**:
  - Dual-stage: Stage 1 B0 (immutable bootloader using CC310 hardware crypto) $\rightarrow$ Stage 2 MCUboot (dual slot partition manager) $\rightarrow$ Signed Application.
  - Image signing uses root-level ECDSA P-256 keys (`keys/root-ec-p256.pem`).
- **USB Interfaces**:
  - `cdc_acm_uart0`: Zephyr kernel console & logger (`LOG_INF`, `LOG_DBG`, `printk`).
  - `cdc_acm_uart1`: HSM binary command/response interaction channel.
- **RGB LED Indicator**:
  - Slowly pulsating / breathing BLUE: Not configured.
  - Solid RED: Configured but locked.
  - Solid GREEN: Authenticated / unlocked.
- **Core Library (`firmware/lib`)**:
  - Decoupled, pure HSM logic implementing the YubiHSM 2 protocol packet framing, command dispatch, session cryptography, and storage abstraction.

### 2.2 CLI (`nrf52840-hsm-cli`)
- **Executable**: `hsmutil`.
- **Framework**: Go 1.24+ with Cobra and BubbleTea following Clean Architecture.
- **Key Capabilities**:
  - `hsmutil firmware info`: Display active firmware version and bootloader status.
  - `hsmutil firmware update --file <path>`: Chunked streaming upload to candidate partition slot.
  - `hsmutil info`, `hsmutil echo`, `hsmutil auth`, `hsmutil lock`, `hsmutil reset`.
  - `hsmutil tui`: Interactive terminal dashboard.
- **Cross-Platform**: Builds on macOS (arm64), Linux (arm64/amd64), and Windows (arm64/amd64) via pure-Go serial I/O.

### 2.3 Documentation (`nrf52840-hsm-obsidian`)
- Centralized Obsidian markdown vault.
- Follows wikilink conventions (`[[Note Name]]`), YAML frontmatter (`title`, `tags`, `created`), and Mermaid architecture diagrams.
- Stores architecture specs, protocols, session transcripts, and planning roadmaps.

### 2.4 PKCS#11 Shared Library Provider (`nrf52840-hsm-libpkcs11`)
- **Library**: `libnrf52840_pkcs11.dylib` (macOS), `libnrf52840_pkcs11.so` (Linux), `libnrf52840_pkcs11.dll` (Windows).
- **Standard**: Cryptoki v2.40 specification.
- **Transport**: AT-style ASCII serial protocol communicating with dongle CDC-ACM UART1 interface (`0x1209:0x0001`) or virtual mock PTY (`/tmp/mock-hsm-pty`).
- **Cryptographic Mechanisms**: `CKM_EC_KEY_PAIR_GEN`, `CKM_ECDSA`, `CKM_ECDSA_SHA256` (SECP256R1 / prime256v1).
- **Tooling Compatibility**: Direct compatibility with OpenSC `pkcs11-tool`, OpenSSL 3 `pkcs11-provider`, and OpenSSH.

### 2.5 Air-Gapped Embedded Linux OS (`rpi-z2w-yocto-hsm`)
- **Framework**: Yocto Project 6.1 (`blacksail`) / Linux 6.12+ (`linux-raspberrypi`).
- **Target Hardware**: 64-bit Raspberry Pi (`raspberrypi0-2w-64`, `raspberrypi3-64`, `raspberrypi4-64`, `raspberrypi5`) with Waveshare USB HAT (B).
- **Hardening & Isolation**:
  - Full air-gap: WiFi, Bluetooth, Ethernet, and unused GPIO headers disabled at kernel/DTB level.
  - Total-drop firewall (`nftables` drop 100% inbound, outbound, forward).
  - Read-only rootfs with dual-slot (A/B) RAUC update daemon and x509 cryptographic verification.
- **Custom Driver (`nrf52840-hsm-kmod`)**:
  - Automatically recognizes nRF52840 dongles and creates deterministic `/dev/tty.hsm<ble_address><number>`.
  - Production mode: strictly binds and exposes AT crypto channel (`cdc_acm_uart1`), suppressing debug logging ports.
- **Dedicated Console User Space**:
  - Mandatory first-login wizard (password change, keyboard layout, locale) and login-time clock prompt.
  - Auto-mount service granting `hsmutil` read/write access to external USB storage partitions.

---

## 3. Automation Commands (Root Makefile)

| Target | Description |
| :--- | :--- |
| `make sync` | Syncs/clones missing repositories and plugins, fast-forwards all repos |
| `make status` (or `st`) | Reports git status across root, plugins, and sub-repos |
| `make diff` | Displays uncommitted changes across all repositories |
| `make pull` | Fast-forwards all sub-repositories |
| `make push` | Pushes current branches across all sub-repositories |
| `make firmware-build` | Builds production and debug firmware |
| `make firmware-flash` | Programs device using J-Link `802007333` |
| `make firmware-monitor`| Connects to firmware console USB port |
| `make cli-build` | Builds `hsmutil` for current host |
| `make cli-build-all` | Cross-compiles `hsmutil` for all 5 target architectures |
| `make libpkcs11-build` | Builds PKCS#11 shared provider library via CMake |
| `make libpkcs11-test` | Runs PKCS#11 unit and interface test suite |
| `make libpkcs11-clean` | Cleans PKCS#11 build artifacts |
| `make integration-test`| Runs end-to-end integration tests using virtual mock PTY |
| `make integration-test-hw`| Runs integration tests against physical connected Dongle |
| `make yocto-build-dev` | Builds development OS image (`hsm-image-dev`) via Kas |
| `make yocto-build-prod`| Builds production air-gapped OS image (`hsm-image-prod`) via Kas |
| `make yocto-bundle`    | Builds signed RAUC A/B update bundle (`.raucb`) |
| `make yocto-shell`     | Launches interactive Kas shell inside build container |
| `make yocto-clean`     | Cleans Yocto build directory |
| `make clean` | Cleans build artifacts |
