# AGENTS.md — nRF52840 Dongle HMS Workspace Coordinator

Welcome to the **ncs-nrf52840dongle-kms** workspace. This repository coordinates an open-source, dual-stage secure boot Hardware Security Module (HSM) on an nRF52840 USB Dongle (`PCA10059`), compatible with the YubiHSM 2 API. It brings together firmware built with the nRF Connect SDK (NCS), a cross-platform Go CLI/TUI (`hmsutil`), an Obsidian knowledge vault, and Antigravity plugins.

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
├── agentic-coding-plugin/            # Cloned Antigravity coding companion plugin
├── agentic-investigate-plugin/       # Cloned Antigravity issue investigation plugin
├── agentic-monitoring-plugin/        # Cloned Antigravity monitoring surveillance plugin
├── agentic-triage-plugin/            # Cloned Antigravity dynamic prompt triage plugin
├── nrf52840-hms-firmware/            # Git Repo: Zephyr / NCS firmware workspace
├── nrf52840-hms-cli/                 # Git Repo: Cross-platform Go CLI (`hmsutil`)
└── nrf52840-hms-obsidian/            # Git Repo: Obsidian documentation vault
```

---

## 2. Subsystem Summary

### 2.1 Firmware (`nrf52840-hms-firmware`)
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

### 2.2 CLI (`nrf52840-hms-cli`)
- **Executable**: `hmsutil`.
- **Framework**: Go 1.24+ with Cobra and BubbleTea following Clean Architecture.
- **Key Capabilities**:
  - `hmsutil firmware info`: Display active firmware version and bootloader status.
  - `hmsutil firmware update --file <path>`: Chunked streaming upload to candidate partition slot.
  - `hmsutil info`, `hmsutil echo`, `hmsutil auth`, `hmsutil lock`, `hmsutil reset`.
  - `hmsutil tui`: Interactive terminal dashboard.
- **Cross-Platform**: Builds on macOS (arm64), Linux (arm64/amd64), and Windows (arm64/amd64) via pure-Go serial I/O.

### 2.3 Documentation (`nrf52840-hms-obsidian`)
- Centralized Obsidian markdown vault.
- Follows wikilink conventions (`[[Note Name]]`), YAML frontmatter (`title`, `tags`, `created`), and Mermaid architecture diagrams.
- Stores architecture specs, protocols, session transcripts, and planning roadmaps.

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
| `make cli-build` | Builds `hmsutil` for current host |
| `make cli-build-all` | Cross-compiles `hmsutil` for all 5 target architectures |
| `make clean` | Cleans build artifacts |
