# ncs-nrf52840dongle-kms

Multi-repo workspace for building a Hardware Security Module (HSM) on an **nRF52840 USB Dongle** (`PCA10059`), compatible with the **YubiHSM 2 API**, featuring dual-stage secure boot and dual USB CDC-ACM serial interfaces.

## Sub-Repositories

- **[`nrf52840-hsm-firmware/`](file:///Users/gpfister/Development/Projects/gpfister/nrf52840-hsm/nrf52840-hsm-firmware)**: NCS/Zephyr firmware workspace with dual-stage B0 + MCUboot secure boot, dual USB CDC ACM (console & HSM), RGB status LED, and pure HSM logic library.
- **[`nrf52840-hsm-cli/`](file:///Users/gpfister/Development/Projects/gpfister/nrf52840-hsm/nrf52840-hsm-cli)**: Cross-platform Go CLI & TUI executable `hsmutil` with `firmware update`, `firmware info`, BubbleTea interactive dashboard, and automated tests.
- **[`nrf52840-hsm-obsidian/`](file:///Users/gpfister/Development/Projects/gpfister/nrf52840-hsm/nrf52840-hsm-obsidian)**: Project-wide documentation vault with architecture specifications, protocols, and sessions.

## Quick Start

```bash
# Display help and targets
make help

# Initialize keys
make keys

# View workspace status
make status
```
