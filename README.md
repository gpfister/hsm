# ncs-nrf52840dongle-kms

Multi-repo workspace for building a Hardware Security Module (HSM) on an **nRF52840 USB Dongle** (`PCA10059`), compatible with the **YubiHSM 2 API**, featuring dual-stage secure boot and dual USB CDC-ACM serial interfaces.

## Sub-Repositories

- **[`nrf52840-hms-firmware/`](file:///Users/gpfister/Development/Projects/gpfister/ncs-nrf52840dongle-kms/nrf52840-hms-firmware)**: NCS/Zephyr firmware workspace with dual-stage B0 + MCUboot secure boot, dual USB CDC ACM (console & HSM), RGB status LED, and pure HSM logic library.
- **[`nrf52840-hms-cli/`](file:///Users/gpfister/Development/Projects/gpfister/ncs-nrf52840dongle-kms/nrf52840-hms-cli)**: Cross-platform Go CLI & TUI executable `hmsutil` with `firmware update`, `firmware info`, BubbleTea interactive dashboard, and automated tests.
- **[`nrf52840-hms-obsidian/`](file:///Users/gpfister/Development/Projects/gpfister/ncs-nrf52840dongle-kms/nrf52840-hms-obsidian)**: Project-wide documentation vault with architecture specifications, protocols, and sessions.

## Quick Start

```bash
# Display help and targets
make help

# Initialize keys
make keys

# View workspace status
make status
```
