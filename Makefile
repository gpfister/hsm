# ==============================================================================
# ncs-nrf52840dongle-kms Workspace Makefile
# Multi-repository orchestration and lifecycle management
# ==============================================================================

SHELL := /bin/bash

# Configuration
GITHUB_ORG ?= gpfister
GIT_PROTOCOL ?= ssh

ifeq ($(GIT_PROTOCOL),ssh)
GIT_BASE_URL := git@github.com:$(GITHUB_ORG)
else
GIT_BASE_URL := https://github.com/$(GITHUB_ORG)
endif

# Sub-repositories
SUBREPOS := nrf52840-hsm-firmware nrf52840-hsm-cli nrf52840-hsm-obsidian nrf52840-hsm-libpkcs11
FIRMWARE_DIR := nrf52840-hsm-firmware
CLI_DIR := nrf52840-hsm-cli
OBSIDIAN_DIR := nrf52840-hsm-obsidian
LIBPKCS11_DIR := nrf52840-hsm-libpkcs11
CLI_BIN := $(CLI_DIR)/bin/hsmutil
PLUGIN_DIR := .agents/plugins
PLUGIN_NAMES := agentic-coding-plugin agentic-investigate-plugin agentic-monitoring-plugin agentic-triage-plugin
PLUGINS := $(addprefix $(PLUGIN_DIR)/, $(PLUGIN_NAMES))
ALL_REPOS := $(SUBREPOS) $(PLUGINS)

.PHONY: help all sync clone pull fetch push status st diff clean distclean keys \
        firmware-init firmware-sync firmware-build firmware-build-debug firmware-flash firmware-monitor firmware-clean firmware-distclean \
        cli-build cli-build-all cli-test cli-clean \
        libpkcs11-build libpkcs11-test libpkcs11-clean \
        integration-test integration-test-hw

help:
	@echo "=================================================================="
	@echo "             nRF52840 HSM Dongle Workspace Manager               "
	@echo "=================================================================="
	@echo "Multi-Repo Management:"
	@echo "  make sync                Sync all repos & plugins, pull updates, show status"
	@echo "  make clone               Clone missing sub-repos and plugins"
	@echo "  make pull                Pull latest changes (fast-forward) across all repos"
	@echo "  make push                Push current branches across all repos"
	@echo "  make status (st)         Show branch and status across all repos"
	@echo "  make diff                Show diff across all repos"
	@echo ""
	@echo "Keys:"
	@echo "  make keys                Generate ECDSA P-256 keys in keys/ if missing"
	@echo ""
	@echo "Firmware Targets:"
	@echo "  make firmware-init       Initialize firmware dependencies (uv sync)"
	@echo "  make firmware-sync       Sync Zephyr modules (west update -o depth=1)"
	@echo "  make firmware-build      Build production firmware (sysbuild, dual-stage, signed)"
	@echo "  make firmware-build-debug Build debug firmware (DEBUG log level)"
	@echo "  make firmware-flash      Flash firmware to Dongle using JLink 802007333"
	@echo "  make firmware-monitor    Open USB console serial port"
	@echo "  make firmware-clean      Clean firmware build outputs"
	@echo "  make firmware-distclean  Distclean firmware (builds, Zephyr modules, .venv)"
	@echo ""
	@echo "CLI Targets:"
	@echo "  make cli-build           Build 'hsmutil' for host"
	@echo "  make cli-build-all       Cross-compile 'hsmutil' for macOS, Linux, Windows"
	@echo "  make cli-test            Run Go tests for 'hsmutil'"
	@echo "  make cli-clean           Clean CLI build outputs"
	@echo ""
	@echo "PKCS#11 Provider Targets:"
	@echo "  make libpkcs11-build     Build PKCS#11 shared library (Release)"
	@echo "  make libpkcs11-test      Run CTest unit tests for PKCS#11 provider"
	@echo "  make libpkcs11-clean     Clean PKCS#11 build artifacts"
	@echo ""
	@echo "Integration Test Targets:"
	@echo "  make integration-test    Run automated integration tests using mock PTY"
	@echo "  make integration-test-hw Run integration tests on physical connected Dongle"
	@echo "=================================================================="

keys:
	@./scripts/generate_keys.sh

clone:
	@echo -e "\033[1;34m==> Checking and cloning missing repositories & plugins...\033[0m"
	@mkdir -p $(PLUGIN_DIR)
	@for p in $(PLUGIN_NAMES); do \
		target="$(PLUGIN_DIR)/$$p"; \
		if [ ! -d "$$target/.git" ]; then \
			echo -e "  \033[1;33mCloning plugin $$p from $(GIT_BASE_URL)/$$p.git into $$target...\033[0m"; \
			git clone "$(GIT_BASE_URL)/$$p.git" "$$target" || echo "⚠️ Failed to clone $$p"; \
		else \
			echo -e "  \033[0;32m✓\033[0m Plugin $$p ready."; \
		fi; \
	done
	@for r in $(SUBREPOS); do \
		if [ ! -d "$$r/.git" ]; then \
			echo -e "  \033[1;33mSubrepo $$r not yet cloned or initialized.\033[0m"; \
		else \
			echo -e "  \033[0;32m✓\033[0m Subrepo $$r ready."; \
		fi; \
	done

pull:
	@echo -e "\033[1;34m==> Pulling latest changes across repositories...\033[0m"
	@git pull --ff-only 2>/dev/null || echo -e "  \033[1;33m⚠️ Could not fast-forward root\033[0m"
	@for r in $(ALL_REPOS); do \
		if [ -d "$$r/.git" ]; then \
			echo -e "  \033[1;36mPulling $$r...\033[0m"; \
			git -C "$$r" pull --ff-only 2>/dev/null || echo -e "  \033[1;33m⚠️ Could not fast-forward $$r\033[0m"; \
		fi; \
	done

push:
	@echo -e "\033[1;34m==> Pushing changes across repositories...\033[0m"
	@for r in $(ALL_REPOS); do \
		if [ -d "$$r/.git" ]; then \
			branch=$$(git -C "$$r" rev-parse --abbrev-ref HEAD 2>/dev/null); \
			if [ -n "$$branch" ] && [ "$$branch" != "HEAD" ]; then \
				echo -e "  \033[1;36mPushing $$r ($$branch)...\033[0m"; \
				git -C "$$r" push origin "$$branch" 2>/dev/null || echo -e "  \033[1;33m⚠️ Remote push skipped/failed for $$r\033[0m"; \
			fi; \
		fi; \
	done
	@git push origin HEAD 2>/dev/null || true

status st:
	@echo -e "\033[1;34m==> Workspace Git Status Overview\033[0m"
	@printf "%-35s %-20s %-15s\n" "Repository" "Branch" "Status"
	@printf "%-35s %-20s %-15s\n" "-----------------------------------" "--------------------" "---------------"
	@root_branch=$$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "detached"); \
	root_status=$$(git status --porcelain 2>/dev/null | wc -l | tr -d ' '); \
	if [ "$$root_status" -eq 0 ]; then rstat="\033[0;32mclean\033[0m"; else rstat="\033[0;31m$$root_status modified\033[0m"; fi; \
	printf "%-35s %-20s %-25b\n" "root (workspace)" "$$root_branch" "$$rstat"
	@for r in $(ALL_REPOS); do \
		if [ -d "$$r/.git" ]; then \
			b=$$(git -C "$$r" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "detached"); \
			st=$$(git -C "$$r" status --porcelain 2>/dev/null | wc -l | tr -d ' '); \
			if [ "$$st" -eq 0 ]; then stat_str="\033[0;32mclean\033[0m"; else stat_str="\033[0;31m$$st modified\033[0m"; fi; \
			printf "%-35s %-20s %-25b\n" "$$r" "$$b" "$$stat_str"; \
		fi; \
	done

diff:
	@for r in $(ALL_REPOS); do \
		if [ -d "$$r/.git" ]; then \
			echo -e "\033[1;34m=== Diff for $$r ===\033[0m"; \
			git -C "$$r" diff; \
		fi; \
	done

sync: clone pull status

# Firmware forwards
firmware-init: keys
	@$(MAKE) -C $(FIRMWARE_DIR) init

firmware-sync:
	@$(MAKE) -C $(FIRMWARE_DIR) sync

firmware-build: keys
	@$(MAKE) -C $(FIRMWARE_DIR) build-prod

firmware-build-debug: keys
	@$(MAKE) -C $(FIRMWARE_DIR) build-debug

firmware-flash:
	@$(MAKE) -C $(FIRMWARE_DIR) flash

firmware-monitor:
	@$(MAKE) -C $(FIRMWARE_DIR) monitor

firmware-clean:
	@$(MAKE) -C $(FIRMWARE_DIR) clean

firmware-distclean:
	@$(MAKE) -C $(FIRMWARE_DIR) distclean

# CLI forwards
cli-build:
	@$(MAKE) -C $(CLI_DIR) build

cli-build-all:
	@$(MAKE) -C $(CLI_DIR) build-all

cli-test:
	@$(MAKE) -C $(CLI_DIR) test

cli-clean:
	@$(MAKE) -C $(CLI_DIR) clean

# PKCS#11 Provider forwards
libpkcs11-build:
	@$(MAKE) -C $(LIBPKCS11_DIR) build

libpkcs11-test:
	@$(MAKE) -C $(LIBPKCS11_DIR) test

libpkcs11-clean:
	@$(MAKE) -C $(LIBPKCS11_DIR) clean

# Integration test harness
integration-test:
	@./scripts/run_integration_tests.sh

integration-test-hw:
	@TARGET_HW=1 ./scripts/run_integration_tests.sh

clean: firmware-clean cli-clean libpkcs11-clean
distclean: firmware-distclean cli-clean libpkcs11-clean
