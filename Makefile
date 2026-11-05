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
SUBREPOS := hsm-ncs-firmware hsm-cli hsm-obsidian libgphsm hsm-yocto-offgrid-rpi
YOCTO_DIR := hsm-yocto-offgrid-rpi
FIRMWARE_DIR := hsm-ncs-firmware
CLI_DIR := hsm-cli
OBSIDIAN_DIR := hsm-obsidian
LIBPKCS11_DIR := libgphsm
CLI_BIN := $(CLI_DIR)/bin/gphsm
ALL_REPOS := $(SUBREPOS)

.PHONY: help all sync clone pull fetch push status st diff clean distclean keys \
        worktree-add wt-add worktree-rm wt-rm worktree-list wt-list wt worktree-prune \
        firmware-init firmware-sync firmware-build firmware-build-debug firmware-flash firmware-monitor firmware-clean firmware-distclean \
        cli-build cli-build-all cli-test cli-clean \
        yocto-build-dev yocto-build-prod yocto-bundle yocto-shell yocto-clean \
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
	@echo "Worktree Management (Parallel Development):"
	@echo "  make worktree-list (wt)  List active worktrees across workspace and subrepos"
	@echo "  make worktree-add        Create parallel worktree (NAME=<name> [BRANCH=...] [BASE=...])"
	@echo "  make worktree-rm         Remove worktree (NAME=<name> [FORCE=--force])"
	@echo "  make worktree-prune      Prune stale worktree metadata"
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
	@echo "  make cli-build           Build 'gphsm' for host"
	@echo "  make cli-build-all       Cross-compile 'gphsm' for macOS, Linux, Windows"
	@echo "  make cli-test            Run Go tests for 'gphsm'"
	@echo "  make cli-clean           Clean CLI build outputs"
	@echo ""
	@echo "PKCS#11 Provider Targets:"
	@echo "  make libpkcs11-build     Build libgphsm PKCS#11 shared library (Release)"
	@echo "  make libpkcs11-test      Run CTest unit tests for libgphsm PKCS#11 provider"
	@echo "  make libpkcs11-clean     Clean libgphsm build artifacts"
	@echo ""
	@echo "Yocto OS Targets (hsm-yocto-offgrid-rpi):"
	@echo "  make yocto-build-dev     Build development OS image (hsm-image-dev) via Kas"
	@echo "  make yocto-build-prod    Build air-gapped production OS image (hsm-image-prod) via Kas"
	@echo "  make yocto-bundle        Build signed RAUC A/B update bundle (.raucb)"
	@echo "  make yocto-shell         Launch interactive Kas shell inside build container"
	@echo "  make yocto-clean         Clean Yocto build directory"
	@echo ""
	@echo "Integration Test Targets:"
	@echo "  make integration-test    Run automated integration tests using mock PTY"
	@echo "  make integration-test-hw Run integration tests on physical connected Dongle"
	@echo "=================================================================="

keys:
	@./scripts/generate_keys.sh

clone:
	@echo -e "\033[1;34m==> Checking and cloning missing repositories...\033[0m"
	@for r in $(SUBREPOS); do \
		if [ ! -e "$$r/.git" ]; then \
			echo -e "  \033[1;33mSubrepo $$r not yet cloned or initialized.\033[0m"; \
		else \
			echo -e "  \033[0;32m✓\033[0m Subrepo $$r ready."; \
		fi; \
	done

pull:
	@echo -e "\033[1;34m==> Pulling latest changes across repositories...\033[0m"
	@git pull --ff-only 2>/dev/null || echo -e "  \033[1;33m⚠️ Could not fast-forward root\033[0m"
	@for r in $(ALL_REPOS); do \
		if [ -e "$$r/.git" ]; then \
			echo -e "  \033[1;36mPulling $$r...\033[0m"; \
			git -C "$$r" pull --ff-only 2>/dev/null || echo -e "  \033[1;33m⚠️ Could not fast-forward $$r\033[0m"; \
		fi; \
	done

push:
	@echo -e "\033[1;34m==> Pushing changes across repositories...\033[0m"
	@for r in $(ALL_REPOS); do \
		if [ -e "$$r/.git" ]; then \
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
		if [ -e "$$r/.git" ]; then \
			b=$$(git -C "$$r" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "detached"); \
			st=$$(git -C "$$r" status --porcelain 2>/dev/null | wc -l | tr -d ' '); \
			if [ "$$st" -eq 0 ]; then stat_str="\033[0;32mclean\033[0m"; else stat_str="\033[0;31m$$st modified\033[0m"; fi; \
			printf "%-35s %-20s %-25b\n" "$$r" "$$b" "$$stat_str"; \
		fi; \
	done

diff:
	@for r in $(ALL_REPOS); do \
		if [ -e "$$r/.git" ]; then \
			echo -e "\033[1;34m=== Diff for $$r ===\033[0m"; \
			git -C "$$r" diff; \
		fi; \
	done

sync: clone pull status

# Worktree targets
worktree-list wt-list wt:
	@./scripts/worktree.sh list

worktree-add wt-add:
	@if [ -z "$(NAME)" ]; then \
		echo "Usage: make worktree-add NAME=<worktree-name> [BRANCH=<branch>] [BASE=<base>]"; \
		exit 1; \
	fi
	@./scripts/worktree.sh add $(NAME) $(BRANCH) $(BASE)

worktree-rm wt-rm:
	@if [ -z "$(NAME)" ]; then \
		echo "Usage: make worktree-rm NAME=<worktree-name> [FORCE=--force]"; \
		exit 1; \
	fi
	@./scripts/worktree.sh remove $(NAME) $(FORCE)

worktree-prune:
	@./scripts/worktree.sh prune

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

# Yocto Embedded Linux OS forwards
yocto-build-dev:
	@$(MAKE) -C $(YOCTO_DIR) build-dev

yocto-build-prod:
	@$(MAKE) -C $(YOCTO_DIR) build-prod

yocto-bundle:
	@$(MAKE) -C $(YOCTO_DIR) bundle

yocto-shell:
	@$(MAKE) -C $(YOCTO_DIR) shell

yocto-clean:
	@$(MAKE) -C $(YOCTO_DIR) clean

clean: firmware-clean cli-clean libpkcs11-clean yocto-clean
distclean: firmware-distclean cli-clean libpkcs11-clean
