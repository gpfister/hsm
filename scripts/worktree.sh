#!/usr/bin/env bash
# ==============================================================================
# scripts/worktree.sh
# Multi-repository git worktree management for ncs-nrf52840dongle-kms
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORKTREES_DIR="${WORKSPACE_ROOT}/.worktrees"
SUBREPOS=(nrf52840-hsm-firmware nrf52840-hsm-cli nrf52840-hsm-obsidian nrf52840-hsm-libpkcs11 rpi-z2w-yocto-hsm)

# Terminal colors
BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
RED="\033[0;31m"
RESET="\033[0m"

usage() {
    echo -e "${BOLD}Usage:${RESET} $0 <command> [arguments]"
    echo ""
    echo -e "${BOLD}Commands:${RESET}"
    echo "  add <name> [branch] [base]   Create a new parallel worktree across root and subrepos"
    echo "  remove <name> [--force]       Remove an existing worktree across root and subrepos"
    echo "  list                         List active worktrees across root and subrepos"
    echo "  prune                        Prune stale worktree administrative files"
    echo ""
    echo -e "${BOLD}Examples:${RESET}"
    echo "  $0 add feature-p256          # Creates .worktrees/feature-p256 on branch feature-p256 from main"
    echo "  $0 add bugfix-cdc bugfix-123 # Creates .worktrees/bugfix-cdc on branch bugfix-123 from main"
    echo "  $0 list                      # Show all active worktrees"
    echo "  $0 remove feature-p256       # Tear down .worktrees/feature-p256 and clean up git states"
    exit 1
}

# Determine default base branch (main or master)
get_default_base() {
    local repo_dir="$1"
    if git -C "${repo_dir}" show-ref --verify --quiet refs/heads/main; then
        echo "main"
    elif git -C "${repo_dir}" show-ref --verify --quiet refs/heads/master; then
        echo "master"
    else
        git -C "${repo_dir}" rev-parse --abbrev-ref HEAD
    fi
}

cmd_add() {
    local name="${1:-}"
    local branch="${2:-${name}}"
    local base="${3:-}"

    if [ -z "${name}" ]; then
        echo -e "${RED}[ERROR] Worktree name is required.${RESET}"
        usage
    fi

    local wt_path="${WORKTREES_DIR}/${name}"

    if [ -d "${wt_path}" ]; then
        echo -e "${RED}[ERROR] Target directory already exists: ${wt_path}${RESET}"
        exit 1
    fi

    mkdir -p "${WORKTREES_DIR}"

    local root_base="${base}"
    if [ -z "${root_base}" ]; then
        root_base="$(get_default_base "${WORKSPACE_ROOT}")"
    fi

    echo -e "${BLUE}==> Creating root worktree for '${name}' (branch: ${branch}, base: ${root_base})...${RESET}"
    if git -C "${WORKSPACE_ROOT}" show-ref --verify --quiet "refs/heads/${branch}"; then
        echo -e "    Branch '${branch}' exists in root, checking out..."
        git -C "${WORKSPACE_ROOT}" worktree add "${wt_path}" "${branch}"
    else
        echo -e "    Branch '${branch}' not found in root, creating from '${root_base}'..."
        git -C "${WORKSPACE_ROOT}" worktree add -b "${branch}" "${wt_path}" "${root_base}"
    fi

    # Set up subrepositories
    for r in "${SUBREPOS[@]}"; do
        local r_src="${WORKSPACE_ROOT}/${r}"
        local r_dst="${wt_path}/${r}"

        if [ ! -d "${r_src}/.git" ] && [ ! -f "${r_src}/.git" ]; then
            echo -e "${YELLOW}    [SKIP] Subrepo '${r}' is not a valid git repository.${RESET}"
            continue
        fi

        local sub_base="${base}"
        if [ -z "${sub_base}" ]; then
            sub_base="$(get_default_base "${r_src}")"
        fi

        echo -e "${BLUE}==> Creating worktree for '${r}' in '${name}' (branch: ${branch})...${RESET}"
        if git -C "${r_src}" show-ref --verify --quiet "refs/heads/${branch}"; then
            echo -e "    Branch '${branch}' exists in '${r}', checking out..."
            git -C "${r_src}" worktree add "${r_dst}" "${branch}"
        else
            echo -e "    Branch '${branch}' not found in '${r}', creating from '${sub_base}'..."
            git -C "${r_src}" worktree add -b "${branch}" "${r_dst}" "${sub_base}"
        fi
    done

    # Symlink non-committed root assets (keys, .agents)
    if [ -d "${WORKSPACE_ROOT}/keys" ]; then
        mkdir -p "${wt_path}/keys"
        for keyfile in "${WORKSPACE_ROOT}/keys"/*; do
            if [ -f "${keyfile}" ]; then
                local kbase="$(basename "${keyfile}")"
                if [ ! -e "${wt_path}/keys/${kbase}" ]; then
                    ln -sf "${keyfile}" "${wt_path}/keys/${kbase}"
                fi
            fi
        done
        echo -e "${GREEN}    ✓ Linked cryptographic keys to worktree.${RESET}"
    fi

    if [ -d "${WORKSPACE_ROOT}/.agents" ] && [ ! -e "${wt_path}/.agents" ]; then
        ln -sf "${WORKSPACE_ROOT}/.agents" "${wt_path}/.agents"
        echo -e "${GREEN}    ✓ Linked .agents configuration to worktree.${RESET}"
    fi

    echo ""
    echo -e "${GREEN}${BOLD}✓ Parallel worktree ready at:${RESET} ${wt_path}"
    echo -e "  To begin working in parallel, run:"
    echo -e "    ${BOLD}cd ${wt_path}${RESET}"
}

cmd_remove() {
    local name="${1:-}"
    local force_arg="${2:-}"
    local git_force=""

    if [ -z "${name}" ]; then
        echo -e "${RED}[ERROR] Worktree name is required.${RESET}"
        usage
    fi

    if [ "${force_arg}" = "--force" ] || [ "${force_arg}" = "-f" ]; then
        git_force="--force"
    fi

    local wt_path="${WORKTREES_DIR}/${name}"
    if [ ! -d "${wt_path}" ] && [ -d "${name}" ]; then
        wt_path="${name}"
    fi

    echo -e "${BLUE}==> Removing worktrees for '${name}'...${RESET}"

    # Remove subrepo worktrees first
    for r in "${SUBREPOS[@]}"; do
        local r_src="${WORKSPACE_ROOT}/${r}"
        local r_dst="${wt_path}/${r}"

        if [ -d "${r_dst}" ] || [ -f "${r_dst}/.git" ]; then
            echo -e "    Removing subrepo worktree: ${r}..."
            git -C "${r_src}" worktree remove ${git_force} "${r_dst}" 2>/dev/null || true
            git -C "${r_src}" worktree prune 2>/dev/null || true
        fi
    done

    # Remove root worktree
    if [ -d "${wt_path}" ]; then
        echo -e "    Removing root worktree..."
        git -C "${WORKSPACE_ROOT}" worktree remove ${git_force} "${wt_path}" 2>/dev/null || true
        git -C "${WORKSPACE_ROOT}" worktree prune 2>/dev/null || true
    fi

    # Clean up residual directory if symlinks or untracked files remain
    if [ -d "${wt_path}" ]; then
        echo -e "    Cleaning up remaining directory ${wt_path}..."
        rm -rf "${wt_path}"
    fi

    # Delete branch if created for test/feature? No, keep branches unless explicitly asked, standard git behavior.

    echo -e "${GREEN}${BOLD}✓ Worktree '${name}' removed successfully.${RESET}"
}

cmd_list() {
    echo -e "${BLUE}${BOLD}==> Active Workspace Worktrees${RESET}"
    echo ""
    echo -e "${BOLD}Root Repository:${RESET}"
    git -C "${WORKSPACE_ROOT}" worktree list
    echo ""

    for r in "${SUBREPOS[@]}"; do
        local r_src="${WORKSPACE_ROOT}/${r}"
        if [ -d "${r_src}/.git" ] || [ -f "${r_src}/.git" ]; then
            echo -e "${BOLD}Sub-repository ${r}:${RESET}"
            git -C "${r_src}" worktree list
            echo ""
        fi
    done
}

cmd_prune() {
    echo -e "${BLUE}==> Pruning stale worktrees across repositories...${RESET}"
    git -C "${WORKSPACE_ROOT}" worktree prune -v
    for r in "${SUBREPOS[@]}"; do
        local r_src="${WORKSPACE_ROOT}/${r}"
        if [ -d "${r_src}/.git" ] || [ -f "${r_src}/.git" ]; then
            echo -e "    Pruning ${r}..."
            git -C "${r_src}" worktree prune -v
        fi
    done
    echo -e "${GREEN}✓ Prune complete.${RESET}"
}

# Main command dispatcher
ACTION="${1:-}"
shift || true

case "${ACTION}" in
    add)
        cmd_add "$@"
        ;;
    remove|rm)
        cmd_remove "$@"
        ;;
    list|ls)
        cmd_list
        ;;
    prune)
        cmd_prune
        ;;
    help|--help|-h|"")
        usage
        ;;
    *)
        echo -e "${RED}[ERROR] Unknown command: ${ACTION}${RESET}"
        usage
        ;;
esac
