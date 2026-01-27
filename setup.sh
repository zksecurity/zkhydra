#!/usr/bin/env bash
set -euo pipefail

# Pretty output helpers
bold="\033[1m"; green="\033[32m"; red="\033[31m"; blue="\033[34m"; yellow="\033[33m"; reset="\033[0m"
info()  { echo -e "${blue}${bold}==>${reset} $*"; }
ok()    { echo -e "${green}${bold}✔${reset} $*"; }
warn()  { echo -e "${yellow}${bold}!${reset} $*"; }
fail()  { echo -e "${red}${bold}✖${reset} $*"; }

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
CIRCOM_DIR="$ROOT_DIR/setup/circom"
UTIL_DIR="$ROOT_DIR/setup/utils"

run_step() {
  local name="$1"; shift
  local script="$1"; shift
  if [[ ! -f "$script" ]]; then
    warn "$name: script not found at $script (skipping)"
    return 0
  fi
  info "Installing $name"
  pushd "$(dirname "$script")" >/dev/null
  if bash "$(basename "$script")"; then
    popd >/dev/null
    ok "$name installed"
  else
    popd >/dev/null
    fail "$name failed"
    return 1
  fi
}

main() {
  info "Starting zkhydra tool setup"

  # Ensure we’re running from the script’s directory
  cd "$(dirname "$0")"

  # Initialize and update git submodules
  info "Initializing and updating Git submodules..."
  git submodule update --init --recursive
  info "Git submodules initialized and updated successfully."

  # Install uv for Python package management
  if ! command -v uv &> /dev/null; then
      info "Installing uv for Python package management..."
      curl -LsSf https://astral.sh/uv/install.sh | sh
  fi

  # Prereqs
  run_step "Rust toolchain" "$UTIL_DIR/rust.sh" || true

  # Circom base (if provided)
  run_step "circom" "$CIRCOM_DIR/circom.sh" || true

  # Individual tools
  ## Circom
  run_step "circom_civer" "$UTIL_DIR/circom_civer.sh" || true
  run_step "circomspect" "$CIRCOM_DIR/circomspect.sh" || true
  run_step "ecneproject" "$CIRCOM_DIR/ecneproject.sh" || true
  run_step "picus" "$CIRCOM_DIR/picus.sh" || true
  run_step "zkfuzz" "$CIRCOM_DIR/zkfuzz.sh" || true
  ## Pil
  # run_step "pilspector" "$PIL_DIR/pilspector.sh" || true

  ok "All setup steps completed (some steps may have been skipped if scripts were missing)."
}

main "$@"
