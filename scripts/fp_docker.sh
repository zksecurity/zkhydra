#!/usr/bin/env bash
# Run a command inside the zkhydra Docker image with this checkout's code.
#
# The image ships all six tools; this mounts the local package, scripts,
# experiment manifest, examples and output dir over the image's copies so that
# relative paths (output/..., scripts/..., fp_experiment/...) mean the same
# thing inside the container as on the host. Output files are chowned back to
# the calling user.
#
# The container gets a fixed memory cap with swap disabled. The FP run uses
# --jobs 1, so one tool runs at a time and this is the per-tool memory limit; a
# tool that exceeds it is killed and counted as failed. The container's /tmp
# is output/.tmp on the host, so tool temp files (Picus writes GBs) use the
# disk that holds output/ rather than Docker's own disk.
#
# Usage:
#   scripts/fp_docker.sh python3 scripts/install_fp_projects.py
#   scripts/fp_docker.sh uv run python -m zkhydra.main fp --dataset output/fp-corpus/dataset/circom ...
#
# Env: ZKHYDRA_IMAGE (default ghcr.io/zksecurity/zkhydra:latest), ZKHYDRA_MEMORY
# (default 24g); DOCKER_CONTEXT is honoured by the docker CLI as usual.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${ZKHYDRA_IMAGE:-ghcr.io/zksecurity/zkhydra:latest}"
MEMORY="${ZKHYDRA_MEMORY:-24g}"
mkdir -p "$REPO/output/.tmp"

if [[ $# -eq 0 ]]; then
  echo "usage: $0 <command...>" >&2
  exit 2
fi

# Quote the command for bash -lc.
CMD="$(printf '%q ' "$@")"
TTY=()
[[ -t 0 && -t 1 ]] && TTY=(-it)

exec docker run --rm "${TTY[@]}" --memory "$MEMORY" --memory-swap "$MEMORY" \
  -v "$REPO/zkhydra:/zkhydra/zkhydra" \
  -v "$REPO/scripts:/zkhydra/scripts" \
  -v "$REPO/fp_experiment:/zkhydra/fp_experiment" \
  -v "$REPO/examples:/zkhydra/examples" \
  -v "$REPO/output:/zkhydra/output" \
  -v "$REPO/output/.tmp:/tmp" \
  -w /zkhydra \
  "$IMAGE" bash -lc "$CMD; rc=\$?; chown -R $(id -u):$(id -g) /zkhydra/output; exit \$rc"
