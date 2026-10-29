#!/usr/bin/env bash
# Build the swapsha-core npm tarball that swapsha-backend depends on.
#
# The Solidity artifacts in out/ need Foundry to rebuild. SwapSha does not
# change the contracts, so they are taken byte for byte from the published
# upstream boltz-core release this fork is pinned to.
#
# Usage: ./scripts/build-release.sh    -> boltz-core-<version>.tgz in repo root
set -euo pipefail
cd "$(dirname "$0")/.."

UPSTREAM=5.0.0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

( cd "$tmp" && npm pack "boltz-core@$UPSTREAM" --silent >/dev/null && tar xzf "boltz-core-$UPSTREAM.tgz" )
rm -rf out && cp -R "$tmp/package/out" out

rm -rf dist
npx tsc
npm pack --silent
echo "Built $(ls boltz-core-*.tgz | tail -1)"
