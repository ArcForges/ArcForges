#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
expected="$(sed -n 's/.*"version": "\([^"]*\)".*/\1/p' "$repo_root/global.json" | head -1)"
actual="$(dotnet --version)"
[[ "$actual" == "$expected" ]] || { echo "Required .NET SDK $expected, resolved $actual." >&2; exit 1; }
echo ".NET SDK $actual verified."
