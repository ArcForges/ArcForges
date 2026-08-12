#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
managed="$(find "$repo_root/src" "$repo_root/tests" -name '*.csproj' -not -path '*/bin/*' -not -path '*/obj/*' | wc -l)"
native="$(find "$repo_root/native" -name '*.vcxproj' | wc -l)"
shims="$(find "$repo_root/native" -mindepth 1 -maxdepth 1 -type d -name '*-abi' | wc -l)"
[[ "$managed" -eq 166 && "$native" -eq 5 && "$shims" -eq 6 ]] || {
  echo "Layout mismatch: managed=$managed native=$native shims=$shims" >&2; exit 1;
}
[[ ! -e "$repo_root/vcpkg.json" ]] || { echo 'Root vcpkg.json is forbidden.' >&2; exit 1; }
echo 'Repository layout verified.'
