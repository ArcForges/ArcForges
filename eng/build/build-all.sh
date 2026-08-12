#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

./eng/build/check-sdk.sh
./eng/build/check-layout.sh
dotnet restore ArcForges.slnx --locked-mode
dotnet build ArcForges.slnx -c Release --no-restore
dotnet test ArcForges.slnx -c Release --no-build --no-restore
cmake --preset linux-clang-x64
cmake --build --preset linux-clang-x64-release
ctest --preset linux-clang-x64
