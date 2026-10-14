#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Runs test suites selected by traits (16-testing-strategy section 4; suites in eng/test-suites.conf).
#
#   eng/test.sh                               # the unit suite
#   eng/test.sh --suite tools --suite repository
#   eng/test.sh --kind linux                  # the suites for a kind of change
#   eng/test.sh --suite ci --no-build -- --output Detailed
#   eng/test.sh --list
set -euo pipefail
set -f # trait filters contain '*', which must reach the test applications unexpanded

repository="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export AVALONIA_TELEMETRY_OPTOUT=1

configuration=Release
build=1
list=0
kind=
selected=()
passthru=()
while [ $# -gt 0 ]; do
  case "$1" in
    --suite) selected+=("${2//,/ }"); shift 2 ;;
    --kind) kind="$2"; shift 2 ;;
    --configuration|-c) configuration="$2"; shift 2 ;;
    --no-build) build=0; shift ;;
    --list) list=1; shift ;;
    --) shift; passthru=("$@"); break ;;
    -h|--help) sed -n '3,9p' "$0"; exit 0 ;;
    *) echo "test.sh: unknown argument '$1'" >&2; exit 2 ;;
  esac
done

declare -A suite_projects=() suite_filters=() kinds=()
suite_names=()
kind_names=()
while read -r type name projects rest || [ -n "${type:-}" ]; do
  case "${type:-}" in
    ''|\#*) continue ;;
    suite) suite_projects[$name]="$projects"; suite_filters[$name]="${rest%%#*}"; suite_names+=("$name") ;;
    kind) kinds[$name]="$projects ${rest%%#*}"; kind_names+=("$name") ;;
    *) echo "test-suites.conf: unknown entry '$type'" >&2; exit 2 ;;
  esac
done < "$repository/eng/test-suites.conf"

all_projects=()
set +f
for project in "$repository"/tests/*/*.Tests.csproj; do
  if [ -f "$project" ]; then all_projects+=("$(basename "$project" .csproj)"); fi
done
set -f

if [ "$list" = 1 ]; then
  for name in "${suite_names[@]}"; do
    printf 'suite %-13s %-28s %s\n' "$name" "${suite_projects[$name]}" "${suite_filters[$name]}"
  done
  for name in "${kind_names[@]}"; do printf 'kind  %-13s %s\n' "$name" "${kinds[$name]}"; done
  echo "projects: ${all_projects[*]}"
  exit 0
fi

if [ -n "$kind" ]; then
  if [ -z "${kinds[$kind]+x}" ]; then echo "Unknown kind '$kind'. Known: ${kind_names[*]}" >&2; exit 2; fi
  selected+=(${kinds[$kind]})
fi
[ ${#selected[@]} -gt 0 ] || selected=(unit)
suites=()
for name in ${selected[@]}; do
  if [ -z "${suite_projects[$name]+x}" ]; then echo "Unknown suite '$name'. Known: ${suite_names[*]}" >&2; exit 2; fi
  case " ${suites[*]} " in *" $name "*) ;; *) suites+=("$name") ;; esac
done

if [ "$build" = 1 ]; then
  dotnet build "$repository/ArcForges.slnx" -c "$configuration"
fi

failures=()
for name in "${suites[@]}"; do
  if [ "${suite_projects[$name]}" = '*' ]; then
    projects=("${all_projects[@]}")
  else
    IFS=, read -r -a projects <<< "${suite_projects[$name]}"
  fi
  read -r -a filters <<< "${suite_filters[$name]}"
  for project in "${projects[@]}"; do
    path="$repository/tests/$project/$project.csproj"
    [ -f "$path" ] || { echo "Suite '$name' names a missing project: $project" >&2; exit 2; }
    echo "==> suite $name : $project ${filters[*]}"
    # Exit code 8 (no test ran) is accepted only where trait filters select a subset of a project.
    ignore=()
    if [ ${#filters[@]} -gt 0 ]; then ignore=(--ignore-exit-code 8); fi
    if ! dotnet test --project "$path" -c "$configuration" --no-build "${ignore[@]}" "${filters[@]}" "${passthru[@]}"; then
      failures+=("$name/$project")
    fi
  done
done

if [ ${#failures[@]} -gt 0 ]; then
  echo "Failed: ${failures[*]}"
  exit 1
fi
echo "Suites passed: ${suites[*]}"
