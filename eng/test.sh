#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Runs test suites selected by traits (16-testing-strategy section 4; suites in eng/test-suites.conf).
#
#   eng/test.sh                               # the unit suite
#   eng/test.sh --suite tools --suite repository
#   eng/test.sh --kind linux                  # the suites for a kind of change
#   eng/test.sh --suite ci --no-build -- --output Detailed
#   eng/test.sh --suite ci --suite exclusive --no-build --repeat 5
#   eng/test.sh --list
#
# --parallel N runs up to N test projects at once (default 2: measured on 18 logical processors, the ci suite takes as long at 2 as at
# 4 or 9, because its longest project bounds it, and uses the least CPU; projects also run their tests in parallel); each project's output goes
# to artifacts/test-logs/ and is printed when the project completes. --parallel 1 runs them one after another with live output.
# A suite that selects isolation=exclusive (the exclusive suite) runs after the other suites, one project at a time.
# --repeat N runs the selected suites N times, stops at the first failing iteration and prints every iteration's duration.
set -euo pipefail
set -f # trait filters contain '*', which must reach the test applications unexpanded

repository="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export AVALONIA_TELEMETRY_OPTOUT=1
# The single opt-in of the OS secret-store tier (16-testing-strategy section 1). Every suite this script runs is routine, so none
# inherits it: a stray value is removed before anything runs. Only eng/os_secret_store_tier.py runs the tier, never this script.
if [ -n "${ARCFORGES_OS_SECRET_STORE_TESTS+x}" ]; then
  unset ARCFORGES_OS_SECRET_STORE_TESTS
  echo "test.sh: removed ARCFORGES_OS_SECRET_STORE_TESTS from the environment: routine suites never reach a real OS secret store (only eng/os_secret_store_tier.py runs the OS secret-store tier)."
fi

configuration=Release
build=1
list=0
parallel=2
repeat=1
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
    --parallel) parallel="$2"; shift 2 ;;
    --repeat) repeat="$2"; shift 2 ;;
    --) shift; passthru=("$@"); break ;;
    -h|--help) sed -n '3,16p' "$0"; exit 0 ;;
    *) echo "test.sh: unknown argument '$1'" >&2; exit 2 ;;
  esac
done
case "$parallel$repeat" in *[!0-9]*) echo "test.sh: --parallel and --repeat need a positive number" >&2; exit 2 ;; esac
if [ "$parallel" -lt 1 ] || [ "$repeat" -lt 1 ]; then echo "test.sh: --parallel and --repeat need a positive number" >&2; exit 2; fi

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

# One work item per suite and project: "suite project", with the suite's filters looked up when it runs.
items=()
for name in "${suites[@]}"; do
  if [ "${suite_projects[$name]}" = '*' ]; then
    projects=("${all_projects[@]}")
  else
    IFS=, read -r -a projects <<< "${suite_projects[$name]}"
  fi
  for project in "${projects[@]}"; do
    [ -f "$repository/tests/$project/$project.csproj" ] || { echo "Suite '$name' names a missing project: $project" >&2; exit 2; }
    items+=("$name $project")
  done
done

if [ "$build" = 1 ]; then
  dotnet build "$repository/ArcForges.slnx" -c "$configuration"
fi
logs="$repository/artifacts/test-logs"
mkdir -p "$logs"
declare -A running=()

# Runs one work item; with a log file its output goes there. Exit code 8 (no test ran) is accepted only where trait filters select a
# subset of a project.
run_item() {
  local name="$1" project="$2" log="${3:-}" filters ignore=()
  read -r -a filters <<< "${suite_filters[$name]}"
  if [ ${#filters[@]} -gt 0 ]; then ignore=(--ignore-exit-code 8); fi
  local command=(dotnet test --project "$repository/tests/$project/$project.csproj" -c "$configuration" --no-build "${ignore[@]}" "${filters[@]}" "${passthru[@]}")
  if [ -n "$log" ]; then "${command[@]}" > "$log" 2>&1; else "${command[@]}"; fi
}

exclusive() { case " ${suite_filters[$1]} " in *" --filter-trait isolation=exclusive "*) return 0 ;; esac; return 1; }

# Waits for one running project, prints its log and records a failure.
collect() {
  local pid status=0 name project start log
  wait -n -p pid || status=$?
  read -r name project start <<< "${running[$pid]}"
  unset "running[$pid]"
  log="$logs/$name-$project.log"
  echo "==> suite $name : $project ${suite_filters[$name]} ($((SECONDS - start)) s, exit $status, log $log)"
  cat "$log"
  if [ "$status" -ne 0 ]; then failures+=("$name/$project (exit $status, log $log)"); fi
}

durations=()
for ((iteration = 1; iteration <= repeat; iteration++)); do
  started=$SECONDS
  failures=()
  serial=()
  if [ "$parallel" -gt 1 ]; then
    # Up to $parallel projects at once, each into its own log; a log is printed when its project completes.
    running=()
    for item in "${items[@]}"; do
      read -r name project <<< "$item"
      if exclusive "$name"; then serial+=("$item"); continue; fi
      while [ ${#running[@]} -ge "$parallel" ]; do collect; done
      run_item "$name" "$project" "$logs/$name-$project.log" &
      running[$!]="$name $project $SECONDS"
    done
    while [ ${#running[@]} -gt 0 ]; do collect; done
  else
    serial=("${items[@]}")
  fi

  # One after another with live output: everything with --parallel 1, otherwise the exclusive suite after the others.
  for item in "${serial[@]}"; do
    read -r name project <<< "$item"
    echo "==> suite $name : $project ${suite_filters[$name]}"
    if ! run_item "$name" "$project"; then failures+=("$name/$project"); fi
  done

  durations+=("$((SECONDS - started)) s")
  if [ "$repeat" -gt 1 ]; then echo "Iteration $iteration/$repeat: $((SECONDS - started)) s, $([ ${#failures[@]} -gt 0 ] && echo failed || echo passed)"; fi
  if [ ${#failures[@]} -gt 0 ]; then
    echo "Failed: ${failures[*]}"
    if [ "$repeat" -gt 1 ]; then echo "Stopped at iteration $iteration of $repeat; durations: ${durations[*]}"; fi
    exit 1
  fi
done

if [ "$repeat" -gt 1 ]; then echo "All $repeat iterations passed; durations: ${durations[*]}"; fi
echo "Suites passed: ${suites[*]}"
