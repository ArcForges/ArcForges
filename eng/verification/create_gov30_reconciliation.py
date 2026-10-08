# SPDX-License-Identifier: AGPL-3.0-only
"""Regenerate the GOV.30 osx directory retirement in the reconciliation inventory and its source count.

GOV.30 (P2-023) removes the sixteen DesktopPlatform osx runtime directory rows (all present: false) from
eng/policy/reconciliation/directories.json, and sets counts.directories in source.json to the remaining row count.
Every other row and count is kept. reconciliation.py requires counts.directories to equal the row count.

The pinned set is the sixteen rows as they stand on main (f833de34). NAT.32 retires two of them (the Native.Pdf
osx rows) and merges first, so a rebase of GOV.30 onto NAT.32 finds fourteen pinned rows present. Pinned rows
already absent from the base are accepted. Every pinned row that is present must be an absent-directory osx
runtime row (present: false), and the removal is refused if any other DesktopPlatform osx runtime row would remain.

The script is the in-repo generator for these two RES-desktopplatform-policy-data files; it never hand-edits them.
It is idempotent: a rerun after the rows are gone rewrites identical bytes.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
DIRECTORIES = ROOT / "eng/policy/reconciliation/directories.json"
SOURCE = ROOT / "eng/policy/reconciliation/source.json"
OWNER = "DesktopPlatform"
REMOVED = (
    "src/DesktopHelpers/ArcForges.ContentSandbox.Runtime.osx-arm64",
    "src/DesktopHelpers/ArcForges.ContentSandbox.Runtime.osx-x64",
    "src/Native/ArcForges.Native.Colour.Runtime.osx-arm64",
    "src/Native/ArcForges.Native.Colour.Runtime.osx-x64",
    "src/Native/ArcForges.Native.Graphics.Runtime.osx-arm64",
    "src/Native/ArcForges.Native.Graphics.Runtime.osx-x64",
    "src/Native/ArcForges.Native.Image.Runtime.osx-arm64",
    "src/Native/ArcForges.Native.Image.Runtime.osx-x64",
    "src/Native/ArcForges.Native.Instruments.Runtime.osx-arm64",
    "src/Native/ArcForges.Native.Instruments.Runtime.osx-x64",
    "src/Native/ArcForges.Native.Media.Runtime.osx-arm64",
    "src/Native/ArcForges.Native.Media.Runtime.osx-x64",
    "src/Native/ArcForges.Native.Otio.Runtime.osx-arm64",
    "src/Native/ArcForges.Native.Otio.Runtime.osx-x64",
    "src/Native/ArcForges.Native.Pdf.Runtime.osx-arm64",
    "src/Native/ArcForges.Native.Pdf.Runtime.osx-x64",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def remove_pinned_rows(rows: list) -> tuple:
    """Return (kept rows, number of pinned rows removed). Pure: the caller decides what to write."""
    targets = [row for row in rows if row["owner"] == OWNER and row["path"] in REMOVED]
    for row in targets:
        require(row["present"] is False and ".Runtime.osx-" in row["path"], "Unexpected row selected: " + row["path"])
    kept = [row for row in rows if not (row["owner"] == OWNER and row["path"] in REMOVED)]
    require(not any(OWNER == row["owner"] and "Runtime.osx-" in row["path"] for row in kept),
            "A DesktopPlatform osx runtime directory row remains after the pinned removal; refusing to edit.")
    return kept, len(targets)


def main() -> None:
    rows = json.loads(DIRECTORIES.read_text(encoding="utf-8"))
    kept, removed = remove_pinned_rows(rows)

    source = json.loads(SOURCE.read_text(encoding="utf-8"))
    source["counts"]["directories"] = len(kept)
    DIRECTORIES.write_text(json.dumps(kept, indent=2) + "\n", encoding="utf-8", newline="\n")
    SOURCE.write_text(json.dumps(source, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"Removed {removed} pinned osx directory rows; directories count is {len(kept)}.")


if __name__ == "__main__":
    sys.exit(main())
