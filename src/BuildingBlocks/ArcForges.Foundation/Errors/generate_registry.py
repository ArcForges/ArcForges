# SPDX-License-Identifier: AGPL-3.0-only
"""Generate the reason-code policy projection from the immutable C# source registry."""
import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
SOURCE = pathlib.Path(__file__).with_name('ReasonCodes.cs')
OUTPUT = ROOT / 'eng/policy/reason-codes.json'

def render():
    pattern = r'new\("([a-z_]+\.[a-z_]+)", ErrorCategory\.(\w+), RetryMode\.(\w+), EffectCertainty\.(\w+), "([a-z_.]+)"\)'
    rows = re.findall(pattern, SOURCE.read_text(encoding='utf-8-sig'))
    if not rows or len({row[0] for row in rows}) != len(rows):
        raise ValueError('Registry is empty or has duplicate codes')
    records = [dict(zip(('code', 'category', 'retry', 'effect', 'messageKey'), row)) for row in rows]
    return json.dumps({'schemaVersion': 1, 'source': SOURCE.relative_to(ROOT).as_posix(),
                       'authority': 'docs/architecture/contracts/00-operation-catalogue.md#32-the-closed-condition-set',
                       'designCommit': '722e85641c8afb765dafcab5bc0e84d5a22d5a3c',
                       'codes': records}, indent=2) + '\n'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    expected = render()
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding='utf-8-sig') != expected:
            raise ValueError('Reason-code registry is stale; regenerate from C# source')
    else:
        OUTPUT.write_text(expected, encoding='utf-8', newline='\n')
    print(f'Reason-code projection valid: {len(json.loads(expected)["codes"])} codes')

if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
