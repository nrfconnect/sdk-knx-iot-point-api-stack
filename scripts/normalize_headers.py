#!/usr/bin/env python3
"""
One-off tool: normalize copyright/license headers across the repo to the
condensed SPDX style used in api/oc_discovery.c, while:
  - preserving all existing "Copyright (c) YEAR Author" lines verbatim (year/author),
  - preserving any extra non-boilerplate disclaimer text found in the header,
  - adding/bumping a "Copyright (c) YEAR KNX Association" line based on git history
    (2026 takes priority over 2025; never downgrades an existing higher year),
  - leaving files that have no existing copyright header untouched.
Run with --dry-run first to review a diff-like summary before applying.
"""
import re
import subprocess
import sys

BOILERPLATE_SUBSTRINGS = [
    "licensed under the apache license",
    "you may not use this file except in compliance with the license",
    "you may obtain a copy of the license at",
    "http://www.apache.org/licenses/license-2.0",
    "unless required by applicable law or agreed to in writing",
    "distributed under the license is distributed on an",
    "without warranties or conditions of any kind",
    "either express or implied",
    "see the license for the specific",
    "language governing permissions",
    "limitations under the license",
]

COPYRIGHT_RE = re.compile(
    r'^Copyright(?:\s+\(c\))?\s+(\d{4}(?:-\d{4})?(?:\s*,\s*\d{4}(?:-\d{4})?)*)\s*,?\s+(.+?)\s*$', re.IGNORECASE)
SPDX_RE = re.compile(r'^SPDX-License-Identifier:\s*(.+?)\s*$', re.IGNORECASE)


def strip_comment_marker(line):
    s = line.rstrip()
    stripped = s.strip()
    if stripped and all(ch == '*' for ch in stripped):
        return ''
    if stripped.startswith('* '):
        return stripped[2:]
    if stripped == '*':
        return ''
    if stripped.startswith('// '):
        return stripped[3:]
    if stripped == '//':
        return ''
    if stripped.startswith('//'):
        return stripped[2:]
    return stripped


def is_boilerplate(content):
    low = content.lower()
    return any(sub in low for sub in BOILERPLATE_SUBSTRINGS)


def find_header_block(lines):
    """Return (start_idx, end_idx_exclusive, style) or None if no block header found at file start."""
    n = len(lines)
    i = 0
    while i < n and lines[i].strip() == '':
        i += 1
    if i >= n:
        return None
    start = i
    first = lines[i].strip()
    if first.startswith('/*'):
        for j in range(i + 1, min(n, i + 400)):
            if lines[j].strip().endswith('*/'):
                return (start, j + 1, 'block')
        return None
    if first.startswith('//'):
        j = i
        while j < n and lines[j].strip().startswith('//'):
            j += 1
        if j > i:
            return (start, j, 'line')
        return None
    return None


def get_knxa_target_year(filepath):
    try:
        out = subprocess.run(
            ['git', 'log', '--pretty=format:%ae|%ad', '--date=format:%Y', '--', filepath],
            capture_output=True, text=True, check=True, encoding='utf-8', errors='replace'
        ).stdout
    except subprocess.CalledProcessError:
        return None
    years = set()
    for line in out.splitlines():
        if '|' not in line:
            continue
        email, year = line.split('|', 1)
        if email.strip().lower().endswith('@knx.org'):
            years.add(year.strip())
    if '2026' in years:
        return 2026
    if '2025' in years:
        return 2025
    return None


def process_file(path, dry_run=True):
    with open(path, 'rb') as f:
        raw = f.read()
    newline = '\r\n' if b'\r\n' in raw else '\n'
    text = raw.decode('utf-8', errors='replace')
    lines = text.split(newline) if newline in text else text.splitlines()

    block = find_header_block(lines)
    if not block:
        return ('skip-no-header', None)
    start, end, style = block
    content_lines = [strip_comment_marker(l) for l in lines[start + 1:end - 1]] if style == 'block' else \
                     [strip_comment_marker(l) for l in lines[start:end]]

    copyrights = []  # list of [year_str, author]
    extra = []
    spdx_value = 'Apache-2.0'
    found_spdx = False
    for c in content_lines:
        c_stripped = c.strip()
        m = COPYRIGHT_RE.match(c_stripped)
        if m:
            copyrights.append([m.group(1), m.group(2)])
            continue
        m2 = SPDX_RE.match(c_stripped)
        if m2:
            spdx_value = m2.group(1)
            found_spdx = True
            continue
        if c_stripped == '':
            continue
        if is_boilerplate(c_stripped):
            continue
        extra.append(c_stripped)

    if not copyrights:
        return ('skip-no-copyright', None)

    target_year = get_knxa_target_year(path)
    knxa_idx = None
    for idx, (year, author) in enumerate(copyrights):
        if 'knx association' in author.lower():
            knxa_idx = idx
            break

    action = 'format-only'
    if target_year is not None:
        if knxa_idx is None:
            copyrights.append([str(target_year), 'KNX Association'])
            action = f'added-knxa-{target_year}'
        else:
            existing_year_str = copyrights[knxa_idx][0]
            existing_last_year = int(existing_year_str.split('-')[-1])
            if target_year > existing_last_year:
                copyrights[knxa_idx][0] = str(target_year)
                action = f'bumped-knxa-{existing_year_str}-to-{target_year}'
            else:
                action = f'knxa-already-{existing_year_str}'

    new_header_lines = ['/*']
    for year, author in copyrights:
        new_header_lines.append(f' * Copyright (c) {year} {author}')
    new_header_lines.append(' *')
    new_header_lines.append(f' * SPDX-License-Identifier: {spdx_value}')
    if extra:
        new_header_lines.append(' *')
        for e in extra:
            new_header_lines.append(f' * {e}' if e else ' *')
    new_header_lines.append(' */')

    new_lines = lines[:start] + new_header_lines + lines[end:]

    new_text = newline.join(new_lines)
    if not dry_run:
        with open(path, 'wb') as f:
            f.write(new_text.encode('utf-8'))
    extra_note = f' extra-disclaimer-lines={len(extra)}' if extra else ''
    return (action, extra_note)


def main():
    sys.stdout.reconfigure(encoding='utf-8')
    dry_run = '--apply' not in sys.argv
    with open('all_files.txt', encoding='utf-8-sig') as f:
        files = [l.strip() for l in f if l.strip() and 'c-timestamp/' not in l]
    summary = {}
    for path in files:
        try:
            action, note = process_file(path, dry_run=dry_run)
        except Exception as ex:
            action, note = f'ERROR: {ex}', None
        summary.setdefault(action.split('-to-')[0] if 'bumped' in action else action, []).append((path, note))
    for action, entries in sorted(summary.items()):
        print(f'== {action} ({len(entries)}) ==')
        for path, note in entries:
            print(f'  {path}{note or ""}')


if __name__ == '__main__':
    main()
