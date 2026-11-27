#!/usr/bin/env python3
#
# Copyright (c) 2026 KNX Association
#
# SPDX-License-Identifier: Apache-2.0
#
# This file was created with the assistance of AI tools.
# Copyright 2026 KNXA (to the extent protectable under applicable law)
#
"""
Check commit message subjects against the Conventional Commits format
described in CONTRIBUTING.md ("Commit messages").

Usage:
  check_commit_messages.py --range <base>..<head>   check every non-merge commit in the range (CI)
  check_commit_messages.py --file <path>            check one message file (git commit-msg hook)

Exit status 0 when all subjects conform, 1 otherwise.
"""
import argparse
import re
import subprocess
import sys

TYPES = ("feat", "fix", "docs", "test", "ci", "build", "refactor", "perf", "style", "chore", "revert")

# <type>(<scope>)!: <description>  -- scope and "!" are optional
SUBJECT_RE = re.compile(
    r"^(?:" + "|".join(TYPES) + r")"
    r"(?:\([a-z0-9][a-z0-9._/-]*\))?"
    r"!?"
    r": \S.*$"
)

MAX_SUBJECT_LENGTH = 100


def check_subject(subject):
    """Return an error string, or None when the subject conforms."""
    if not SUBJECT_RE.match(subject):
        return "not '<type>(<scope>): <description>', allowed types: " + ", ".join(TYPES)
    if len(subject) > MAX_SUBJECT_LENGTH:
        return f"longer than {MAX_SUBJECT_LENGTH} characters"
    return None


def subjects_in_range(rev_range):
    out = subprocess.run(
        ["git", "log", "--no-merges", "--format=%h%x00%s", rev_range],
        check=True, capture_output=True, text=True,
    ).stdout
    return [tuple(line.split("\0", 1)) for line in out.splitlines() if line]


def subject_from_file(path):
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if line and not line.startswith("#"):
                return line
    return ""


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--range", help="git revision range, e.g. origin/main..HEAD")
    group.add_argument("--file", help="commit message file (commit-msg hook)")
    args = parser.parse_args()

    if args.range:
        commits = subjects_in_range(args.range)
    else:
        commits = [("message", subject_from_file(args.file))]

    failures = 0
    for ref, subject in commits:
        error = check_subject(subject)
        if error:
            failures += 1
            print(f"FAIL {ref}: {subject!r}\n     {error}")

    print(f"{len(commits)} commit(s) checked, {failures} not conforming")
    if failures:
        print("See CONTRIBUTING.md, section 'Commit messages'.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
