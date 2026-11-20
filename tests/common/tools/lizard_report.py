#!/usr/bin/env python3
"""Function complexity of the stack (lizard), as a statistic or a diff check.

Statistic (default): runs lizard over the stack's own C code and writes, into
--out:
  lizard.csv   one row per function (NLOC, CCN, tokens, parameters, length)
  lizard.html  the readable report
and prints the functions over a threshold with lizard's summary line. Fun Rt
(share of functions over a threshold) and nloc Rt (share of the code in them)
are the figures to follow from release to release. It fails nothing.

Diff check (--diff [BASE], default origin/main): looks only at the functions
whose lines changed since the merge base with BASE, uncommitted work included.
A new function must stay within the thresholds; a changed function that was
already over one must not get worse on it. Exit 1 on a violation. A touched
function over a threshold that got no better is a WARN with the changed
lines: it does not fail, it asks for one refactoring move or a reason.

  python3 -m pip install lizard==1.26.0 jinja2
  python3 tests/common/tools/lizard_report.py [--out build/lizard]
  python3 tests/common/tools/lizard_report.py --diff [origin/main]
"""
import argparse
import csv
import fnmatch
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

# The stack's own code; the vendored third-party files are left out
# (docs/licensing.md, "Pure third-party files").
SOURCES = ["src", "include"]
EXCLUDE = ["*/c-timestamp/*", "*/pt/*", "*/mdns/mdns.h"]
LIMITS = {"CCN": 15, "length": 150, "PARAM": 7}  # lizard -C, -L, -a
FIELDS = ["NLOC", "CCN", "token", "PARAM", "length", "location", "file",
          "function", "long_name", "start", "end"]


def lizard(paths, *extra, cwd=ROOT):
    cmd = [sys.executable, "-m", "lizard", *paths, "-l", "c",
           "-C", str(LIMITS["CCN"]), "-L", str(LIMITS["length"]),
           "-a", str(LIMITS["PARAM"])]
    for pattern in EXCLUDE:
        cmd += ["-x", pattern]
    # lizard exits non-zero when a function is over a threshold: not an error
    # here, but no output at all is (lizard missing, say)
    r = subprocess.run(cmd + list(extra), cwd=cwd, capture_output=True,
                       text=True, encoding="utf-8")
    if not r.stdout and r.returncode not in (0, 1):
        sys.exit(r.stderr or "lizard printed nothing")
    return r.stdout


def functions(paths, cwd):
    """name -> row (ints for the metrics, start/end) of every function."""
    rows = csv.reader(lizard(paths, "--csv", cwd=cwd).splitlines())
    out = {}
    for row in rows:
        f = dict(zip(FIELDS, row))
        for key in ("NLOC", "CCN", "PARAM", "length", "start", "end"):
            f[key] = int(f[key])
        out[(Path(f["file"]).as_posix(), f["function"])] = f
    return out


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                          text=True, encoding="utf-8", check=True).stdout


def changed_lines(base):
    """path -> set of changed line numbers (new side) of the stack's C files,
    and path -> its path at base (differs for a moved file)."""
    lines, old_paths, path, old = {}, {}, None, None
    # no pathspec: a file moved into SOURCES must pair with its old path
    for line in git("diff", "-M", "-U0", "--no-color", base).splitlines():
        if line.startswith("--- "):
            old = line[6:] if line != "--- /dev/null" else None
        elif line.startswith("+++ "):
            name = line[6:] if line != "+++ /dev/null" else None
            path = name if name and name.split("/")[0] in SOURCES and name.endswith((".c", ".h")) and not any(
                fnmatch.fnmatch(name, p) for p in EXCLUDE) else None
            if path and old:
                old_paths[path] = old
        elif path and line.startswith("@@"):
            start, count = re.match(r"@@ -\S+ \+(\d+)(?:,(\d+))? @@", line).groups()
            count = 1 if count is None else int(count)
            lines.setdefault(path, set()).update(range(int(start), int(start) + count))
    return lines, old_paths


def over(f):
    return {k: f[k] for k, limit in LIMITS.items() if f[k] > limit}


def diff_check(base):
    merge_base = git("merge-base", base, "HEAD").strip()
    lines, old_paths = changed_lines(merge_base)
    if not lines:
        print(f"no stack C changes since {base}")
        return 0
    paths = [p for p in lines if (ROOT / p).exists()]
    new = functions(paths, ROOT)
    # the same files at the merge base, to compare a changed function with itself
    with tempfile.TemporaryDirectory() as tmp:
        for p in paths:
            if p not in old_paths:
                continue  # a new file
            text = git("show", f"{merge_base}:{old_paths[p]}")
            (Path(tmp) / p).parent.mkdir(parents=True, exist_ok=True)
            (Path(tmp) / p).write_text(text, encoding="utf-8")
        old = functions([p for p in paths if (Path(tmp) / p).exists()], tmp)

    bad = warn = 0
    for key, f in sorted(new.items()):
        touched = lines[key[0]] & set(range(f["start"], f["end"] + 1))
        if not touched:
            continue
        before = old.get(key)
        worse = {k: v for k, v in over(f).items()
                 if before is None or v > before[k]}
        state = "new" if before is None else "changed"
        if worse:
            bad += 1
            was = "" if before is None else " (was " + ", ".join(
                f"{k} {before[k]}" for k in worse) + ")"
            print(f"FAIL {state} {f['function']} {key[0]}:{f['start']}: " +
                  ", ".join(f"{k} {v} > {LIMITS[k]}" for k, v in worse.items()) + was)
        elif over(f):
            figures = ", ".join(f"{k} {before[k]} -> {v}" for k, v in over(f).items())
            if any(v < before[k] for k, v in over(f).items()):
                print(f"ok   improved {f['function']} {key[0]}:{f['start']}: {figures}")
            else:
                # touched but not improved: the changed lines name the block
                # to extract first (test-driven-development skill, rules.md)
                warn += 1
                print(f"WARN not improved {f['function']} {key[0]}:{f['start']}: "
                      f"{figures}; changed lines {min(touched)}-{max(touched)}")
    print(f"{bad} function(s) over the thresholds {LIMITS} in new or changed code, "
          f"{warn} touched over a threshold and not improved")
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default="build/lizard", help="report directory")
    ap.add_argument("--diff", nargs="?", const="origin/main", metavar="BASE",
                    help="check only new or changed functions against BASE")
    args = ap.parse_args()
    if args.diff:
        sys.exit(diff_check(args.diff))
    out = ROOT / args.out
    out.mkdir(parents=True, exist_ok=True)
    (out / "lizard.csv").write_text(lizard(SOURCES, "--csv"), encoding="utf-8")
    (out / "lizard.html").write_text(lizard(SOURCES, "--html"), encoding="utf-8")
    text = lizard(SOURCES)
    print(text[text.find("!!!! Warnings"):].rstrip())


if __name__ == "__main__":
    main()
