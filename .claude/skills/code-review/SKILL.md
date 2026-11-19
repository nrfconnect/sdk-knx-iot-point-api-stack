---
name: code-review
description: "Use to review a stack change (a branch, a merge request, or the own diff before hand-over): gates, checklist, adversarial pass, findings with file:line."
---

# Code review (stack C)

Other change: read-only, verdict. Own change: fix CRITICAL/HIGH, gates again
after the last edit, summary.

1. **Scope:** `git diff --stat <base>...HEAD` or `git diff <baseline>` plus
   untracked files; the plan or MR text.
2. **Gates:** unit preset (incl. `LayeringCheck.*`);
   `python tests/common/tools/lizard_report.py --diff <base>` no `FAIL`, each
   `WARN` improved or reasoned; `git clang-format --diff $(git merge-base origin/main HEAD)`
   prints nothing (Windows: `python (Get-Command git-clang-format).Source`
   instead of `git clang-format`; CI pins clang-format 22). Own change
   also: coverage of the new lines (gcovr), `linux-test-asan` if Linux is at
   hand, Docker runtime tier if hand-written runtime behaviour changed, and
   Docker conformance tier (`-Tier conformance`) if behavior covered by KNX's
   conformance template changed. Runtime and conformance are separate tiers.
   Use the `memory-footprint` skill for flash/RAM. A gate not run: say so.
3. **Checklist** against [rules.md](../test-driven-development/rules.md):
   scope only the plan; layer and hooks; network input; memory and failure
   paths (full table, allocation failure, persisted state); reset on
   shutdown and factory reset; security; ports (sizes, alignment, Zephyr,
   ESP-IDF, Windows); flash (log strings, duplication); tests per branch;
   docs.
4. **Adversarial pass:** break it yourself with length 0/1/max/max+1, NULL,
   empty array, request before provisioning or twice, full pool, malformed
   or duplicate option. Only for >100 changed lines also the
   `quality-litigator` agent; only for network parsing, OSCORE, SPAKE2+ or
   access control the `security-auditor` agent (give base and files). Keep
   findings shown in the code.
5. **Output:** verdict, gates, findings
   `# | CRITICAL/HIGH/MEDIUM/LOW | file:line | input -> effect | fix`. Own
   change: baseline, tests added, gates, lizard, coverage, flash/RAM,
   findings handled, open points. No commit unless asked.
