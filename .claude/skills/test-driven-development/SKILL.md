---
name: test-driven-development
description: "Use for new, changed or refactored stack C code (src/api/, src/messaging/, src/security/, src/util/, src/port/, include/): approved plan, failing Google Test first, minimum code, leave touched functions better, then code-review."
---

# Test-driven development (stack C)

Rules for code, tests and refactoring: [rules.md](rules.md). Windows preset
shown; Linux `linux-test-gcc`.

0. **Plan.** Note `git rev-parse HEAD` as baseline. Read the touched
   functions and callers. Tell the user files, functions, the first failing
   test, the flash/RAM effect; with two or more of (several layers, public or
   hooks header, crypto state, new table/option, >100 lines) also the options
   and steps. **Stack C only after approval.** A bug: root cause first
   (`debug` agent).
1. **RED.** One test in `tests/unit/test_<module>.cpp`
   (`unit-test-writer` skill for mechanics; a runtime test only if reachable
   solely over the wire). Build, run
   `ctest --preset=windows-test-gcc -R "^<Suite>\.<Name>$"`: it fails on the
   assertion.
2. **GREEN.** Only the code that test needs; then the whole preset passes,
   warning-free. Repeat 1-2 per behaviour.
3. **Leave it better.** `python tests/common/tools/lizard_report.py --diff <baseline>`:
   - `FAIL`: fix it (CI fails on it).
   - `WARN ... changed lines x-y`: extract the block around x-y into a
     `static` helper (rules.md, Refactoring), check its lines are covered,
     run the preset and `--diff` again (`ok improved`). Too costly (block
     untested, many parameters): give the reason at hand-over.
4. **Refactoring task** (behaviour unchanged): pin the function's branches
   with passing tests (`windows-coverage-gcc`, `gcovr --filter <file>
   --txt-metric branch`), note `size` of the `.c.obj`, one move at a time
   with the preset after each; done when `--diff` shows no `FAIL` and the
   object is not larger. Stop and ask if a move changes behaviour.
5. **Hand over:** `code-review` skill, own change. No commit unless asked.
