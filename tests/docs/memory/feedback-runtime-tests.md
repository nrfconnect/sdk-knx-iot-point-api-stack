---
name: feedback-runtime-tests
description: Rules for the runtime tier (tests/runtime) - when a test may exist, naming, module order, hooks, deleting tests, ASan.
type: feedback
---

1. A runtime test exists only for behaviour the conformance template does not
   cover or asserts more weakly. Before adding one, check the template; never
   delete one without naming the template case that covers it.
   **Why:** the conformance tier plays the template; duplicates rot, and
   removing a stronger test silently loses coverage.
2. Name tests by behaviour; an overlap with the template is recorded only as
   `@pytest.mark.eitt_overlap("<case>")`.
3. A new module goes into `RUNTIME_MODULE_ORDER` (`tests/common/fixtures.py`)
   where its device-state side effects need it. Order matters per test, not
   per class (a software-update test changes the firmware version for every
   later test).
4. A new `pytest_*` hook in `fixtures.py` is also named in the explicit hook
   import in `tests/conftest.py`: the star-import brings it in, but a hook
   that silently stops being re-exported is a silent behaviour change, so
   the hooks are listed where a reader sees them.
5. After deleting tests, run the whole tier in Docker: tests depend on each
   other's device state. Find unused imports with an AST undefined-name scan,
   not grep; when renaming a module, grep for its name as a string too.
6. Unit tests must also pass `linux-test-asan` (LeakSanitizer gates the
   `unit-asan` job).
7. After a `git rebase`, check untracked files: an autostash once lost one.
