# Agent workflow

Read this file for workflow and agent routing. `CLAUDE.md` has the project map,
commands, and stack-specific constraints.

## Rules

- Diagnose failures from evidence before proposing a fix.
- Do not change stack C code without the user's explicit approval. Tests and
  docs are allowed within the requested scope.
- For a stack C fix, include a regression test that fails without the fix.
- Changes to the conformance test tool belong in its repository, not in this
  stack's submodule. Check the device's C before stating how it behaves.
- Do not edit `CHANGELOG.md`; it is updated at release time.
- Do not commit or push unless asked.
- In this public repository, describe conformance-tool behavior without
  references to its source names or line numbers; use `[parity:P-NNNN]` tags
  where applicable.

## Skills

Load the matching skill and follow its complete workflow; do not load unrelated
skills.

| Work | Skill |
|---|---|
| Stack C change or refactor | `.claude/skills/test-driven-development/SKILL.md` |
| Review a stack change | `.claude/skills/code-review/SKILL.md` |
| Write a Google Test unit test | `.claude/skills/unit-test-writer/SKILL.md` |
| Write a runtime test | `.claude/skills/runtime-test-writer/SKILL.md` |
| Update or estimate the memory report | `.claude/skills/memory-footprint/SKILL.md` |
| Architecture review with measurements | `.claude/skills/architecture-review/SKILL.md` |

## Test tiers

Unit, runtime, and conformance are separate tiers; runtime does not include the
iot-test-tool conformance tests. For behavior covered by KNX's conformance
template, run the conformance tier in Docker; see `tests/README.md`. The
code-review skill defines when each tier is needed.

## Agents

Use only when the task matches; avoid extra agents for simple changes.

| Task | Agent |
|---|---|
| Root cause of a failure, before suggesting a fix | `.claude/agents/debug.agent.md` |
| Explicit security review or vulnerability investigation | `.claude/agents/security-auditor.agent.md` |
| Adversarial review of a stack C diff over 100 changed lines | `.claude/agents/quality-litigator.agent.md` |

For code changes, the test-driven-development and code-review skills define the
gates and when additional review is needed. Use the smallest relevant test
command from `CLAUDE.md`; state any skipped gate in the hand-off.
