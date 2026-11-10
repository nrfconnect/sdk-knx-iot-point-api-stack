---
name: feedback-changelog-only-on-releases
description: Never add CHANGELOG.md entries as part of a change; the changelog is written at release time.
type: feedback
---

Don't touch `CHANGELOG.md` when implementing a change; there is no
"Unreleased" section. The maintainer writes it when a release is cut, from
the commit history.

**Why:** per-change entries create merge noise and duplicate git history;
the user reverted one such section.

**How to apply:** describe removed or changed public API in the commit
message; mention release-worthy changes in the final report. Tell agents
you dispatch "do not edit CHANGELOG.md".
