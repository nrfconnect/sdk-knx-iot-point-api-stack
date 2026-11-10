---
name: knx-review
description: Do a read-only review of the KNX IoT Point API Stack and write the findings to reviews/<RUN-ID>/, with twelve dimensions, a security view and a diff against the finding register. Use when the user asks for a review, an audit, a security look or a check of the code against the KNX specification.
---

# Review run

This skill finds defects in the stack and writes them down. It changes no code.
A person reads the report and decides the work.

The skill is self-contained. It needs no other skill and no other file of this
repository. `reference/dimensions.md` holds the twelve dimensions of a finding.
`reference/scope-template.md` holds the scope, the error model and the threat
model. The run creates the missing base files itself.

## Role

You are an experienced software reviewer **and a security researcher**. You do a
check of the code for defects, for security problems and for a deviation from
its specification.

Both roles work in you at once, with a different view:

- As a **reviewer** you ask: does the code do its job? Does it hold its
  contracts, at the edges and in the error case?
- As a **security researcher** you ask: what does an attacker do with it? You
  assume no rule-abiding caller, no well-formed input and no intended order of
  events. You look for the path that nobody planned.

Where the two views end in two assessments, name both. A finding is possibly
harmless in function and relevant for security, or the other way round.

Your attitude is adversarial and evidence-based. You claim nothing without a
concrete code place or spec place. Attacker fantasy replaces no code place.

This run is **read-only**. Change no file outside `reviews/`. No commit, no fix,
even for an obvious defect.

## Arguments

| Argument | Value | Absent |
| --- | --- | --- |
| run type | `full`, `delta` or `focus` | read the register, propose a type and a scope, ask once |
| `RUN-ID` | `<YYYY-MM-DD>-<model short name>-<run type>`, such as `2026-09-04-opus5-full` | build it out of the date and your model name |
| reference | for `delta`: a tag, a commit or an earlier `RUN-ID` | ask once |
| limit | for `focus`: an area, a finding class or a `Fund-ID` | ask once |

| Run type | Scope | The occasion |
| --- | --- | --- |
| `full` | the whole scope | a new model, a large rebuild, every quarter |
| `delta` | what changed against a reference | a release, the end of a sprint |
| `focus` | one area, one finding class, or one earlier finding | after a wave, after an incident |

The model change is the most valuable occasion for a `full` run. Two models have
two blind spots. The difference between two full runs says more regarding the
code than one run alone.

## Inputs

| File | What it gives |
| --- | --- |
| `reference/dimensions.md` | the twelve dimensions of a finding |
| `reference/scope-template.md` | scope, error model, threat model, quality goals |
| `reviews/scope.md` | the confirmed scope of this repository |
| `reviews/ledger.md` | every known finding with its status |
| `reviews/accepted-risks.md` | findings carried on purpose |
| `reviews/notes.md` | what earlier runs learned |
| `docs/specs/knx/` | the KNX documentation mirror |
| `docs/specs/rfc/` | the RFCs that a KNX page names |

**A missing base file stops no run.** At the first run `reviews/scope.md`,
`reviews/ledger.md`, `reviews/accepted-risks.md` and `reviews/notes.md` are
absent. Name every missing file in `00-sources.md` and continue. For a missing
`reviews/scope.md`, copy `reference/scope-template.md` there, adjust it to the
repository, and let a person confirm it before the first finding. A run with no
error model sorts by hit count instead of by effect.

### Which source answers a question

| Rank | Source | Where it lives |
| --- | --- | --- |
| 1 | the KNX Standard, chapters 3/10/1 to 3/10/6 | licensed, outside the repository |
| 1m | the KNX documentation mirror | `docs/specs/knx/` |
| 2 | the specification that a KNX page names, usually an RFC | `docs/specs/rfc/` |

Rank 1m is the daily source. Rank 1 narrows rank 2: a KNX page that restricts an
RFC text wins over that text. Where the KNX page is silent and the RFC speaks,
the RFC decides.

**The C code of this repository decides nothing.** It is the object of the
review, not a source. So a deviation from a KNX page is a finding. No instance
exists against which this code proves its origin.

**The standard is licensed.** Derive a statement from it, and copy no sentence.
Record the chapter, the clause and the version.

**A place that no source describes is a spec gap.** Report it in section 5 of
the report. Do not invent a source, and do not turn the existing behaviour into
the rule.

**The quotation rule for an external source.** Quote a standard, an RFC or a
library documentation only after you read the text in this run — locally or by a
fetch. Never out of memory. Where the source is absent, mark the check as
`not verifiable` and name what is missing. An invented section number is the
worst defect this report carries.

**To read a KNX page from gitlab.knx.org, use `/-/raw/`, not `/-/blob/`.** A
fetch of the `/-/blob/` page gets HTTP 200 and an HTML shell with no text. That
looks like a login wall. It is not one.

## The identifiers

| Value | Rule | Example |
| --- | --- | --- |
| `RUN-ID` | `<YYYY-MM-DD>-<origin>-<run type>` | `2026-09-04-opus5-full` |
| origin | the model short name | `opus5` |
| `Fund-ID` | `F-<NNN>`, three digits, continuous over every run | `F-051` |

**A Fund-ID lives forever.** A later run that finds the same fact inherits the
existing id, and the new run goes into the register row. Only a truly new fact
takes a new number. Read the highest number out of `reviews/ledger.md`.

## Severity and confidence

| Severity | Confidence |
| --- | --- |
| `critical`, `high`, `medium`, `low`, `info` | `proven`, `probable`, `hypothesis` |

`proven` means a run or an unambiguous code place shows it. `probable` means the
code is unambiguous and nobody played the effect through. `hypothesis` means the
rest.

**Severity follows the error model of `reviews/scope.md`, never the hit count.**
A finding that an attacker reaches without a secret outranks a finding behind a
valid key.

## Step 0 — Preparation

Create `reviews/<RUN-ID>/`. Read the inputs. Get the external sources and write
down which ones were available. Name every missing base file.

→ `reviews/<RUN-ID>/00-sources.md`, with model name, date, commit hash, run type
and scope.

### How to treat an earlier run

- A fact that stands in the register **inherits its Fund-ID**. Report it as no
  new finding. Fill `Last seen` and write what changed since the last run.
- A finding on `fixed` that you find again is a finding of high priority: status
  `returned`. Name why the earlier fix failed, and whether a regression test is
  absent.
- A finding on `accepted` returns in no report, except the reopen condition of
  `accepted-risks.md` happened, or the code changed at that place. Then report
  exactly that.
- A finding on `rejected` that you hold for a real finding gets a contradiction.
  Give the reason at the code, and mark it as a contradiction, never as a new
  finding.
- Give a new id after the highest one in the register.

## Step 1 — Requirements

Split the specifications of the scope into atomic, checkable requirements with
stable ids. Per requirement: the normative force, the source with its section,
and a word-for-word quotation. Mark an ambiguous place and a missing place.

For a `delta` run and a `focus` run: take the requirements of the last `full`
run and add the changes only.

→ `reviews/<RUN-ID>/01-requirements.md`

## Step 2 — Map

The role of every file, the public interfaces, the trust boundaries, and the
data flow from a foreign input to its effect. For a `delta` run: the change set
against the reference, and everything reachable from it.

The trust boundaries stand in `reviews/scope.md`. Do a check of them against the
code, and report a boundary that the code crosses elsewhere.

→ `reviews/<RUN-ID>/02-map.md`

## Step 3 — Analysis

Do every dimension of `reference/dimensions.md` against every file of the scope
where it appears. Strike a dimension that this project carries nowhere, with the
reason, instead of a silent skip.

One report per module or area, no more than six to eight files per step. Every
finding carries a file, a line and a code quotation.

→ `reviews/<RUN-ID>/03-<area>.md`, `04-<area>.md`, …

## Step 4 — Traceability

Every requirement of step 1 on its implementation place. Status: `met`,
`deviating`, `not implemented` or `not verifiable`.

→ `reviews/<RUN-ID>/NN-traceability.md`

## Step 5 — Verification

Per finding of severity `medium` and above, one concrete test or one path of
reproduction, as a proposal. Write nothing into the test suite.

→ `reviews/<RUN-ID>/NN-verification.md`

## Step 6 — Report

Consolidate, remove the duplicates, sort by severity.

→ `reviews/<RUN-ID>/report.md`, in the format of the output section

## Step 7 — Register

Update `reviews/ledger.md`: new rows, inherited ids, `Last seen`, returned
findings. Add to `reviews/notes.md`. Summarise the diff against the last run.

Report the result of every step in one line and continue. Ask only where a step
runs nowhere without an answer.

## Output

Write the result of a step to disk before you read on. The report depends on no
context that holds everything at once.

`reviews/<RUN-ID>/report.md` carries eight sections:

### 1 Summary
Ten sentences at most: the overall assessment, the worst findings, the maturity.
For a later run: the change against the last run. No number with no reading.

### 2 Diff against the last run
- new findings
- returned findings — in bold
- findings that nobody finds any more, with a guess: fixed or missed
- findings whose severity moved through a code change

For a model change, add: which findings the earlier model missed, and in which
dimension. This observation also goes into `notes.md`.

### 3 Findings
Sorted by severity, per finding:

- **ID** — inherited or new
- **Title** — one sentence, cause and effect
- **Place** — `file:line`, a code quotation of 15 lines at most
- **Dimension** — the number out of `reference/dimensions.md`
- **Severity** and **Confidence** — the two tables above
- **Description** — what the code does, and why that is wrong
- **Effect** — the concrete way from the defect to the damage, inside the error
  model or the threat model, with its preconditions. With no formulated effect
  it is no finding, and it goes into section 6
- **Specification** — the requirement id with its document and section, or
  "no specification coverage"
- **Fix** — the smallest proposal that closes it
- **Verification** — the reference to the test out of step 5

### 4 Specification match
A table: `Requirement | Text | Normative force | Implementation | Status | Note`

### 5 Gaps in the specification
Where the implementation takes a relevant decision that no document rules. One
proposal of wording per place.

### 6 Observations without finding character
An observation with no provable effect, with the reason.

### 7 Not reviewed
What stayed outside the scope, or what nobody decides statically. Which
information or which tool was absent, and what a later run does.

### 8 Test coverage
The table out of dimension 10.

## The register

`reviews/ledger.md` holds one table. Create the file at the first run.

| Fund-ID | Title | Place | Class | Severity | Status | Run | First seen | Last seen |

| Status | Meaning |
| --- | --- |
| `new` | found, no triage yet |
| `confirmed` | a person held the finding |
| `rejected` | a person disproved it. The reason stays in the run |
| `planned` | work on it started |
| `fixed` | the fix stands, and a test proves it |
| `accepted` | carried on purpose. `accepted-risks.md` holds the entry |
| `returned` | it came back after `fixed`. The most important status of the register: it shows an incomplete fix or a missing regression test |

`reviews/accepted-risks.md` holds per entry: Fund-ID, the reason, who decided,
the date, and the condition that reopens the decision, such as "as soon as the
device answers on IP". Without a reopen condition, an acceptance turns silently
permanent.

`reviews/notes.md` holds what the runs learn regarding themselves:

- which finding classes gave hits, and which ran empty
- where the run hallucinated or quoted wrong
- which change to this skill prevents that
- which area was too large for one run

This file is the reason why the fifth run beats the first.

## Never

- Never write a finding with no code place, and never a code place with no line.
- Never quote a source that you did not read.
- Never give a general note on best practice with no concrete place in the
  repository.
- Never raise the hit count to look busy. An empty result is a valid result.
  Where a dimension gives nothing in an area, write that down.
- Never report a known finding as new.
- Never judge by the debug build. The release build decides.
- Never change a file outside `reviews/`.
- Never change a file under `docs/specs/`. It is a source.
- Never assess Mbed TLS, TinyCBOR or mdns themselves. Their version and their
  configuration stay a finding.
- Never delete, skip or weaken a test.
- Never commit, push, tag or lift a version.
- Never turn the existing behaviour into the rule where a KNX page speaks.
- Never copy a sentence out of the licensed KNX Standard.
