# How to Contribute

We'd love to accept your patches and contributions to this project.

- How to contribute, please review the clause workflow. 
- To contribute you have to accept the underneath  **Contribution License Agreement ("Agreement")**. 

Many thanks in advance.

## Workflow

There are several tools/vendors already using the API, several workflows prepare for these tools the corresponding content, based on internal and external requests.

To keep control over the (build) tools and their generated artefact's please simply:

1. Create a git issue in this [repository](https://gitlab.knx.org/public-projects/knx-iot-point-api/knx-iot-point-api-stack/-/issues) by using your credentials/username
2. Describe your requested change or issue/bug (you may also add a code snippet)
3. All submissions require review. We use the [Feature Branch Workflow](https://www.atlassian.com/git/tutorials/comparing-workflows/feature-branch-workflow) and review all 
   changes before we merge to the 'main' branch. Merge requests are only possible by the repository maintainer, this prevents accidental damage.
1. After merging/testing/publishing it, the change will also be deployed here.

## Commit messages

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).
The CI job `commit-lint` checks every commit of a branch that is not yet on `main`; a branch with a non-conforming commit cannot be merged.

### Format

```
<type>(<scope>): <description>

<body>

<footer>
```

- **Subject line** (checked by CI): `<type>(<scope>): <description>`, at most 100 characters. The scope is optional, the description starts in lower case and has no trailing period.
- **Body** (optional): what changed and why, wrapped at 72 characters.
- **Footer** (optional): issue references and breaking changes, see below.

### Types

| Type | Use for | Release impact |
|------|---------|----------------|
| `feat` | a new feature | minor |
| `fix` | a bug fix | patch |
| `perf` | a performance or memory improvement without functional change | patch |
| `refactor` | a code change that neither fixes a bug nor adds a feature | none |
| `test` | adding or changing tests only | none |
| `docs` | documentation only | none |
| `build` | build system, CMake, Kconfig, dependencies | none |
| `ci` | CI configuration (`.gitlab-ci.yml`, CI scripts) | none |
| `style` | formatting only, no code change | none |
| `chore` | maintenance that fits no other type | none |
| `revert` | reverting an earlier commit | depends |

### Scopes

The scope names the part of the stack that is changed. Use lower case and prefer one of these:

| Scope | Area |
|-------|------|
| `api` | `api/` (resources, discovery, core API) |
| `messaging` | `messaging/` (CoAP) |
| `oscore` | OSCORE |
| `security` | `security/` (SPAKE2+, access tokens, auth) |
| `mdns` / `dns-sd` | `port/mdns/`, DNS-SD |
| `zephyr` | `port/zephyr/`, `zephyr/` |
| `freertos` | `port/freertos_esp32/`, `esp-idf/` |
| `linux` / `windows` | host ports |
| `soc` | vendor or SoC specific code, boards, patches (name the vendor in the description) |
| `wifi` / `thread` / `ethernet` | network backend |
| `config` | CMake options, Kconfig, presets |
| `tests` | `tests/` |
| `tools` | `tools/`, `scripts/` |

Combine an operating system with a network backend with a slash, for example `fix(zephyr/thread): ...`.

Leave the scope out when a change spans many areas.

### Breaking changes

Mark a change that requires users to adapt with `!` after the type/scope and describe the migration in a `BREAKING CHANGE:` footer:

```
feat(api)!: rename oc_add_device() to knx_add_device()

BREAKING CHANGE: callers must use knx_add_device(); the old name is removed.
```

### Issue references

Reference the related issue in the footer: `Closes #123` closes it when merged to `main`, `Refs #123` only links it.

### Examples

```
fix(oscore): reject replayed sequence numbers after a reset
feat(mdns): announce the device on every interface
docs: describe the memory footprint per platform
ci: add commit message check
```

### Local check (optional)

The same check can run on every commit as a git `commit-msg` hook. Create `.git/hooks/commit-msg` with:

```sh
#!/bin/sh
exec python3 scripts/check_commit_messages.py --file "$1"
```

On Windows replace `python3` with `python` if needed. On Linux and macOS make the hook executable (`chmod +x .git/hooks/commit-msg`).

To check a branch before pushing:

```sh
python3 scripts/check_commit_messages.py --range origin/main..HEAD
```

## Contribution License Agreement ("Agreement")

This Contribution License Agreement ("Agreement") is agreed to by the party signing below ("You"), and conveys certain license rights to the KNX Association, ("KNX Association") 
for Your contributions to KNX Association open source projects. 
This Agreement is effective by performing a _Submit_ to one of the KNX Association open source _Projects_. 

1. **Definitions**

    **Code** means the computer software code, whether in human-readable or machine- executable form, that is delivered by You to KNX Association under this Agreement.

    **Project** means any of the projects owned or managed by KNX Association and offered under a license approved by the Open Source Initiative (www.opensource.org).

    **Submit** is the act of uploading, submitting, transmitting, or distributing code or other content to any Project, including but not limited to communication on electronic mailing lists, source code control systems, and issue tracking systems that are managed by, or on behalf of, the Project for the purpose of discussing and improving that Project, but excluding communication that is conspicuously marked or otherwise designated in writing by You as "Not a Submission."

    **Submission** means the Code and any other copyrightable material Submitted by You, including any associated comments and documentation.

2. **Your Submission**. You must agree to the terms of this Agreement before making a Submission to any Project. This Agreement covers any and all Submissions that You, now or in the future (except as described in Section 4 below), Submit to any Project.

3. **Originality of Work**. You represent that each of Your Submissions is entirely Your original work. Should You wish to Submit materials that are not Your original work, You may Submit them separately to the Project if You (a) retain all copyright and license information that was in the materials as you received them, (b) in the description accompanying your Submission, include the phrase "Submission containing materials of a third party:" followed by the names of the third party and any licenses or other restrictions of which You are aware, and (c) follow any other instructions in the Project's written guidelines concerning Submissions.
 
4. **Licenses**.

   1. **Copyright License**. You grant KNX Association, and those who receive the Code directly or indirectly from KNX Association, a perpetual, worldwide, non-exclusive, royalty-free, irrevocable license in the Submission to reproduce, prepare derivative works of, publicly display, publicly perform, and distribute the Submission and such derivative works, and to sublicense any or all of the foregoing rights to third parties.

   2. **Patent License**. You grant KNX Association, and those who receive the Code directly or indirectly from KNX Association, a perpetual, worldwide, non-exclusive, royalty-free, irrevocable license under your patent claims that directly read on the Code to make, have made, use, offer to sell, sell and import or otherwise dispose of the Code.

   3. **Other Rights Reserved**. Each party reserves all rights not expressly granted in this Agreement. No additional licenses or rights whatsoever (including, without limitation, any implied licenses) are granted by implication, exhaustion, estoppel or otherwise.

5. **Representations and Warranties**. You represent that You are legally entitled to grant the above licenses. You represent that each of Your Submissions is entirely Your original work (except as you may have disclosed under Section 3). You are not expected to provide support for Your Submission, unless you choose to do so. UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING, AND EXCEPT FOR THE WARRANTIES EXPRESSLY STATED IN SECTIONS 3, AND 5, THE SUBMISSION PROVIDED UNDER THIS AGREEMENT IS PROVIDED WITHOUT WARRANTY OF ANY KIND, INCLUDING, BUT NOT LIMITED TO, ANY WARRANTY OF NONINFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.

6. **Notice to KNX Association**. You agree to notify KNX Association in writing of any facts or circumstances of which You later become aware that would make Your representations in this Agreement inaccurate in any respect.

7. **Information about Submissions**. You acknowledge that contributions to Projects and information about contributions may be maintained indefinitely and disclosed publicly, including your name and other information that you submit with Your Submission.

8. **Governing Law/Jurisdiction/Attorneys' Fees**. This Agreement shall be construed and controlled by the laws of Belgium, and the parties consent to exclusive jurisdiction and venue in the courts sitting in Brussels. The parties waive all defenses of lack of personal jurisdiction and forum non- conveniens.

9. **Entire Agreement/Assignment**. This Agreement is the entire agreement between the parties, and supersedes any and all prior agreements, understandings or communications, written or oral, between the parties relating to the subject matter hereof. This Agreement may be assigned by KNX Association.