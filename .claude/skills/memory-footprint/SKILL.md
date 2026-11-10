---
name: memory-footprint
description: "Keeps docs/memory_breakdown.md (the KNX IoT stack memory footprint report) current after code changes by estimating the flash and RAM effect of the diff from the report's own formulas, no build required. Use it whenever the user asks to update, refresh or check the memory footprint, memory breakdown or flash/RAM figures, asks what a change costs in memory, or has changed table sizes, buffer constants, rings, Kconfig/CMake options, structs behind a table, or added/removed stack source."
compatibility:
  claude: ">=3.5"
---

# Memory footprint report update (estimate)

`docs/memory_breakdown.md` was measured once from linked images (§ 1 names the
revision). Between measurements it is kept current by estimate: read the
changes since the measured revision, work out which rows of the report they
move, recompute those rows from the constants the report itself states, and
mark them as estimates. The report already has that convention: `~` means
estimated, plain numbers mean measured.

Run by hand after code changes. Never commits.

## 1. Find what changed

In the stack repo:

```bash
git log --oneline -1 -- docs/memory_breakdown.md   # last report update
git diff --stat <measured-or-last-estimated-rev>..HEAD
git status --short                                  # uncommitted work counts too
```

The measured revision is in § 1 "Stack revision". If a previous estimate was
already applied, § 1 also says "estimated for `<rev>`"; diff from that one so
nothing is counted twice.

Discard everything under `tests/`, `docs/`, `.gitlab-ci.yml`, `port/linux/`,
`port/windows/`: not in the Zephyr image. Keep `api/`, `messaging/`,
`security/`, `util/`, `include/`, `port/zephyr/`, `port/*.c`, `CMakeLists.txt`,
`zephyr/`.

## 2. Turn each change into a delta

Use the report's numbers, not general rules of thumb. Show the arithmetic.

| Change | Rule (from the report) | Rows it moves |
| --- | --- | --- |
| Table capacity default (`CONFIG_KNXIOT_*_MAX_ENTRIES`) | § 6 bytes-per-entry × new count | § 6 row and subtotals, § 2.1 "RAM, static", § 9.1 "KNX IoT stack" RAM |
| Field added/removed in a table entry struct | new `sizeof` on 32-bit (pointers and `size_t` 4 B, align to 4) × entries | same as above; update the bytes-per-entry cell |
| Ring/history count or record size (`ECHO_RING_SIZE`, `OC_REQUEST_HISTORY_SIZE`, replay) | count × record | § 6 row, subtotal |
| `KNX_PAYLOAD_SIZE`, header reserve, block size | § 7.1 table; ± payload change per message and per response state | § 7.1, § 7.3, § 7.4 scenarios, § 8 knob row, § 1 note |
| Hard-coded constant becomes a Kconfig/CMake option (or vice versa) | value unchanged → no size delta | "Configured by" cell in § 6 or § 8, like commit `e1279efd` |
| New/removed source in an area of § 5 | area KiB ÷ non-blank lines of that area's objects = B/line, × lines added; note the density used | § 5 area row; § 2.1 "FLASH" if the total moves ≥ 1 KiB |
| New shell command | § 5 says `knx_shell` = 6 KiB for the current set; scale by command count | § 5 port rows, § 4 "6 KiB shell commands" sentence |
| Log strings (`OC_INF`/`OC_WRN`/`OC_ERR` at INFO level; `OC_DBG` is compiled out) | sum of added format-string bytes → image string pool | mention in § 5 only if ≥ 1 KiB; never the stack rows (§ 5 excludes strings) |
| New dependency (Mbed TLS feature, PSA algorithm, Zephyr subsystem) | not estimable from the report | do not guess: flag for a real measurement |

Anything smaller than 0.5 KiB does not move a row; the report rounds to KiB.
Say so rather than editing a number that would round back to itself.

## 3. Patch the report

- Recompute the moved rows and every subtotal that depends on them (§ 6
  subtotals → § 2.1 → § 2.2 → § 9.1 "KNX IoT stack" row and "KNX share").
  Prefix each changed cell with `~`. Leave measured cells that did not move.
- § 1 Conditions: keep "Stack revision `<measured>`" and add or update
  "figures marked `~` estimated for `<rev>` (`<date>`)", so the next run knows
  both baselines.
- Do not touch the measured image totals of § 9.1 (flash/RAM per backend) for a
  stack-only change: the backend dominates them and the delta is inside their
  rounding. Do adjust them for a change that certainly exceeds 1 KiB and say
  which one.
- Keep the report's formatting: KiB as integers, thin-space thousands
  (`1 385 KiB`), tables aligned as they are.

## 4. Report back

One table: change → rows moved → old → new, with the arithmetic in a short
note per line. Then the flagged items (new dependencies, anything the report
has no formula for). Then the accumulated estimated drift since the measured
revision; when it exceeds ~5 KiB flash or ~2 KiB static RAM, or a flagged item
exists, recommend measuring again from a build (`size` on `zephyr.elf`, the
linker map for attribution, method in § 9) and resetting § 1.

Do not commit.
