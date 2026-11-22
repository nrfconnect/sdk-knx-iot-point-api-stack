# Docker

`docker/Dockerfile` builds a Linux image for building the stack and running
its tests as the GitLab pipeline (`.gitlab-ci.yml`) does. It is based on the
pipeline's own image (`itgesellschaft/knxiot-knx-ci`: Debian 13, GCC, CMake,
Ninja). On top of that it installs what the CI jobs install at job time:
clang 19 with its sanitizer and fuzzer runtimes, `llvm-cov-19`, `iproute2`,
Valgrind, gcovr, lizard, clang-format and the Python packages of the device
tiers. The source tree is copied into the image at `/w`.

Run all commands from the repository root. They work the same in bash and
PowerShell.

## Build the Image

```bash
docker build -t knx-iot-stack -f docker/Dockerfile .
```

Because the source is part of the image, rebuild the image after changing the
code. Only the last layers are rebuilt, which takes seconds. The device tiers
need the test tool, so initialize it before building the image; the unit tiers
work without it:

```bash
git submodule update --init tests/iot-test-tool
```

## Build and Unit Tests (as in CI)

```bash
docker run --rm knx-iot-stack
```

The default command runs the CI jobs `build-gcc`, `build-plain-sender`,
`build-server-only`, `quality-include-cycle`, `quality-size`, `unit-gcc`,
`unit-asan` and `unit-asan-clang` in this order. It stops at the first failure.

Nothing of the run is kept: the container builds in its own `/w/build` and
`--rm` removes it. To keep the size report of `quality-size` in
`build/arm-size/size/size.txt` of the checkout, mount that folder:

```bash
docker run --rm -v "${PWD}/build/arm-size/size:/w/build/arm-size/size" knx-iot-stack
```

To run a single job, pass its commands from `.gitlab-ci.yml`:

```bash
docker run --rm knx-iot-stack bash -c "cmake --preset=linux-test-asan && cmake --build --preset=linux-test-asan && ctest --preset=linux-test-asan"
```

| CI job | Preset |
| --- | --- |
| `build-gcc` | `linux-debug-gcc` (no ctest) |
| `build-plain-sender` | `linux-plain-sender-gcc` (no ctest) |
| `build-server-only` | `linux-server-only-gcc` (no ctest) |
| `quality-include-cycle` | `linux-include-cycle` (no ctest; clang-tidy fails the build on a header include cycle) |
| `quality-size` | `arm-size` (no ctest; prints text/data/bss of the stack objects for Cortex-M33, see below) |
| `unit-gcc` | `linux-test-gcc` |
| `unit-asan` | `linux-test-asan` |
| `unit-asan-clang` | `linux-test-asan-clang` |

### Stack Object Sizes (`quality-size`)

Of the working tree, without an image rebuild:

```bash
docker run --rm -v "${PWD}:/src:ro" -v "${PWD}/build/arm-size/size:/x/build/arm-size/size" -w /x knx-iot-stack bash -c "tar -C /src --exclude=./build --exclude=./.git --exclude=./tests/iot-test-tool -cf - . | tar -xf - && cmake --preset=arm-size && cmake --build --preset=arm-size"
```

The report lands in `build/arm-size/size/size.txt` of the checkout, as the CI
job's artifact. The sources are copied into the container rather than built
on the mount: on a Windows mount the dependency download fails to rename its
folder. For the delta of a change, run the same command on the base revision
(`git worktree add --detach ../stack-base <base>`, `../stack-base` as `/src`,
`build/arm-size-base` as output) and compare the two files (`diff`,
`Compare-Object`): the object paths are the same, so only changed objects
differ.

The preset compiles the stack objects (`kisClientServer`) for Cortex-M33 with
`arm-none-eabi-gcc -Os`, logs off and the default table sizes, without linking.
`size.txt` lists text, data and bss per object and their TOTALS. The sizes
include the string literals and exclude Mbed TLS, TinyCBOR, the port, the heap
and the stacks. Image totals per platform are in
[memory_breakdown.md](memory_breakdown.md).

### Coverage (`unit-coverage-gcc`)

```bash
docker run --rm -v "${PWD}:/w" -v knx-cov-build:/w/build -v "${PWD}/build/coverage-html:/out" -w /w knx-iot-stack bash -c "cmake --preset=linux-coverage-gcc && cmake --build --preset=linux-coverage-gcc && ctest --preset=linux-coverage-gcc && gcovr --root . --filter src/resources/ --filter src/core/ --filter src/messaging/ --filter src/security/ --filter src/util/ --exclude 'src/util/c-timestamp/.*' --exclude 'src/resources/ri/oc_test_control[.]c' --html-medium-threshold 65 --html-high-threshold 85 --html-details /out/index.html --print-summary --fail-under-branch 62 build/linux-coverage-gcc"
```

The working tree is mounted, so the current code is measured without an image
rebuild. The build stays in the named volume `knx-cov-build` (faster reruns,
no build files in the source tree), and the HTML report, the same as the CI
job's artifact, lands in `build/coverage-html/index.html` on the host. A
failing test stops the command before the report is written.

### Fuzz Seed Replay (`fuzz-seed-replay`)

This replays the fuzz corpus once. The CI's short mutation run is not
included.

```bash
docker run --rm knx-iot-stack bash -c "cmake --preset=linux-fuzz-coverage-clang && cmake --build --preset=linux-fuzz-coverage-clang && ctest --preset=linux-fuzz-coverage-clang -L fuzz"
```

### Fuzzing for a Set Time (`fuzz-explore`)

This mutates every fuzz target for `FUZZ_SECONDS` seconds each, starting from
its seed corpus; the CI job uses 900. New inputs go to `findings/<target>/`
and crashes to `crashes/` in the mounted directory. The exit status is 1 if
any target crashed. To keep a finding as a permanent seed, add it to
`tests/fuzz/make_corpus.py`.

```bash
docker run --rm -e FUZZ_SECONDS=900 -v "${PWD}/artifacts/fuzz:/out" knx-iot-stack bash -c 'cmake --preset=linux-fuzz-clang && cmake --build --preset=linux-fuzz-clang || exit 1; cd build/linux-fuzz-clang/tests/fuzz; s=0; for t in fuzz_*; do [ -f $t ] && [ -x $t ] || continue; n=${t#fuzz_}; d=; [ -f dict/$n.dict ] && d=-dict=dict/$n.dict; mkdir -p /out/findings/$t /out/crashes; ./$t /out/findings/$t corpus/$n $d -max_total_time=$FUZZ_SECONDS -timeout=10 -rss_limit_mb=2048 -artifact_prefix=/out/crashes/$t- || s=1; done; exit $s'
```

The script deliberately uses no double quotes, because Windows PowerShell 5.1
strips them from arguments passed to `docker`.

### Function Complexity (`quality-code`)

```bash
docker run --rm -v "${PWD}:/w" -w /w knx-iot-stack python3 tests/common/tools/lizard_report.py --out build/lizard
```

This mounts the working tree over the copy in the image, so the report
covers the current code without an image rebuild and `lizard.html` and
`lizard.csv` land in `build/lizard/` on the host. Without the mount the
report is written inside the container and removed with it (`--rm`).

The image has no git history, so the job's diff checks (lizard `--diff`,
`git clang-format --diff`) have to run on the host; see the README.

## Device Tiers (runtime, conformance)

These tiers need a network namespace and a veth pair inside the container,
which requires `--privileged`. `tests/common/tools/run-local-ci.sh` sets up
the same network as the CI jobs `runtime-gcc` and `conformance-gcc`, builds
`runtime_test_server` and runs pytest:

```bash
docker run --rm --privileged --sysctl net.ipv6.conf.all.disable_ipv6=0 knx-iot-stack bash tests/common/tools/run-local-ci.sh --tier runtime
docker run --rm --privileged --sysctl net.ipv6.conf.all.disable_ipv6=0 knx-iot-stack bash tests/common/tools/run-local-ci.sh --tier conformance --section 5.6
docker run --rm --privileged --sysctl net.ipv6.conf.all.disable_ipv6=0 knx-iot-stack bash tests/common/tools/run-local-ci.sh   # both, each against a fresh DUT
docker run --rm knx-iot-stack bash tests/common/tools/run-local-ci.sh --tier tool                                             # the test tool's own tests
```

`--help` lists the remaining options (`--server-logs`, `--massif`, ...).
Arguments after `--` go to pytest, for example
`--tier runtime -- tests/runtime/test_observe.py -x`.

For day-to-day work on the device tiers, `tests/common/tools/run-in-docker.ps1`
(or `.sh`) is usually the better choice. It needs no image build, can test
either the committed HEAD or the working tree, and keeps the build in a volume
(see `tests/README.md`).

## Keep the Build Between Runs

Mount a named volume at `/w/build` to keep the build directories and the
dependencies that CMake fetches (mbedTLS, tinycbor, GoogleTest) between runs;
the next run is then much faster. When you reuse the volume, pass `--fresh`
to `cmake --preset` so that preset changes take effect:

```bash
docker run --rm -v knx-build:/w/build knx-iot-stack bash -c "cmake --preset=linux-test-gcc --fresh && cmake --build --preset=linux-test-gcc && ctest --preset=linux-test-gcc"
docker volume rm knx-build   # rebuild from scratch
```

To get reports out of the container (for example the lizard HTML report),
mount a host directory and write there. On Docker Desktop for Windows, use an
absolute path; relative paths are not bind-mounted:

```bash
docker run --rm -v "${PWD}/artifacts/docker:/out" knx-iot-stack python3 tests/common/tools/lizard_report.py --out /out/lizard
```

## Interactive Shell

```bash
docker run --rm -it knx-iot-stack bash
```
