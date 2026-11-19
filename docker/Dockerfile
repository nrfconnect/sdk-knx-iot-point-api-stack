# Linux build and test image for the stack, see docs/docker.md.
#
# Based on the image the GitLab pipeline runs in (.gitlab-ci.yml, default
# image), so compiler, CMake and Python are the CI's. The packages and Python
# tools the CI jobs install at job time are installed here once instead.
#
#   docker build -t knx-iot-stack -f docker/Dockerfile .
#   docker run --rm knx-iot-stack                  # build + unit jobs, as in CI
ARG BASE_IMAGE=itgesellschaft/knxiot-knx-ci:latest
FROM ${BASE_IMAGE}

# clang + libclang-rt-19-dev: unit-asan-clang and the fuzz presets
# llvm-19:                    llvm-cov-19 for gcovr on clang's coverage output
# iproute2:                   DUT network namespace of the device tiers
# valgrind:                   the *-massif jobs
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang libclang-rt-19-dev llvm-19 iproute2 valgrind \
    && rm -rf /var/lib/apt/lists/*

# pip the way the CI jobs get it (get-pip.py, not Debian's python3-pip, which
# run-local-ci.sh's get-pip.py could not upgrade). Same pins as the
# quality-code job; gcovr for the coverage jobs.
COPY tests/common/requirements.txt /tmp/requirements.txt
RUN curl -sSL https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py \
    && python3 /tmp/get-pip.py --break-system-packages --quiet \
    && rm /tmp/get-pip.py \
    && python3 -m pip install --break-system-packages --no-cache-dir \
        -r /tmp/requirements.txt gcovr lizard==1.26.0 jinja2 clang-format==22.1.8 \
    && rm /tmp/requirements.txt

WORKDIR /w
COPY . /w

# A Windows checkout may carry CRLF; the scripts run in bash.
# The test tool (submodule tests/iot-test-tool) is optional for the unit tiers.
RUN sed -i 's/\r$//' tests/common/tools/*.sh \
    && if [ -f tests/iot-test-tool/requirements.txt ]; then \
           python3 -m pip install --break-system-packages --no-cache-dir \
               -r tests/iot-test-tool/requirements.txt; \
       fi \
    && mkdir -p /knx-cache

# KNX's files for the conformance tier (template, ...); mount a volume here
# to keep them between runs.
ENV KNX_TOOL_CACHE=/knx-cache

# Default: the CI jobs build-gcc, build-plain-sender, unit-gcc, unit-asan and
# unit-asan-clang, stopping at the first failure.
CMD ["bash", "-c", "set -e; for p in linux-debug-gcc linux-plain-sender-gcc linux-test-gcc linux-test-asan linux-test-asan-clang; do echo \"=== $p ===\"; cmake --preset=$p; cmake --build --preset=$p; case $p in *-test-*) ctest --preset=$p ;; esac; done"]
