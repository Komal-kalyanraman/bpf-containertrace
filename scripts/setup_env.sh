#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# setup_env.sh – Validate the build environment for bpf-containertrace

set -euo pipefail

PASS=0; FAIL=0

check() {
    local label="$1"; shift
    if "$@" &>/dev/null; then
        echo "  [OK]  $label"
        ((PASS++)) || true
    else
        echo "  [FAIL] $label"
        ((FAIL++)) || true
    fi
}

echo "=== bpf-containertrace environment check ==="
echo

echo "--- Kernel & BTF ---"
check "Kernel >= 5.8"            bash -c "[ $(uname -r | cut -d. -f1) -ge 5 ]"
check "BTF present"               test -f /sys/kernel/btf/vmlinux
check "cgroup v2 mounted"         test -f /sys/fs/cgroup/cgroup.controllers
check "machine.slice exists"      test -d /sys/fs/cgroup/machine.slice

echo
echo "--- Build tools ---"
check "gcc"                       which gcc
check "clang-18"                  which clang-18
check "bpftool"                   which bpftool
check "cmake >= 3.20"             bash -c "cmake --version | head -1 | awk '{print \$3}' | awk -F. '\$1>3 || (\$1==3 && \$2>=20)'"

echo
echo "--- Libraries ---"
check "libbpf-dev headers"        test -f /usr/include/bpf/libbpf.h
check "libbpf.so"                 bash -c "ldconfig -p | grep -q libbpf"
check "libelf"                    bash -c "ldconfig -p | grep -q libelf"
check "zlib"                      bash -c "ldconfig -p | grep -q libz"

echo
echo "--- Runtime ---"
check "Running as root"           bash -c "[ \$(id -u) -eq 0 ]"
check "podman installed"          which podman

echo
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
