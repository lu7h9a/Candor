# Candor Makefile. Target names are fixed by .claude/skills/candor/SKILL.md section 6.
# Rules: never run cargo/rustup/git under sudo. Root tests build as the user and run
# the test binaries through a "sudo -E" runner.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
# rustup's toolchain must win over Debian's /usr/bin/cargo.
export PATH := $(HOME)/.cargo/bin:$(PATH)

CARGO ?= cargo
# libelf headers for the vendored libbpf come from target/sysroot when
# libelf-dev is not installed system-wide (scripts/sysroot.sh).
SYSROOT := $(CURDIR)/target/sysroot
ifneq ($(wildcard $(SYSROOT)/usr/include/libelf.h),)
export LIBBPF_SYS_EXTRA_CFLAGS := -I$(SYSROOT)/usr/include
export LIBBPF_SYS_LIBRARY_PATH := $(SYSROOT)/usr/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu
endif
DISTRO ?= debian12
BPF_DIR := crates/candord/bpf
CLANG_FORMAT := $(or $(shell command -v clang-format),$(wildcard $(SYSROOT)/usr/lib/llvm-21/bin/clang-format))
# Packages from docs/MASTER_PLAN.md section 2 (official Kali repos only).
APT_PKGS := build-essential clang llvm lld libelf-dev zlib1g-dev libzstd-dev pkg-config bpftool \
	linux-headers-$(shell uname -r) libbpf-dev make git python3 strace qemu-system-x86 qemu-utils \
	cloud-image-utils genisoimage openssh-client xvfb mesa-utils libgl1-mesa-dri libxkbcommon-dev \
	libwayland-dev libx11-dev libxcursor-dev libxi-dev libxrandr-dev libfontconfig-dev bubblewrap \
	libseccomp-dev clang-format rpm dpkg-dev fakeroot jq

.PHONY: setup build test test-root lint bench vm-test vm-matrix gui-shot fuzz vm-hostile \
	fp-eval package gate integrity sysroot release wl itest-bin

setup:
	@if ! sudo -n true 2>/dev/null; then \
		echo "make setup: passwordless sudo is not available (a sudoers rule for your user is needed)."; \
		echo "Install the packages yourself with:"; \
		echo "  sudo apt-get install -y $(APT_PKGS)"; \
		exit 1; \
	fi
	sudo apt-get install -y $(APT_PKGS)
	@command -v rustup >/dev/null || { echo "install rustup with the official installer first"; exit 1; }
	rustup show active-toolchain

sysroot:
	scripts/sysroot.sh

build: sysroot
	$(CARGO) build --workspace --all-targets

release: sysroot
	$(CARGO) build --workspace --release

# Ground-truth workload, linked statically so it runs in every test VM.
wl:
	mkdir -p target/testkit target/release
	gcc -static -O2 -Wall -Wextra -Werror -pthread -o target/testkit/wl testkit/wl/wl.c
	cp target/testkit/wl target/release/candor-wl

# Root integration test binaries copied next to the daemon as
# target/release/candor-itest-<name>, so vm/run.sh ships them to guests.
itest-bin: release wl
	$(CARGO) test -p candor-itest --release --no-run --message-format=json 2>/dev/null | \
		python3 -c 'import json,sys,shutil,os; \
[shutil.copy(m["executable"], "target/release/candor-itest-" + m["target"]["name"]) \
 for m in map(json.loads, sys.stdin) \
 if m.get("reason") == "compiler-artifact" and m.get("executable") and m["target"]["kind"] == ["test"]]'
	ls target/release/candor-itest-*

# Unprivileged tests only. The root integration tests live in candor-itest and
# run through `make test-root`; they are excluded here, not ignored.
test: integrity sysroot
	$(CARGO) test --workspace --exclude candor-itest -- --skip no_frame_over_50ms_with_2000_processes
	@# The GUI frame-time budget (50 ms) is measured on the optimised build
	@# users run, not the debug build (owner's choice H, WP32: on 2-CPU CI
	@# runners the debug build drew a 56 ms frame).
	$(CARGO) test --release -p candor-gui --test stress

test-root: release wl
	@sudo -n true 2>/dev/null || { echo "make test-root: needs passwordless sudo"; exit 1; }
	CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="sudo -E" \
		$(CARGO) test -p candor-itest --release -- --test-threads=1

lint: sysroot
	scripts/check-claims.sh
	scripts/check-theme.sh
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --workspace --all-targets -- -D warnings
	@bpf_files=$$(find $(BPF_DIR) -name '*.c' -o -name '*.h' 2>/dev/null | grep -v '/vmlinux/' || true); \
	if [ -n "$$bpf_files" ]; then \
		[ -n "$(CLANG_FORMAT)" ] || { echo "lint: clang-format missing (run make sysroot)"; exit 1; }; \
		$(CLANG_FORMAT) --dry-run --Werror $$bpf_files; \
	else echo "lint: no BPF C files yet"; fi

integrity:
	scripts/check-integrity.sh

bench: release wl
	python3 bench/run.py

# Root tests inside a throw-away guest (SKILL.md: new BPF is loaded in a VM first).
vm-test: release itest-bin
	@set -e; for t in vm/tests/wp*.sh; do \
		echo "== vm-test $(DISTRO) $$t"; \
		vm/run.sh $(DISTRO) "$$(cat $$t)"; \
	done; vm/down.sh $(DISTRO)

# Plan WP31: install the package in each distro and run the itest subset,
# a simulator per rule, the CLI export and the Glasshouse demo; writes
# docs/COMPAT.md. Needs target/packages from `make package`.
vm-matrix:
	@set -e; for d in debian12 ubuntu2204 ubuntu2404 fedora arch; do \
		echo "== vm-matrix $$d"; vm/matrix.sh $$d; done
	python3 scripts/compat.py

gui-shot: sysroot
	$(CARGO) build -p candor-gui -p candor-cli
	scripts/gui-shots.sh

# Plan WP29 (b): every target for FUZZ_SECONDS (default 600), zero crashes.
# Needs the nightly toolchain and cargo-fuzz (pre-authorised, plan section 2).
FUZZ_TARGETS = frame bstr_unescape abi_decode rules_toml record ghreport
FUZZ_SECONDS ?= 600
fuzz:
	@set -e; cd fuzz; for t in $(FUZZ_TARGETS); do \
		echo "== fuzz $$t ($(FUZZ_SECONDS) s)"; \
		rc=0; $(CARGO) +nightly fuzz run $$t -- -max_total_time=$(FUZZ_SECONDS) \
			-print_final_stats=1 > ../target/fuzz-$$t.log 2>&1 || rc=$$?; \
		grep -E "Done [0-9]+ runs|SUMMARY|panicked" ../target/fuzz-$$t.log || true; \
		[ $$rc -eq 0 ] || { echo "fuzz $$t FAILED (rc $$rc), see target/fuzz-$$t.log"; exit 1; }; \
	done

vm-hostile: release
	vm/hostile.sh debian12 && vm/down.sh debian12
	vm/hostile.sh ubuntu2204 && vm/down.sh ubuntu2204
	vm/hostile.sh ubuntu2404 && vm/down.sh ubuntu2404

# Benign corpus (plan 5.7(3)): records each workload on this host and in the
# debian12 VM, replays it, writes docs/FP_REPORT.md. Host recordings stay in
# target/fp (never committed); VM ones become fixtures/benign regression tests.
fp-eval: release
	scripts/fp-eval.sh host
	vm/run.sh debian12 "$$(cat vm/tests/wp00_tools.sh)" > /dev/null
	vm/run.sh debian12 "mkdir -p /opt/candor/repo/scripts /opt/candor/repo/testkit/benign
	$$(vm/embed.sh scripts/fp-eval.sh:/opt/candor/repo/scripts/fp-eval.sh $$(for f in testkit/benign/*.sh; do printf '%s:/opt/candor/repo/%s ' $$f $$f; done))
	apt-get -qq install -y rsync zip unzip curl git make gcc python3-venv > /dev/null 2>&1
	bash /opt/candor/repo/scripts/fp-eval.sh vm-guest"
	mkdir -p target/fp/vm; for w in git_build tar_zip rsync_tree editor_save pip_venv curl_local ssh_localhost apt; do \
		vm/run.sh debian12 "cat /opt/candor/repo/target/fp/vm/$$w.summary.json" > target/fp/vm/$$w.summary.json; \
		vm/run.sh debian12 "cat /opt/candor/repo/target/fp/vm/$$w.events.jsonl" > target/fp/vm/$$w.events.jsonl; done
	vm/down.sh debian12
	scripts/fp-eval.sh report

# Plan WP30: .deb, .rpm, tarball and Arch PKGBUILD, built in an ubuntu2204
# guest (oldest supported glibc); output in target/packages.
package:
	vm/package.sh

gate: lint test test-root bench vm-test
	@echo "GATE PASSED"
