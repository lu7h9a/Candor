# SysScope Makefile. Target names are fixed by .claude/skills/sysscope/SKILL.md section 6.
# Rules: never run cargo/rustup/git under sudo. Root tests build as the user and run
# the test binaries through a "sudo -E" runner.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
# rustup's toolchain must win over Debian's /usr/bin/cargo.
export PATH := $(HOME)/.cargo/bin:$(PATH)

CARGO ?= cargo
DISTRO ?= debian12
BPF_DIR := crates/sysscoped/bpf
# Packages from docs/MASTER_PLAN.md section 2 (official Kali repos only).
APT_PKGS := build-essential clang llvm lld libelf-dev zlib1g-dev libzstd-dev pkg-config bpftool \
	linux-headers-$(shell uname -r) libbpf-dev make git python3 strace qemu-system-x86 qemu-utils \
	cloud-image-utils genisoimage openssh-client xvfb mesa-utils libgl1-mesa-dri libxkbcommon-dev \
	libwayland-dev libx11-dev libxcursor-dev libxi-dev libxrandr-dev libfontconfig-dev bubblewrap \
	libseccomp-dev clang-format rpm dpkg-dev fakeroot jq hyperfine

.PHONY: setup build test test-root lint bench vm-test vm-matrix gui-shot fuzz vm-hostile \
	fp-eval package gate integrity

setup:
	@if ! sudo -n true 2>/dev/null; then \
		echo "make setup: passwordless sudo is not available (see NEEDS_USER.md Q1)."; \
		echo "Install the packages yourself with:"; \
		echo "  sudo apt-get install -y $(APT_PKGS)"; \
		exit 1; \
	fi
	sudo apt-get install -y $(APT_PKGS)
	@command -v rustup >/dev/null || { echo "install rustup with the official installer first"; exit 1; }
	rustup show active-toolchain

build:
	$(CARGO) build --workspace --all-targets

# Unprivileged tests only. The root integration tests live in sysscope-itest and
# run through `make test-root`; they are excluded here, not ignored.
test: integrity
	$(CARGO) test --workspace --exclude sysscope-itest

test-root:
	@sudo -n true 2>/dev/null || { echo "make test-root: needs passwordless sudo (NEEDS_USER.md Q1)"; exit 1; }
	CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="sudo -E" \
		$(CARGO) test -p sysscope-itest -- --test-threads=1

lint:
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --workspace --all-targets -- -D warnings
	@bpf_files=$$(find $(BPF_DIR) -name '*.c' -o -name '*.h' 2>/dev/null | grep -v '/vmlinux/' || true); \
	if [ -n "$$bpf_files" ]; then \
		command -v clang-format >/dev/null || { echo "lint: clang-format missing (NEEDS_USER.md Q1)"; exit 1; }; \
		clang-format --dry-run --Werror $$bpf_files; \
	else echo "lint: no BPF C files yet"; fi

integrity:
	scripts/check-integrity.sh

bench:
	@echo "make bench: not implemented yet (WP14)"; exit 1

vm-test:
	@echo "make vm-test: not implemented yet (WP03/WP04)"; exit 1

vm-matrix:
	@echo "make vm-matrix: not implemented yet (WP31)"; exit 1

gui-shot:
	@echo "make gui-shot: not implemented yet (WP20)"; exit 1

fuzz:
	@echo "make fuzz: not implemented yet (WP29)"; exit 1

vm-hostile:
	@echo "make vm-hostile: not implemented yet (WP25)"; exit 1

fp-eval:
	@echo "make fp-eval: not implemented yet (WP18)"; exit 1

package:
	@echo "make package: not implemented yet (WP30)"; exit 1

gate: lint test test-root bench vm-test
	@echo "GATE PASSED"
