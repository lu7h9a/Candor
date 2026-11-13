# ENV.md - build host environment (recorded in WP00, 2026-11-13)

All values below were read on the host in this session. Re-check anything marked "re-check" when the noted WP starts.

## Host

| Item | Value | How read |
|---|---|---|
| Kernel | `6.19.14+kali-amd64`, x86_64 | `uname -r; uname -m` |
| Distro | apt sources point at `http://http.kali.org/kali kali-rolling`. **Oddity:** `/etc/os-release` says `Ubuntu 24.04 LTS (Noble Numbat)`. Recorded as found, not explained. Package candidates come from the Kali repository. | `/etc/os-release`, `/etc/apt/sources.list` |
| glibc | 2.43 (Debian GLIBC 2.43-4) | `ldd --version` |
| CPU | 13th Gen Intel Core i5-13420H, 12 logical CPUs, governor `powersave` | `lscpu`, `scaling_governor` |
| CLK_TCK | 100 | `getconf CLK_TCK` |
| BTF | `/sys/kernel/btf/vmlinux` present, world-readable, 5 308 991 bytes | `ls -la` |
| cgroup | v2 (`cgroup2fs`); controllers `cpuset cpu io memory hugetlb pids rdma misc` | `stat -fc %T /sys/fs/cgroup` |
| systemd | 260 (260.1-1) | `systemctl --version` |
| Display | X11, `DISPLAY=:0` | env |
| Disk free | 78 GB free on `/` (452 GB, 82% used) | `df -h` |
| RAM | 15 634 MiB total, 5 453 MiB available at probe time. **Below the 6 GiB E5 line** - re-check with `free -m` against 6144 when a VM WP starts (WP03). | `free -m` |
| Swap | 19 GiB | `free -g` |

## Privilege and kernel knobs

| Item | Value |
|---|---|
| `sudo -n true` | **fails: "a password is required"** -> escalated as NEEDS_USER Q1 (E1) |
| `kernel.unprivileged_userns_clone` | 1 |
| `kernel.perf_event_paranoid` | 3 |
| `kernel.unprivileged_bpf_disabled` | 2 (every BPF load needs root on this host) |
| `/dev/kvm` | `crw-rw----+ root kvm`; user is **not** in group `kvm`, access is via the POSIX ACL (`+`); read+write test succeeds as the user |
| KVM modules | `kvm_intel`, `kvm` loaded |
| VirtualBox | `VBoxManage` installed; modules `vboxdrv`, `vboxnetflt`, `vboxnetadp` loaded; `VBoxManage list runningvms` empty at probe time |

## Toolchain

| Tool | Version | Note |
|---|---|---|
| rustup | 1.29.3 | installed in WP00 with the official installer, `--no-modify-path --profile minimal -c clippy -c rustfmt` into `~/.cargo`, `~/.rustup` |
| rustc / cargo | 1.100.0 (2026-11-09) stable via rustup | Debian's `/usr/bin/rustc` 1.94.1 also exists; the Makefile prepends `$HOME/.cargo/bin` to PATH so rustup's toolchain always wins |
| clang | Debian clang 21.1.8 | |
| llvm-strip | `/usr/lib/llvm-21/bin/llvm-strip` (not on PATH) | |
| bpftool | v7.8.0, libbpf v1.8 | |
| qemu-system-x86_64 | 10.2.2 | |
| qemu-img | 11.1.0 | |
| bubblewrap | 0.12.0 | |
| python3 | 3.14.7 | |
| GNU make | 4.4.1 | |
| git | 2.53.0 | |
| gh | 2.103.0, logged in as `lu7h9a` | |
| genisoimage | 1.1.11 | used instead of `cloud-localds` for cloud-init seed ISOs |
| rpm | 6.1.0 | |
| dpkg-deb | 1.23.7 | |
| pkg-config | 2.5.1 | |
| Xvfb / xvfb-run | present | |
| libbpf-rs / libbpf-cargo / libbpf-sys | 0.27.2 / 0.27.2 / 1.7.0+v1.7.0 (latest on crates.io at WP00) | |

## Pre-authorised packages: present vs missing

Present: build-essential, clang, bpftool, linux-headers-6.19.14+kali-amd64, make, git, python3, qemu-system-x86, qemu-utils, genisoimage, openssh-client, xvfb, libgl1-mesa-dri, libxkbcommon-dev, libx11-dev, libfontconfig-dev, zlib1g-dev, rpm, dpkg-dev, fakeroot, pkg-config, bubblewrap.

Missing (cannot install without sudo, see Q1): libelf-dev, libzstd-dev, libbpf-dev, libseccomp-dev, strace, jq, hyperfine, clang-format, cloud-image-utils, lintian, lld.

Runtime `libelf.so.1` (0.196) and `libz.so` exist; only the libelf development headers/symlink are missing.

## WP00 Verify

- `rustc --version && clang --version && bpftool version && qemu-system-x86_64 --version && bwrap --version` all succeed (see PROGRESS.md log).
- A minimal `tp_btf/sched_process_exec` program compiled with `clang -O2 -g -target bpf -D__TARGET_ARCH_x86` against a `vmlinux.h` dumped from the host BTF, using the libbpf headers vendored inside the `libbpf-sys 1.7.0` crate (system `libbpf-dev` is absent). Not loaded (needs root).
