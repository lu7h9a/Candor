# Running a real or suspected malware sample

Glasshouse on your own machine is **not** for this. It shares your kernel,
and a real sample may exploit it:

> Glasshouse is a behaviour-demonstration sandbox, not a malware containment system. The program you run shares this computer's kernel. A kernel or sandbox vulnerability, a CPU side-channel, or a mistake in configuration could let it read your data or take over your account or the machine. Glasshouse does not hide that it is a sandbox, so a program may behave differently inside it. Run only programs you would accept losing this machine to, such as your own test scripts. For real or suspected malware use a dedicated virtual machine or a separate computer with no network, following docs/REAL_SAMPLES.md.

`vm/detonate.sh` does that for you: it runs the sample in Glasshouse
*inside a throw-away virtual machine that has no network*, and brings back
only a text report. Follow these steps exactly.

1. **Get the sample yourself, still inside its password-protected zip.**
   SysScope never downloads, links to or fetches samples.
   *Why:* an archive with a password (sample collections use "infected")
   cannot be opened by accident, scanned and quarantined mid-copy, or run by
   a double click.

2. **Keep the zip in its own folder that only you can read:**
   `mkdir -m 700 ~/sysscope-quarantine` and move it there. Do not extract it.
   *Why:* the sample stays an inert blob on the host; nothing on the host
   ever needs to open it.

3. **The zip must hold exactly one file and use classic zip encryption**
   (what `zip -P` makes; not AES/7z).
   *Why:* the guest extracts it with Python's zipfile module, which reads
   only that format, and one file means there is no doubt what was run.

4. **Build the detonation guest once:** `make release` then
   `vm/build-detonation-image.sh` (re-run after every SysScope update).
   *Why:* this step has network access, so it happens before any sample
   exists. It installs bubblewrap and SysScope into a Debian 12 disk, disables
   cloud-init and SSH, and leaves an autorun unit that acts only when a sample
   disc is attached.

5. **Close VirtualBox and other VMs, then run**
   `vm/detonate.sh ~/sysscope-quarantine/sample.zip infected 60`.
   The arguments are the archive, its password and the timeout in seconds
   (1 to 600).
   *Why:* the script refuses to start without KVM or while a VirtualBox VM
   runs. Two hypervisors on one CPU are unreliable, and a half-working VM is
   the wrong place for malware.

6. **What the script does** (you do not need to do anything):
   - it copies the zip into a read-only CD image;
   - it boots the guest with `-snapshot` (every disk write is thrown away),
     `-nic none` (no network card at all), `-nodefaults` (no USB, no extra
     devices), no shared folders and no clipboard;
   - it gives the guest a second serial port that writes to a file on the host.

   *Why:* the only path out of the guest is that serial file. There is no
   network to spread over and no shared disk to write to, and the guest's own
   disk is discarded at power-off.

7. **Inside the guest** the autorun unit extracts the sample, runs it in
   Glasshouse with your timeout, writes the JSON report to the serial port
   and powers off.
   *Why:* Glasshouse inside the VM still gives the decoys, the trace and the
   differ, and the VM wall around it means a sandbox escape only reaches a
   disposable machine.

8. **The host kills QEMU at timeout + 60 s no matter what.**
   *Why:* a sample that hangs the guest, or stops it from powering off,
   cannot keep running.

9. **The report comes back as untrusted text.** The script reads at most
   64 MiB from the serial file, takes only the marked block, parses it
   strictly, and prints it through `sysscope glasshouse report` (all text
   escaped). The QEMU command line is in `report-header.txt` next to
   `report.json` under `~/.cache/sysscope-vm/detonate/<date>/`.
   *Why:* the sample controls file names and contents in the report. Strict
   parsing and escaping stop it from attacking your terminal, and the header
   proves which isolation options were used.

10. **Never do these, even "just once":**
    - never add a network device;
    - never mount or open the guest disk on the host;
    - never copy anything out of the guest except through the serial report;
    - never run the sample on the host.

    *Why:* each of these removes one of the walls above. Mounting an
    attacker-written filesystem is an attack on your host kernel by itself.

## Remaining risk, plainly

Hypervisor escapes (from the guest into QEMU/KVM) exist, though they are
rare and valuable. Keep your host and QEMU patched. If the sample is
important to someone, use a separate computer that you can wipe.
