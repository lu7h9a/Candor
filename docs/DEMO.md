# 60-second demo

A short screen recording that shows what SysScope does. `scripts/demo.sh`
stages everything, so the recording needs only clicks. Everything it runs is a
harmless simulator from `testkit/sim/`, and it removes what it created when
it ends.

## Before recording

```text
sudo systemctl start sysscoped
sysscope-gui &
scripts/demo.sh
```

Record the real desktop at 1080p. Keep the yellow Glasshouse warning visible
whenever the Glasshouse page is on screen.

## Script

| Time | On screen |
|---|---|
| 0–10 s | The GUI, system-wide, the table updating. Sort by **conns**. |
| 10–25 s | Click a browser. Show its **Files**, **Network** and **Syscalls** tabs. Press **Follow this process tree**, then stop following. |
| 25–40 s | Press Enter in the `demo.sh` terminal. A program reads a fake private SSH key, and another runs from `/tmp`. Two alerts appear (R001 credential read, R002 temp-folder execution). Open one and show its explanation and the evidence events. |
| 40–60 s | **Glasshouse** page, **Browse**, choose `testkit/sim/fake_malware.py`, **Run in Glasshouse**. The decoy tiles change as it runs (keys read, documents encrypted and renamed, photos deleted). Scroll the before/after report. |

## Notes

- The plan's script ran the beaconing simulator at 25–40 s. That simulator
  only talks to this computer (127.0.0.1), and the beaconing rule rightly
  ignores local connections outside tests. The demo shows the temp-folder
  rule instead (docs/DEVIATIONS.md).
- `fake_malware.py` refuses to run anywhere except inside Glasshouse. It
  checks for the sandbox's decoy home and hostname.
- On Ubuntu 24.04, Glasshouse is unavailable with the default AppArmor policy;
  the page says why. Record on Debian, Fedora, Arch or Ubuntu 22.04.
