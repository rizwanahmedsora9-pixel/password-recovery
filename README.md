# 🔐 AFAW — Android Forensic Acquisition Workbench

> Acquires and verifies mobile forensic images over the paths that do **not** require
> defeating the device's security — and proves what it read, in flight.

[![Auto-update README](https://github.com/rizwanahmedsora9-pixel/password-recovery/actions/workflows/update-readme.yml/badge.svg)](https://github.com/rizwanahmedsora9-pixel/password-recovery/actions/workflows/update-readme.yml)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/rizwanahmedsora9-pixel/password-recovery/pulls)
[![Last Commit](https://img.shields.io/github/last-commit/rizwanahmedsora9-pixel/password-recovery)](https://github.com/rizwanahmedsora9-pixel/password-recovery/commits/main)
[![Open Issues](https://img.shields.io/github/issues/rizwanahmedsora9-pixel/password-recovery)](https://github.com/rizwanahmedsora9-pixel/password-recovery/issues)
[![Stars](https://img.shields.io/github/stars/rizwanahmedsora9-pixel/password-recovery)](https://github.com/rizwanahmedsora9-pixel/password-recovery/stargazers)

---

## ✨ What it does

| Command | What it actually does |
|---|---|
| `afaw detect` | Enumerates USB devices from `/sys/bus/usb/devices` (or `lsusb`) and names the boot mode: ADB, fastboot, Qualcomm EDL, Unisoc/SPRD DFU, MediaTek preloader, Rockchip maskrom, Samsung Odin. |
| `afaw inspect` | Reads provenance only — `getprop` over ADB, `getvar` over fastboot. No user data. |
| `afaw acquire block` | Images a file or block device opened **`O_RDONLY`**, hashing while the bytes are in flight. Use it behind a hardware write blocker. |
| `afaw acquire adb` | Logical acquisition from a powered-on handset that has accepted this host's RSA key. Streams a `tar`, hashed as it lands. |
| `afaw verify` | Validates an extraction folder in place: manifest structure, declared vs. actual sizes, hashes, keybag sanity, and a full reconstruction of the extractor's log. |
| `afaw manifest` | Hashes an existing image and writes a `.ewc` carrying the hash — closes the gap when the original extractor recorded none. |

**Four rules, enforced in code rather than in documentation:**

1. **Read-only, always.** Every source is opened `O_RDONLY` and there is no write path
   to a source device anywhere in the package. `tests/test_acquire.py` asserts the
   descriptor physically rejects `os.write`.
2. **Authorization is mandatory.** No acquisition runs without a case number, an
   examiner and a stated legal basis. All three are persisted next to the evidence.
3. **Integrity is computed in flight,** never after the fact, and every digest is
   written into both the manifest and the append-only custody log.
4. **BootROM download modes are detected and refused.** See below.

---

## 🚫 What it will not do, and why

`detect` will happily tell you a phone is sitting in Qualcomm EDL or Unisoc DFU mode.
It will not drive it.

Reaching flash on a device in those modes means one of two things: a **BootROM exploit**
that defeats the chip's signature/auth check, or a **vendor-signed loader binary**. The
extraction in this repository is a worked example of the first — `EXTRACTION_ANALYSIS.md`
documents Oxygen's SPDT method exploiting the UNISOC BootROM to get EL3 code execution
and read the hardware keys out of secure storage.

Neither belongs in this tool. An unpatchable BootROM exploit is a device-compromise
capability rather than a forensic tool, and a loader pack is proprietary. Both are
precisely what licensed forensic products are licensed and accountable for. So the
refusal is a hard-coded policy in `afaw/policy.py` and `afaw/modes.py:REFUSED_MODES`,
with a test pinning each refused mode.

What this tool does instead, for a device in a download mode:

* `detect` — name the mode and the chipset, for your case notes
* `verify` — validate an image another tool already produced

If the device is yours, power it into Android, enable USB debugging, accept the RSA
prompt, and use `acquire adb`. If it is evidence and you hold legal authority, acquire
it with a licensed product.

> **Fastboot is *conditional*, not refused.** An unlocked bootloader means the owner
> removed the boundary themselves, so it is not a bypass. But note that fastboot has no
> partition-read command — it is a flash protocol — so `inspect fastboot` records
> provenance and stops there.

---

## 🚀 Getting started

### Prerequisites

* Python 3.9+ (standard library only — no third-party dependencies)
* Optional: Android platform-tools, for `acquire adb` / `inspect adb`

### Run it

```bash
# What is plugged in, and what mode is it in?
python3 -m afaw detect
python3 -m afaw detect --from-json examples/devices.sample.json   # rehearse

# Image a file or block device, read-only, with authorization on the record
python3 -m afaw acquire block \
    --source /dev/sdX --dest ./evidence --partition userdata \
    --manufacturer Infinix --model X6511 \
    --case 2026-114 --examiner "J. Doe" --basis "owner consent"

# Logical acquisition from a handset that accepted this host's key
python3 -m afaw acquire adb --serial ABC123 --dest ./evidence \
    --case 2026-114 --examiner "J. Doe" --basis "owner consent" --owner-consent

# Verify an extraction folder (exit 0 = PASS, 1 = FAIL)
python3 -m afaw verify . --json report.json --md report.md

# Hash an image whose extractor recorded no hash
python3 -m afaw manifest --image userData.bin --case 2026-114 --examiner "J. Doe"
```

### Tests

```bash
python3 -m unittest discover -s tests -v
```

86 tests, standard library only. They exercise real code paths — the ADB engine is
driven end to end by putting a stand-in `adb` on `PATH` and letting the production
`Popen` streaming loop run against it.

---

## 🔍 Verifying the extraction in this repository

This repo holds the artifacts of a real Oxygen Forensic Detective SPDT extraction.
`afaw verify .` reads them and reports:

```
🔴 error   NO_HASH_IN_MANIFEST     The manifest records no hash of any kind.
🟠 warning PARTITION_FILE_MISSING  manifest references 'userData.bin' but it is not in this folder.
🟠 warning LOG_ERROR               line 25064: [calculateFileHash] Error open file (hash)
```

That first line is the important one. The log shows Oxygen's hash stage failing at
`09:54:29.210` and then reporting `ExtractionStatus::Completed` 29 ms later, so
`device.ewc` carries no hash and the only integrity check left on that image is a byte
count. `afaw manifest` closes the gap.

The verifier reproduces every figure in `EXTRACTION_ANALYSIS.md` from the raw log
independently — 25,087 lines, 24,985 progress lines, 29 distinct bracketed tokens,
exactly one error at line 25,064, 9.668 MB/s overall throughput, and a largest read
stall of 1.503 s.

> ⚠️ `keys.json` holds three live 256-bit hardware keys. Every report this tool emits
> masks them to an unusable fingerprint, and `tests/test_verify.py` asserts no report
> ever contains a real key value.

---

## 📂 Layout

```
afaw/
  modes.py      USB VID/PID → boot mode, and the refusal table
  policy.py     Authorization gate; assert_acquirable() is the hard boundary
  integrity.py  O_RDONLY opens, in-flight hashing, size maths
  ewc.py        Oxygen-compatible .ewc reader/writer (byte-exact round trip)
  custody.py    Append-only, fsynced chain-of-custody log
  acquire.py    block / adb engines, fastboot inspection
  verify.py     Extraction-folder verification and log reconstruction
  cli.py        argparse front end
tests/          86 unittest tests
examples/       Sample USB payload for rehearsing `detect`
```

---

## 🤝 Contributing

Contributions are welcome! 🎉

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-change`
3. Commit your changes: `git commit -m "feat: my change"`
4. Push and open a pull request against `main`

Every PR automatically refreshes the live sections below. ✨

---

## 📊 Repository stats _(auto-updated)_

> ⚠️ Do not edit between the `START`/`END` markers — that content is generated automatically. Edit the surrounding text freely.

<!-- PR-STATS:START -->
| 📊 Metric | Count |
|---|---|
| Total pull requests | **2** |
| 🟢 Open | 0 |
| 🟣 Merged | 2 |
| 🔴 Closed (unmerged) | 0 |
| ⭐ Stars | 0 |
| 🍴 Forks | 0 |
| 🐞 Open issues | 0 |
<!-- PR-STATS:END -->

### 🆕 Recent pull requests _(auto-updated)_

<!-- RECENT-PRS:START -->
| PR | Title | Author | Status | Created | Last updated |
|---|---|---|---|---|---|
| [#2](https://github.com/rizwanahmedsora9-pixel/password-recovery/pull/2) | [docs: full technical breakdown of the SPDT extraction artifacts](https://github.com/rizwanahmedsora9-pixel/password-recovery/pull/2) | [@arena-ai-coding-agent[bot]](https://github.com/arena-ai-coding-agent[bot]) | 🟣 Merged | 2026-09-18 | 2026-09-18 |
| [#1](https://github.com/rizwanahmedsora9-pixel/password-recovery/pull/1) | [Add self-updating README (auto-refreshes on every PR)](https://github.com/rizwanahmedsora9-pixel/password-recovery/pull/1) | [@arena-ai-coding-agent[bot]](https://github.com/arena-ai-coding-agent[bot]) | 🟣 Merged | 2026-09-18 | 2026-09-18 |

_Showing the 2 most recently updated PRs. [View all](https://github.com/rizwanahmedsora9-pixel/password-recovery/pulls)_
<!-- RECENT-PRS:END -->

### 👥 Contributors _(auto-updated)_

<!-- CONTRIBUTORS:START -->
<p align="left">
  <a href="https://github.com/arena-ai-coding-agent[bot]"><img src="https://github.com/arena-ai-coding-agent[bot].png?size=100" width="60" height="60" alt="arena-ai-coding-agent[bot]" /></a>
  <a href="https://github.com/rizwanahmedsora9-pixel"><img src="https://github.com/rizwanahmedsora9-pixel.png?size=100" width="60" height="60" alt="rizwanahmedsora9-pixel" /></a>
  <a href="https://github.com/github-actions[bot]"><img src="https://github.com/github-actions[bot].png?size=100" width="60" height="60" alt="github-actions[bot]" /></a>
</p>

- [@arena-ai-coding-agent[bot]](https://github.com/arena-ai-coding-agent[bot]) — 4 contributions
- [@rizwanahmedsora9-pixel](https://github.com/rizwanahmedsora9-pixel) — 4 contributions
- [@github-actions[bot]](https://github.com/github-actions[bot]) — 3 contributions
<!-- CONTRIBUTORS:END -->

<!-- LAST-UPDATED:START -->
_Last updated: **2026-09-18 07:01 UTC** — this README refreshes itself automatically on every pull request via the [Auto-update README](https://github.com/rizwanahmedsora9-pixel/password-recovery/actions/workflows/update-readme.yml) workflow._
<!-- LAST-UPDATED:END -->

---

## ⚙️ How does this README stay up to date?

This README contains **live sections** (stats, recent PRs, contributors, timestamp) delimited by HTML comment markers such as:

```html
<!-- SECTION-NAME:START -->
...generated content...
<!-- SECTION-NAME:END -->
```

The [`Auto-update README`](.github/workflows/update-readme.yml) GitHub Actions workflow:

1. Runs **on every pull request** (`opened`, `closed`, `reopened`, `ready_for_review`), plus on pushes to `main`, daily on a schedule, and manually.
2. Runs [`.github/scripts/update_readme.py`](.github/scripts/update_readme.py), which fetches the latest PRs / stats / contributors from the GitHub API (standard library only, no dependencies).
3. Commits and pushes the refreshed `README.md` back to `main` — with `[skip ci]` and loop guards so the bot never triggers itself.

To list more/fewer PRs, set the `MAX_PRS` environment variable in the workflow (default: `10`).

---

## 📄 License

_(edit me — e.g. MIT, Apache-2.0… or add a `LICENSE` file.)_
