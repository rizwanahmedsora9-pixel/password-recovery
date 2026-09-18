# How This Extraction Was Made — Full Technical Breakdown

**Extraction:** `SPDT-2026-09-18-09-00-01`
**Target:** Infinix Smart 6 (`X6511`), Unisoc SC9863A ("SharkL3")
**Tool:** Oxygen Forensic Detective → **DeviceExtractor 2.17.1.1105** [Dec 2 2024] (build `e0ddc423f`)
**Host:** Windows 10 Version 2009 x86_64 · Sale ID `12345` · locale flag `-lng:NTV`
**Window:** 18-09-2026 08:59:45 → 09:55:48 local (**UTC+5**)

---

# Part 1 — How it was made

This is Oxygen's **SPDT method** (`ExtractionMethod=SPDT_Method`), their UNISOC/Spreadtrum
physical acquisition. "SPDT" is Oxygen's own label — `ChainType` in `keys.json` is the hex
string `53504454`, which is literally the ASCII bytes for `SPDT`.

It works because UNISOC SoCs contain a **BootROM-level download mode** (DFU) intended for
factory firmware flashing. Oxygen exploits a vulnerability in that low-level proprietary
protocol. The flaw lives in the BootROM, so it cannot be patched by an OTA update.

## The eight steps, reconstructed from the log

### 1. App start and profile lookup — 08:59:45

```
08:59:45.825  [loadDataFromFile] Path: :/Database/MainBase.db
08:59:45.917  [loadDataFromFile] File loaded: 24162304 bytes
08:59:45.920  SQL = select count(*) from RawData;
08:59:46.813  SQL = select FieldUID, ValueUID, Value from CachedValues;
```

DeviceExtractor loads its 24 MB device-profile database (an embedded SQLite resource) and
queries the `RawData` table for supported vendor/model/method combinations. This is how it
knows which loader pack to use for an Infinix Smart 6.

### 2. Task setup — 09:00:01

```
09:00:01.908  Property::DestinationPath   = D:/forensic/POP5
09:00:02.097  Property::TargetFolder      = D:\forensic\POP5\SPDT-2026-09-18-09-00-01
09:00:02.165  Property::TargetFilePathData= ...\SPDT-2026-09-18-09-00-01\SPDT.bin
09:00:02.165  Property::TargetFilePathEWC = ...\SPDT-2026-09-18-09-00-01\device.ewc
09:00:02.165  Property::DetectedDeviceName= Smart 6
09:00:02.165  [SPDT_Extractor::execute_V2] BaseProfile = SharkL3_sam
```

Four stages are declared but immediately set `ExtractionState::Hidden` — `RunFDL`,
`ConnectRootBoot`, `RunRootBoot`, `WaitAndroid`. They exist in the generic extractor
framework but this device profile does not use them. All the real work goes through
`PatchBoot` instead.

### 3. Wait for the phone in DFU mode — 09:00:02 → 09:00:10

```
09:00:02.166  Stage::DeviceConnection WaitingManual
              "Connect the device via USB in DFU mode"
09:00:02.492  [SPDT_Extractor::STG_ConnectDevice] Disconnected
09:00:10.569  [waitConnectedSPDTDevice] [Success] Found connected device: COM16 6&3391380f&0&2
```

The phone was powered off and plugged in while holding a volume key, dropping it into the
UNISOC chipset DFU mode. It enumerates as a USB serial port — **COM16**, USB instance ID
`6&3391380f&0&2`. The examiner took ~8 seconds to do this.

At this point **Android is not running**. That matters: the userdata partition is still
encrypted and nothing on the phone can help decrypt it.

### 4. BootROM exploit and loader chain — 09:00:13 → 09:00:22

This is the core of the method. Five files are pushed to the device:

```
09:00:13.244  [SPDT_Extractor::STG2_BootRom]  SPDT: platform = SharkL3

  C:\Program Files (x86)\Oxygen Forensics\Spreadtrum_Image_pack\Spreadtrum\20\SharkL3_sam\

09:00:15.365    fdl1_ptch.bin
09:00:17.987    fdl1_ptch.dram.bin
09:00:18.013    sml-sign.bin
09:00:18.678    teecfg-sign.bin
09:00:21.904    fdl2_ptch.bin
```

| File | Role |
|---|---|
| `fdl1_ptch.bin` | **FDL1** — first-stage flash downloader. Loaded by the BootROM. `_ptch` = Oxygen's patched build. |
| `fdl1_ptch.dram.bin` | DRAM initialisation blob — brings up RAM so the larger second stage can run. |
| `sml-sign.bin` | **SML** (Secure Monitor Layer) — UNISOC's TrustZone secure monitor, signed. Reaching EL3 is what makes key extraction possible. |
| `teecfg-sign.bin` | TEE configuration, signed — sets up the trusted execution environment. |
| `fdl2_ptch.bin` | **FDL2** — second-stage downloader, now running from DRAM. This is the agent that reads flash and talks back over the serial link. |

The `Spreadtrum\20\` path segment is a version/revision folder inside Oxygen's loader pack;
I can't confirm from the log what `20` denotes.

Exploiting the BootROM yields arbitrary code execution at **EL3** (highest privilege, above
the hypervisor and the TEE). That privilege level is what lets Oxygen read the hardware keys
out of secure storage — something normal Android, and even root, cannot do.

### 5. Hardware keys pulled — 09:00:34.737

```
09:00:34.737  [storeJsonFile] [Enter]
09:00:34.786  [storeJsonFile] [Leave]
```

**12.8 seconds after FDL2 started running**, the keybag is written to `keys.json`. The keys
are read from the device's secure hardware while running at EL3, over the serial link.

Note the ordering: this happens **before a single byte of the dump is read**. That is why
the later `STG_ExtractHardwareKeys` stage completes instantly — the keys were already in hand.

All of this runs in RAM. Nothing is written to the handset; on reboot or battery pull the
phone returns to its original state. The method is non-destructive.

### 6. Manifest written (first pass) — 09:00:34.812

```
09:00:34.812  [SPDT_Extractor::writeEWCFile] [Enter]
09:00:34.951  [SPDT_Extractor::writeEWCFile] [Leave]
```

`device.ewc` is created with device identity, method and start time. It will be rewritten
at the end once the size is known.

### 7. The physical dump — 09:00:34.951 → 09:54:29.174

```
09:00:34.951  Stage::ReadFullDump  InProgress
09:00:35.063  Stage::ReadFullDump  ProgressTotal changed: 31268536320
   ... 12,688 size samples, 1000 progress ticks ...
09:54:29.157  Stage::ReadFullDump  ProgressPos  changed: 1000
09:54:29.157  Stage::ReadFullDump  ProgressSize changed: 31268536320
09:54:29.174  Stage::ReadFullDump  Completed
09:54:29.174  Property::ExtractionSize = 31268536320
```

FDL2 reads the flash and streams it over USB serial to `SPDT.bin`.

**Throughput was flat the entire way:**

| Period | MB/s |
|---|---|
| 0–5 min | 9.80 |
| 5–10 | 9.82 |
| 10–15 | 9.48 |
| 15–20 | 9.86 |
| 20–25 | 9.71 |
| 25–30 | 9.63 |
| 30–35 | 9.59 |
| 35–40 | 9.49 |
| 40–45 | 9.66 |
| 45–50 | 9.71 |
| 50–55 | 9.58 |

Median 0.043 s between size samples. **Largest gap in the entire run: 1.503 s** (at
09:34:38, and it still moved 5,529,600 bytes). Zero gaps over 5 s, zero over 10 s, zero
retries. ~9.7 MB/s is normal for USB serial on this hardware — this is a serial link, not
a block device.

### 8. Hash, finalize, hand off — 09:54:29 → 09:55:48

```
09:54:29.174  Stage::CalcExtractionHashes  InProgress
09:54:29.174  [calculateFileHash] File path = ...\SPDT.bin
09:54:29.210  [calculateFileHash] Error open file (hash)      ← FAILED
09:54:29.239  Stage::CalcExtractionHashes  Completed          ← reported success anyway
09:54:29.239  [writeEWCFile] [Enter]   (second pass — writes end time + size)
09:54:29.520  [writeEWCFile] [Leave]
09:54:29.520  Stage::STG_ExtractHardwareKeys  InProgress → Completed   (same millisecond)
09:54:29.520  ExtractionStatus::Completed
09:55:48.654  [wg_RunningScenarioResults::clickImportEwc] → sendMessageToOFCX
09:55:48.713  Application terminated
```

The examiner clicked "Import" ~79 seconds later, which passed the `.ewc` to Oxygen Forensic
Detective (OFCX) through the JET engine.

---

# Part 2 — Every file

## `device.ewc` — 424 bytes

Plain-text INI, **CRLF line endings, no BOM**, ends `=1\r\n\r\n`. It is a *manifest* — a
pointer file, no image data. Detective reads this first and follows the references.

```ini
[BaseInfo]
ContentType=ANDROID_IMAGE
ExtractionEndUtc=20260918T045429
ExtractionMethod=SPDT_Method
ExtractionStartUtc=20260918T040001
InternalModelName=X6511
ProductName=DeviceExtractor
ProductVersion=2.17.1

[DeviceInfo]
DeviceAlias=Smart 6
Manufacturer=Infinix

[ExtendedInfo]
KeyBagFile=keys.json
Partition 1 File=userData.bin
Partition 1 Name=userData
Partition 1 Size=31268536320
PartitionsCount=1
```

Three sections, **14 keys** (7 in `BaseInfo`, 2 in `DeviceInfo`, 5 in `ExtendedInfo`).
`KeyBagFile` → `keys.json`. `Partition 1 File` → `userData.bin`.
**There is no hash field of any kind** — no `Hash`, `MD5`, or `SHA` key. Confirmed by
byte-level inspection of all 424 bytes.

## `keys.json` — 274 bytes

Single line, **no trailing newline**, UTF-8. The FBE hardware keybag.

```json
{"SPRD_UK_KEY": "8efd5a4f7d77bcbd…",
 "SPRD_GK_KEY": "d6fae58596af3841…",
 "SPRD_KM_KEY": "fb0f8a586a275130…",
 "ChainType": "53504454"}
```

| Key | Length | Role |
|---|---|---|
| `SPRD_UK_KEY` | 64 hex = **32 bytes** | User/unlock key |
| `SPRD_GK_KEY` | 64 hex = **32 bytes** | Gatekeeper — bound to the lockscreen credential |
| `SPRD_KM_KEY` | 64 hex = **32 bytes** | Keymaster — hardware root of trust |
| `ChainType` | `53504454` = ASCII `SPDT` | Identifies the key-derivation chain |

All three keys are complete, lowercase hex, exactly 32 bytes each. Nothing truncated,
nothing zeroed. This is a **successful** key extraction.

## `extraction_SPDT_2026-09-18 09-00-01.log` — 3,334,798 bytes / 25,087 lines

CRLF, valid UTF-8, no BOM. Qt debug log from DeviceExtractor.

| Content | Lines |
|---|---|
| `setStageProgress` lines | 24,985 |
| — of which carry a parseable progress value | 24,965 |
| — of which are stage state transitions | 20 |
| Qt warnings/debug (UI noise) | 51 |
| **Substantive events** | **51** |

99.8% of the file is progress ticks. I enumerated **every distinct bracketed token** in the
log: **29** in total — 15 `Class::method` names (`SPDT_Extractor::execute_V2`,
`BaseExtractor::setStageProgress`, `SQLiteStatement::prepare`, …), 2 Qt log categories
(`Qt::Warning`, `Qt::Debug`), 6 free-function names (`calculateFileHash`,
`storeJsonFile`, `loadDataFromFile`, `sendMessageToOFCX`, `startJetEngineTask`,
`prepareStudioMessage`), and 6 plain log markers (`[Enter]`, `[Leave]`, `[Success]`,
`[Value]`, `[string]`, `[int64]`). 15 + 2 + 6 + 6 = 29. All are accounted for in Part 1.
Nothing is hiding in there.

> **Correction, added when AFAW's log parser was written:** an earlier revision of this
> section said "17 `Class::method` names". The total of 29 was right; that breakdown was
> not. 15 of the qualified tokens are real `Class::method` names and the other 2 are
> `Qt::Warning` / `Qt::Debug`, which are Qt's own log categories, not DeviceExtractor
> methods. The split above is the accurate one, and `afaw verify` reports all four
> counts separately.

The 20 stage state transitions are the spine of the run and read well on their own.
`afaw verify` reconstructs them as a timeline; the informative ones are:

| Log time | Stage | State |
|---|---|---|
| 09:00:01.916 | `Stage::RunFDL` | Hidden |
| 09:00:01.917 | `Stage::ConnectRootBoot` / `RunRootBoot` / `WaitAndroid` | Hidden |
| 09:00:02.166 | `Stage::DeviceConnection` | WaitingManual — "Connect the device via USB in DFU mode" |
| 09:00:10.569 | `Stage::DeviceConnection` | Completed — "Selected device: Smart 6" |
| 09:00:10.569 | `Stage::PatchBoot` | InProgress |
| 09:00:34.951 | `Stage::ReadFullDump` | InProgress |
| 09:54:29.174 | `Stage::ReadFullDump` | Completed |
| 09:54:29.174 → .239 | `Stage::CalcExtractionHashes` | InProgress → Completed (65 ms — see §8) |
| 09:54:29.520 | `Stage::STG_ExtractHardwareKeys` | InProgress → Completed (same millisecond) |

The four stages Oxygen declares but hides — `RunFDL`, `ConnectRootBoot`, `RunRootBoot`,
`WaitAndroid` — never leave `Hidden`. That is the log's own confirmation of Part 1 §2:
this device profile does not use the generic loader-boot path, it goes through `PatchBoot`.

**Exactly one error in the entire file**, at line 25,064:

```
[calculateFileHash] Error open file (hash)
```

Grepped for `error|fail|wipe|erase|factory|reset|retry|denied|refus|corrupt|invalid|
cannot read|timeout` — that is the only hit.

## `userData.bin` — not in this repo

The raw physical image. **Still fully encrypted (FBE)** — Android never booted during this
extraction, so nothing was decrypted on-device.

---

# Part 3 — Two things that need your attention

## 1. Size: the manifest says 29.12 GiB, you said 28 GB

The declared size is **31,268,536,320 bytes** exactly:

- = **29.12 GiB** (what Windows Explorer shows)
- = **31.27 GB** (decimal, what a "32 GB" phone advertises)

If your file is genuinely ~28 GB it is **short by 1–3 GB** and the image is truncated:

| If it's really… | Bytes | Short by |
|---|---|---|
| 28 GB decimal | 28,000,000,000 | −3,268,536,320 |
| 28 GiB | 30,064,771,072 | −1,203,765,248 |
| **29.12 GiB (correct)** | **31,268,536,320** | **0** |

Check the exact byte count — do not trust the rounded number:

```powershell
# Windows PowerShell
(Get-Item "D:\forensic\POP5\SPDT-2026-09-18-09-00-01\userData.bin").Length
```
```bash
# Linux / WSL / macOS
stat -c %s userData.bin        # or: stat -f %z userData.bin on macOS
```

It must print **31268536320**. Because no hash was ever recorded, the byte count is the
only integrity check you have — if it doesn't match, the copy is incomplete.

The declared size divides evenly by 512, 1024, 2048, 4096 and 1 MiB (61,071,360 sectors of
512 B; 7,455 blocks of 4 MiB), which is what you'd expect of a clean partition image.

## 2. The filename — correcting what I told you earlier

**I over-claimed last turn.** I said the file "must" be renamed to `userData.bin` or the
import would break. I cannot support that from these artifacts. Here is what is actually
verifiable:

- The log mentions a data filename **twice**, both times `SPDT.bin` (lines 68 and 25,063).
- The string `userData` appears **nowhere** in the 25,087-line log.
- The manifest declares `Partition 1 File=userData.bin`.

So the extractor wrote `SPDT.bin` and the manifest points at `userData.bin`, but **the log
contains no rename event either way**. I can't tell whether Oxygen renames the file at
finalize or whether `Partition 1 File` is a logical name Detective resolves internally.

You can settle it in one step: **look at the original folder**
`D:\forensic\POP5\SPDT-2026-09-18-09-00-01\` on the extraction PC. Whatever the image is
called there is what Oxygen actually left behind, and that is the name that works.

If you're stuck with a mismatched name, `device.ewc` is plain text — edit
`Partition 1 File=` to match your actual filename. **Work on a copy; leave the original
manifest untouched** so your evidence stays intact.

---

# Part 4 — Is the passcode in any of these files?

No. `device.ewc` was inspected byte-for-byte and holds **14 keys, none of them a secret** —
content type, timestamps, method, model, manufacturer, alias, and four partition/manifest
pointers. Searching all three artifacts for `password`, `passcode`, `passw`, `passwd`,
`pin`, `pwd`, `credential`, `synthetic`, `secret`, `lock`, `token`, `keystore`, `spblob`,
`weaver` and `gatekeeper` returns **zero hits in every file**.

The three keys in `keys.json` are full 256-bit keys, not credentials:

| Key | What it unlocks |
|---|---|
| `SPRD_KM_KEY` (keymaster) | **DE storage** — needs no passcode at all |
| `SPRD_GK_KEY` (gatekeeper) | **Verifier** material — combined with a *candidate* passcode to test a guess |
| `SPRD_UK_KEY` (user) | User key material |

`SPRD_GK_KEY` lets you *check* a guess. It is not the guess.

**Why it cannot be derived:** under FBE the CE storage key is unwrapped using material
derived from the hardware key **plus** the user's synthetic password. The SPDT exploit
recovers the hardware half; the passcode half only ever existed in the gatekeeper verifier
and the owner's head, and was never written to flash. There is nothing here to extract.

The only route is to **attack** it. Import `device.ewc` into Detective, leave the password
blank, and the Password Technology module runs offline and GPU-accelerated — unlimited
attempts, unlike the live device. Expected effort: a 4–6 digit PIN is seconds to minutes;
a pattern or common PIN, minutes; a long alphanumeric password, possibly infeasible.

Whether a passcode was set at all is **not determinable from these artifacts** — the log
never mentions it. Detective resolves that on import; if no screen lock was configured, CE
storage decrypts immediately from the keys alone.

---

# Part 5 — Where this stands

| Question | Answer |
|---|---|
| Is the data destroyed? | **No.** Full read, no errors, no wipe, non-destructive method. |
| Was the read complete? | **Yes** — 31,268,536,320 of 31,268,536,320 bytes, tick 1000/1000, zero stalls. |
| Are the keys good? | **Yes** — three complete 32-byte keys. |
| Is the image readable as-is? | **No** — still FBE-encrypted. |
| Is integrity provable? | **No** — hash stage failed, no hash in the manifest. |

**To read the data:** drag `device.ewc` into Oxygen Forensic Detective. You'll be prompted
for the screen-lock passcode. Enter it if known, or leave it blank and use the Password
Technology module for dictionary/brute-force — it runs offline and GPU-accelerated, so you
get unlimited attempts, unlike the live phone. Without the passcode you'll only see DE
storage; CE storage (messages, app data, media) requires it.

To move the result to another tool, export the **decrypted** file system to an archive from
Detective. The `.bin` itself will always stay encrypted.

**Fix the hash gap now** — it's the one real defect in this extraction:

```powershell
Get-FileHash -Algorithm SHA256 "D:\forensic\POP5\SPDT-2026-09-18-09-00-01\userData.bin"
```

Record the value in your case notes with the date and your name.

> Confirm you have legal authority over this device before decrypting or analysing it.

---

*Every number above was re-derived from the raw artifacts and cross-checked by assertion —
20 consolidated checks (33 in the first pass) against `device.ewc`, `keys.json` and all
25,087 log lines. All passing.*
