"""
Verification of an existing extraction folder.

This is the part of the pipeline that the extraction in this repository is
missing. The Oxygen log shows its hash stage failing --

    09:54:29.210 [calculateFileHash] Error open file (hash)

-- and the run then reported `ExtractionStatus::Completed` anyway, 29 ms later.
The manifest it wrote carries no hash of any kind, so the only integrity check
left on that image is a byte count.

`verify` closes that gap after the fact: it re-reads whatever artifacts are
present, recomputes hashes, cross-checks declared sizes against real ones, and
reconstructs the acquisition timeline from the extractor's log. It is
read-only by construction -- nothing here writes into the evidence folder.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
from dataclasses import asdict, dataclass, field
from typing import Optional

from . import ewc as ewc_mod
from .integrity import DEFAULT_ALGOS, describe_alignment, gib, hash_file, human

TS_FMT = "%d-%m-%Y %H:%M:%S.%f"

# 18-09-2026 09:54:29.210 [362c] [calculateFileHash] Error open file (hash)
_LINE_RE = re.compile(
    r"^(?P<ts>\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r"(?:\[(?P<thread>[^\]]*)\]\s+)?"
    r"(?:\[(?P<token>[^\]]+)\]\s+)?"
    r"(?:\[(?P<token2>[^\]]+)\]\s+)?"
    r"(?P<rest>.*)$"
)
_SIZE_RE = re.compile(r"(?P<stage>Stage::\w+) ProgressSize changed: (?P<n>\d+)")
_TOTAL_RE = re.compile(r"(?P<stage>Stage::\w+) ProgressTotal changed: (?P<n>\d+)")
_POS_RE = re.compile(r"(?P<stage>Stage::\w+) ProgressPos changed: (?P<n>\d+)")
_SPEED_RE = re.compile(r"Speed:\s*(?P<speed>[\d.]+)\s*Mb/s")
# 18-09-2026 09:00:02.166 [362c] [BaseExtractor::setStageProgress] Stage::DeviceConnection ExtractionState::WaitingManual <font …>Connect the device…</font>
_STAGE_EVENT_RE = re.compile(
    r"(?P<stage>Stage::[\w]+)\s+ExtractionState::(?P<state>\w+)(?:\s+(?P<msg>.*))?$"
)
# Any bracketed token whose content starts with a letter or underscore. This is
# deliberately not line-anchored: markers like `[Enter]` sit at end of line and
# `[int64]` sits mid-line inside `value[int64]:`. Thread ids (`[362c]`, `[:0]`)
# start with a digit or colon and are therefore excluded.
_TOKEN_RE = re.compile(r"\[([A-Za-z_][\w:]*)\]")

# Plain log markers, as opposed to `Class::method` or free-function names.
_MARKER_TOKENS = frozenset(
    {"Enter", "Leave", "Success", "Value", "string", "int64", "int", "bool"}
)

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_BREAK_RE = re.compile(r"<br\s*/?>", re.IGNORECASE)
_WS_RE = re.compile(r"\s+")


def _strip_html(text: str) -> str:
    """Stage messages arrive wrapped in Qt rich-text tags.

    A `<br/>` is a real separator, not markup to discard -- dropping it runs
    "Selected device: Smart 6" straight into "Connect the device via USB".
    """
    text = _BREAK_RE.sub(" — ", text)
    text = _HTML_TAG_RE.sub("", text)
    return _WS_RE.sub(" ", text).strip(" —")
_ERROR_RE = re.compile(
    r"error|fail|denied|refus|corrupt|invalid|cannot read|timeout|wipe|erase|"
    r"factory reset|truncat",
    re.IGNORECASE,
)

# Secrets are masked in every report this module produces.
_SENSITIVE_RE = re.compile(
    r"(UK_KEY|GK_KEY|KM_KEY|KEYBAG|synthetic|passcode|password|passw|passwd|"
    r"pin|pwd|credential|secret|token)",
    re.IGNORECASE,
)


def _short_hash(value: Optional[str]) -> str:
    if not value:
        return "—"
    return f"`{value[:16]}…`"


def _clip(text: str, width: int = 72) -> str:
    """Truncate on a word boundary rather than mid-word."""
    if not text:
        return "—"
    if len(text) <= width:
        return text
    cut = text[:width]
    if " " in cut:
        cut = cut[: cut.rfind(" ")]
    return cut.rstrip(" ,;:") + "…"


def mask(value: str, keep: int = 8) -> str:
    """Show enough of a key to tell two apart, never enough to use one."""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}...{value[-4:]} ({len(value)} hex chars)"


# --- log analysis -------------------------------------------------------------


@dataclass
class LogAnalysis:
    path: str
    bytes: int = 0
    lines: int = 0
    crlf: int = 0
    valid_utf8: bool = True
    progress_lines: int = 0
    set_stage_progress_lines: int = 0
    qt_noise_lines: int = 0
    substantive_lines: int = 0
    distinct_tokens: int = 0
    qt_log_categories: int = 0
    qualified_tokens: int = 0
    free_function_tokens: int = 0
    marker_tokens: int = 0
    error_lines: list[dict] = field(default_factory=list)
    stages: list[str] = field(default_factory=list)
    stage_events: list[dict] = field(default_factory=list)
    read_window: dict = field(default_factory=dict)
    throughput: dict = field(default_factory=dict)
    tool: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def analyze_log(path: str) -> LogAnalysis:
    """Reconstruct what happened from an extractor log."""
    with open(path, "rb") as fh:
        raw = fh.read()

    out = LogAnalysis(path=path, bytes=len(raw), crlf=raw.count(b"\r\n"))
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        out.valid_utf8 = False
        text = raw.decode("utf-8", errors="replace")
        out.warnings.append("log is not valid UTF-8; decoded with replacement chars")

    lines = text.splitlines()
    out.lines = len(lines)

    tokens: set[str] = set()
    qt_tokens: set[str] = set()
    sizes: list[tuple[float, int]] = []
    totals: list[int] = []
    positions: list[tuple[float, int]] = []
    speeds: list[float] = []
    stages: list[str] = []

    for lineno, line in enumerate(lines, start=1):
        ts: Optional[_dt.datetime] = None
        m = _LINE_RE.match(line)
        if m:
            try:
                ts = _dt.datetime.strptime(m.group("ts"), TS_FMT)
            except ValueError:
                ts = None

        for tok in _TOKEN_RE.findall(line):
            tokens.add(tok)
            if tok.startswith("Qt::"):
                qt_tokens.add(tok)

        if "[Qt::" in line:
            out.qt_noise_lines += 1
        if "setStageProgress" in line:
            out.set_stage_progress_lines += 1

        if ts is not None:
            epoch = ts.timestamp()
            sm = _SIZE_RE.search(line)
            if sm:
                sizes.append((epoch, int(sm.group("n"))))
                out.progress_lines += 1
                if sm.group("stage") not in stages:
                    stages.append(sm.group("stage"))
                continue
            tm = _TOTAL_RE.search(line)
            if tm:
                totals.append(int(tm.group("n")))
                out.progress_lines += 1
                continue
            pm = _POS_RE.search(line)
            if pm:
                positions.append((epoch, int(pm.group("n"))))
                out.progress_lines += 1
                continue
            sp = _SPEED_RE.search(line)
            if sp:
                # Speed lines also read `Stage::X ExtractionState::InProgress`,
                # so they must be consumed here -- otherwise all 11k of them
                # get recorded as stage transitions.
                speeds.append(float(sp.group("speed")))
                out.progress_lines += 1
                continue

            # Stage state transitions are the spine of the run: Hidden,
            # WaitingManual, InProgress, Completed. These are worth keeping in
            # order, with whatever human-readable message came with them.
            se = _STAGE_EVENT_RE.search(line)
            if se:
                msg = _strip_html(se.group("msg") or "")
                out.stage_events.append(
                    {
                        "ts": _dt.datetime.fromtimestamp(
                            epoch, _dt.timezone.utc
                        ).isoformat(),
                        "stage": se.group("stage"),
                        "state": se.group("state"),
                        "message": msg,
                    }
                )

        for stg in re.findall(r"Stage::([A-Za-z]\w*)", line):
            if stg not in stages:
                stages.append(stg)

        if _ERROR_RE.search(line):
            out.error_lines.append({"line": lineno, "text": line.strip()[:200]})

    out.distinct_tokens = len(tokens)
    out.qt_log_categories = len(qt_tokens)
    out.qualified_tokens = sum(1 for t in tokens if "::" in t)
    out.marker_tokens = sum(1 for t in tokens if t in _MARKER_TOKENS)
    out.free_function_tokens = out.distinct_tokens - out.qualified_tokens - out.marker_tokens
    out.substantive_lines = out.lines - out.set_stage_progress_lines
    out.stages = stages

    vm = re.search(r"Application version:\s*(.+)", text)
    if vm:
        out.tool["version"] = vm.group(1).strip()
    om = re.search(r"OS version:\s*(.+)", text)
    if om:
        out.tool["os"] = om.group(1).strip()
    am = re.search(r"Application started:\s*(.+)", text)
    if am:
        out.tool["started"] = am.group(1).strip()

    if totals:
        out.read_window["declared_total"] = totals[-1]
    if positions:
        out.read_window["first_tick"] = positions[0][1]
        out.read_window["last_tick"] = positions[-1][1]
        out.read_window["ticks"] = len(positions)
    if sizes:
        t0, s0 = sizes[0]
        t1, s1 = sizes[-1]
        span = max(t1 - t0, 1e-9)
        # Timestamps in the log are the extractor's own local clock, not UTC.
        out.read_window["first_sample"] = _dt.datetime.fromtimestamp(
            t0, _dt.timezone.utc
        ).isoformat()
        out.read_window["last_sample"] = _dt.datetime.fromtimestamp(
            t1, _dt.timezone.utc
        ).isoformat()
        out.read_window["samples"] = len(sizes)
        out.read_window["first_byte"] = s0
        out.read_window["last_byte"] = s1
        out.read_window["seconds"] = round(span, 3)

        gaps = [
            (round(sizes[i][0] - sizes[i - 1][0], 3), i)
            for i in range(1, len(sizes))
        ]
        worst = max(gaps, key=lambda g: g[0]) if gaps else (0.0, 0)
        out.throughput["overall_mbps"] = round((s1 - s0) / span / 1e6, 3)
        out.throughput["reported_speed_min_mbps"] = round(min(speeds), 3) if speeds else None
        out.throughput["reported_speed_max_mbps"] = round(max(speeds), 3) if speeds else None
        out.throughput["largest_stall_seconds"] = worst[0]
        out.throughput["largest_stall_at_sample"] = worst[1] + 1
        out.throughput["stalls_over_5s"] = sum(1 for g, _ in gaps if g > 5)
        out.throughput["stalls_over_10s"] = sum(1 for g, _ in gaps if g > 10)
        out.throughput["median_sample_gap_ms"] = (
            round(sorted(g for g, _ in gaps)[len(gaps) // 2] * 1000, 1) if gaps else None
        )

    if out.error_lines and not out.warnings:
        out.warnings.append(
            f"{len(out.error_lines)} error-matching line(s) in the log; see error_lines"
        )
    return out


# --- keybag -------------------------------------------------------------------


@dataclass
class KeybagAnalysis:
    path: str
    present: bool = True
    parse_error: str = ""
    chain_type: str = ""
    chain_type_ascii: str = ""
    keys: list[dict] = field(default_factory=list)
    verdict: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def analyze_keybag(path: str) -> KeybagAnalysis:
    """Describe a keybag without ever echoing a key.

    The values in keys.json are live 256-bit hardware keys. Reports show a
    masked fingerprint and a length check only.
    """
    out = KeybagAnalysis(path=path)
    if not os.path.exists(path):
        out.present = False
        out.verdict = "no keybag file"
        return out
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        out.present = True
        out.parse_error = str(exc)
        out.verdict = "unparseable"
        return out

    chain = data.get("ChainType", "")
    out.chain_type = chain
    try:
        out.chain_type_ascii = bytes.fromhex(chain).decode("ascii", "replace")
    except ValueError:
        out.chain_type_ascii = ""

    for name, value in data.items():
        if name == "ChainType":
            continue
        hexok = bool(re.fullmatch(r"[0-9a-fA-F]+", value or ""))
        nbytes = len(value) // 2 if hexok else 0
        out.keys.append(
            {
                "name": name,
                "hex_chars": len(value or ""),
                "bytes": nbytes,
                "valid_hex": hexok,
                "masked": mask(value or ""),
            }
        )

    good = [k for k in out.keys if k["valid_hex"] and k["bytes"] in (16, 32)]
    if out.parse_error:
        out.verdict = "unparseable"
    elif good and len(good) == len(out.keys):
        out.verdict = (
            f"{len(good)} key(s), all well-formed "
            f"({', '.join(str(k['bytes']) + 'B' for k in good)}). "
            "Hardware key material only -- this is not a passcode and cannot "
            "be turned into one."
        )
    else:
        bad = [k["name"] for k in out.keys if k not in good]
        out.verdict = "present but malformed: " + ", ".join(bad)
    return out


# --- the folder ---------------------------------------------------------------


@dataclass
class VerificationReport:
    folder: str
    ok: bool = False
    manifest: dict = field(default_factory=dict)
    partitions: list[dict] = field(default_factory=list)
    keybag: dict = field(default_factory=dict)
    log: dict = field(default_factory=dict)
    issues: list[dict] = field(default_factory=list)
    summary: list[str] = field(default_factory=list)

    def add_issue(self, severity: str, code: str, message: str) -> None:
        self.issues.append({"severity": severity, "code": code, "message": message})

    def to_dict(self) -> dict:
        return asdict(self)

    def markdown(self) -> str:
        sev = {"error": "🔴", "warning": "🟠", "info": "🔵"}
        out = [f"# Verification report — `{self.folder}`", ""]
        out.append(f"**Verdict:** {'PASS' if self.ok else 'FAIL'}")
        out.append("")
        if self.summary:
            out += ["## Summary", ""] + [f"- {s}" for s in self.summary] + [""]
        if self.issues:
            out += ["## Issues", "", "| | Severity | Code | Detail |", "|---|---|---|---|"]
            for i in self.issues:
                out.append(
                    f"| {sev.get(i['severity'], '•')} | {i['severity']} | "
                    f"`{i['code']}` | {i['message']} |"
                )
            out.append("")
        if self.partitions:
            out += ["## Partitions", "",
                    "| Name | Declared | Actual | Δ | Hash recorded | SHA256 (computed) |",
                    "|---|---|---|---|---|---|"]
            for p in self.partitions:
                out.append(
                    f"| {p['name']} | {p['declared_size']:,} | "
                    f"{p['actual_size'] if p['actual_size'] is not None else '—'} | "
                    f"{p['delta'] if p['delta'] is not None else '—'} | "
                    f"{'yes' if p['hash_recorded'] else '**no**'} | "
                    f"{_short_hash(p.get('computed_sha256'))} |"
                )
            out.append("")
        if self.log:
            lg = self.log
            out += [
                "## Extractor log", "",
                f"- lines: **{lg.get('lines', 0):,}** "
                f"({lg.get('set_stage_progress_lines', 0):,} progress, "
                f"{lg.get('qt_noise_lines', 0):,} Qt noise, "
                f"{lg.get('substantive_lines', 0):,} other)",
                f"- distinct bracketed tokens: **{lg.get('distinct_tokens')}** "
                f"({lg.get('qualified_tokens')} qualified, "
                f"{lg.get('free_function_tokens')} free functions, "
                f"{lg.get('marker_tokens')} markers)",
                f"- error-matching lines: **{len(lg.get('error_lines', []))}**",
            ]
            tw = lg.get("throughput", {})
            if tw:
                out.append(
                    f"- throughput: **{tw.get('overall_mbps')} MB/s** overall; "
                    f"largest stall **{tw.get('largest_stall_seconds')} s**; "
                    f"{tw.get('stalls_over_5s')} stalls over 5 s"
                )
            out.append("")
            events = [e for e in lg.get("stage_events", [])
                      if e["state"] in ("WaitingManual", "InProgress", "Completed")]
            if events:
                out += ["## Stage timeline", "",
                        "Times are the extractor's own clock, not UTC.", "",
                        "| Log time | Stage | State | Message |", "|---|---|---|---|"]
                for e in events:
                    out.append(
                        f"| {e['ts'][11:23]} | `{e['stage']}` | {e['state']} | "
                        f"{_clip(e['message'], 72)} |"
                    )
                out.append("")
        return "\n".join(out) + "\n"


def verify_folder(
    folder: str,
    algos: tuple[str, ...] = DEFAULT_ALGOS,
    compute_hashes: bool = True,
) -> VerificationReport:
    """Verify an extraction folder in place. Never writes to `folder`."""
    rep = VerificationReport(folder=folder)
    ewc_path = os.path.join(folder, "device.ewc")

    if not os.path.isdir(folder):
        rep.add_issue("error", "NO_FOLDER", f"not a directory: {folder}")
        rep.summary.append("Folder does not exist.")
        return rep

    # -- manifest -------------------------------------------------------------
    if not os.path.exists(ewc_path):
        rep.add_issue("error", "NO_MANIFEST", "no device.ewc in the folder")
    else:
        with open(ewc_path, "rb") as fh:
            raw = fh.read()
        rep.manifest["path"] = ewc_path
        rep.manifest["bytes"] = len(raw)
        rep.manifest["crlf"] = raw.count(b"\r\n")
        rep.manifest["line_endings"] = "CRLF" if raw.count(b"\r\n") else "LF"
        rep.manifest["bom"] = raw.startswith(b"\xef\xbb\xbf")
        rep.manifest["ends_with_blank_line"] = raw.endswith(b"\r\n\r\n") or raw.endswith(b"\n\n")
        try:
            ewc = ewc_mod.parse_file(ewc_path)
            rep.manifest["parsed"] = True
            rep.manifest["key_count"] = ewc_mod.count_keys(ewc)
            rep.manifest["sections"] = {k: sorted(v) for k, v in ewc.sections().items()}
            rep.manifest["method"] = ewc.extraction_method
            rep.manifest["model"] = ewc.internal_model_name
            rep.manifest["manufacturer"] = ewc.manufacturer
            rep.manifest["device_alias"] = ewc.device_alias
            rep.manifest["start_utc"] = ewc.extraction_start_utc
            rep.manifest["end_utc"] = ewc.extraction_end_utc
            start = ewc_mod.parse_stamp(ewc.extraction_start_utc)
            end = ewc_mod.parse_stamp(ewc.extraction_end_utc)
            if start and end:
                rep.manifest["duration_seconds"] = int((end - start).total_seconds())
            rep.manifest["has_any_hash_field"] = any(
                "hash" in k.lower() or "sha" in k.lower() or "md5" in k.lower()
                for keys in ewc.sections().values()
                for k in keys
            )
            if not rep.manifest["has_any_hash_field"]:
                rep.add_issue(
                    "error",
                    "NO_HASH_IN_MANIFEST",
                    "The manifest records no hash of any kind. Nothing here can "
                    "prove the image is unaltered; byte count is the only check "
                    "available. Recompute a SHA-256 and record it in your notes.",
                )
            if rep.manifest["bom"]:
                rep.add_issue("warning", "MANIFEST_BOM",
                              "manifest has a UTF-8 BOM; Oxygen writes none")
            if rep.manifest["line_endings"] != "CRLF":
                rep.add_issue("info", "MANIFEST_LINE_ENDINGS",
                              f"manifest uses {rep.manifest['line_endings']}, "
                              "Oxygen uses CRLF")

            # -- partitions ---------------------------------------------------
            if not ewc.partitions:
                rep.add_issue("error", "NO_PARTITIONS",
                              "manifest declares PartitionsCount but lists no files")
            for part in ewc.partitions:
                actual_path = os.path.join(folder, part.file)
                rec = {
                    "name": part.name,
                    "file": part.file,
                    "declared_size": part.size,
                    "actual_size": None,
                    "delta": None,
                    "present": False,
                    "hash_recorded": bool(part.sha256),
                    "computed_sha256": None,
                    "computed": {a: None for a in algos},
                    "alignment": [],
                }
                if part.size >= 0:
                    rec["declared_human"] = human(part.size)
                    rec["alignment"] = describe_alignment(part.size)
                if os.path.exists(actual_path):
                    rec["present"] = True
                    rec["actual_size"] = os.path.getsize(actual_path)
                    rec["delta"] = rec["actual_size"] - part.size
                    if rec["delta"] != 0:
                        rep.add_issue(
                            "error",
                            "SIZE_MISMATCH",
                            f"{part.file}: manifest declares {part.size:,} bytes, "
                            f"file is {rec['actual_size']:,} bytes "
                            f"(delta {rec['delta']:+,}). "
                            f"Declared = {human(part.size)}. "
                            "A non-zero delta means a truncated or padded image.",
                        )
                    else:
                        rep.summary.append(
                            f"{part.file} size matches exactly: {human(part.size)}"
                        )
                    if compute_hashes:
                        h = hash_file(actual_path, algos)
                        rec["computed"] = h.digests
                        rec["computed_sha256"] = h.digests.get("sha256")
                        if h.size != part.size:
                            rep.add_issue(
                                "error", "HASH_SIZE_MISMATCH",
                                f"{part.file}: hashed {h.size:,} bytes, "
                                f"manifest declares {part.size:,}",
                            )
                        if part.sha256 and part.sha256.lower() != h.digests.get("sha256", "").lower():
                            rep.add_issue(
                                "error", "SHA256_MISMATCH",
                                f"{part.file}: recorded SHA-256 does not match "
                                "the recomputed value. Treat the image as altered.",
                            )
                        rep.summary.append(
                            f"SHA-256({part.file}) = {h.digests.get('sha256')}"
                        )
                else:
                    rep.add_issue(
                        "warning",
                        "PARTITION_FILE_MISSING",
                        f"manifest references '{part.file}' but it is not in this "
                        f"folder. Expected {human(part.size)}.",
                    )
                rep.partitions.append(rec)

            # -- keybag -------------------------------------------------------
            if ewc.key_bag_file:
                kb = analyze_keybag(os.path.join(folder, ewc.key_bag_file))
                rep.keybag = kb.to_dict()
                if not kb.present:
                    rep.add_issue(
                        "warning", "KEYBAG_MISSING",
                        f"manifest references keybag '{ewc.key_bag_file}' but it "
                        "is not in this folder",
                    )
                elif kb.parse_error:
                    rep.add_issue("error", "KEYBAG_UNPARSEABLE", kb.parse_error)
                else:
                    rep.summary.append(
                        f"Keybag: {kb.verdict} (ChainType {kb.chain_type} = "
                        f"'{kb.chain_type_ascii}')"
                    )
        except ewc_mod.EwcError as exc:
            rep.manifest["parsed"] = False
            rep.add_issue("error", "MANIFEST_PARSE", str(exc))

    # -- extractor log --------------------------------------------------------
    logs = [
        f for f in os.listdir(folder)
        if f.startswith("extraction_") and f.endswith(".log")
    ]
    for name in sorted(logs):
        la = analyze_log(os.path.join(folder, name))
        rep.log = la.to_dict()
        for e in la.error_lines:
            rep.add_issue(
                "warning", "LOG_ERROR", f"{name} line {e['line']}: {e['text']}"
            )
        tw = la.throughput
        if tw.get("stalls_over_5s"):
            rep.add_issue(
                "warning", "LOG_STALLS",
                f"{tw['stalls_over_5s']} read stall(s) over 5 s "
                f"(worst {tw.get('largest_stall_seconds')} s)",
            )
        if "declared_total" in la.read_window:
            declared = la.read_window["declared_total"]
            rep.manifest["log_declared_total"] = declared
            for p in rep.partitions:
                if p["declared_size"] != declared:
                    rep.add_issue(
                        "warning", "LOG_TOTAL_MISMATCH",
                        f"log ProgressTotal was {declared:,} but manifest "
                        f"declares {p['declared_size']:,} for {p['name']}",
                    )
        break  # one log per folder in practice

    errors = [i for i in rep.issues if i["severity"] == "error"]
    rep.ok = not errors
    if rep.ok and not rep.summary:
        rep.summary.append("No blocking issues found.")
    if errors:
        rep.summary.insert(
            0, f"{len(errors)} blocking issue(s) — this extraction is not sound as-is."
        )
    return rep
