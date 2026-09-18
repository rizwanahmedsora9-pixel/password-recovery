"""
Append-only chain-of-custody log.

One JSON object per line: readable by a human in a text editor, parseable by
anything downstream, and append-only so a backfilled entry is obvious. The
file is opened with O_APPEND and every record is flushed and fsynced before
the call returns, because a custody log that can lose its last line is not a
custody log.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import platform
from typing import Any, Optional


class CustodyLog:
    def __init__(self, path: str, case_number: str = "", examiner: str = "") -> None:
        self.path = path
        self.case_number = case_number
        self.examiner = examiner
        self._fh = open(path, "a", encoding="utf-8")
        self._seq = _existing_line_count(path)

    # -- writing --------------------------------------------------------------

    def record(self, event: str, **fields: Any) -> dict:
        self._seq += 1
        entry = {
            "seq": self._seq,
            "utc": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
            + "Z",
            "case": self.case_number,
            "examiner": self.examiner,
            "host": platform.node(),
            "event": event,
            **fields,
        }
        self._fh.write(json.dumps(entry, sort_keys=True) + "\n")
        self._fh.flush()
        os.fsync(self._fh.fileno())
        return entry

    def close(self) -> None:
        if not self._fh.closed:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()

    def __enter__(self) -> "CustodyLog":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def _existing_line_count(path: str) -> int:
    if not os.path.exists(path):
        return 0
    try:
        with open(path, "rb") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def read(path: str) -> list[dict]:
    """Read a custody log back, skipping and reporting corrupt lines."""
    out: list[dict] = []
    if not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as exc:
                out.append(
                    {"seq": None, "event": "CORRUPT_LINE", "line": lineno,
                     "error": str(exc), "raw": line[:200]}
                )
    return out


def summarize(path: str) -> Optional[dict]:
    entries = read(path)
    if not entries:
        return None
    corrupt = [e for e in entries if e.get("event") == "CORRUPT_LINE"]
    events: dict[str, int] = {}
    for e in entries:
        if e.get("event") == "CORRUPT_LINE":
            continue
        events[e.get("event", "?")] = events.get(e.get("event", "?"), 0) + 1
    return {
        "path": path,
        "entries": len(entries),
        "corrupt_lines": len(corrupt),
        "events": events,
        "first_utc": entries[0].get("utc"),
        "last_utc": entries[-1].get("utc"),
        "append_only_intact": all(
            e.get("seq") == i + 1 for i, e in enumerate(entries)
            if e.get("seq") is not None
        ),
    }
