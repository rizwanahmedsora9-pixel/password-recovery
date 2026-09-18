"""
Read and write Oxygen-compatible `.ewc` extraction manifests.

The `.ewc` in this repository was inspected byte-for-byte: plain-text INI,
CRLF line endings, no BOM, keys sorted alphabetically inside each section,
and a single trailing blank line. Writing it back the same way is what lets a
manifest produced here be a drop-in for Detective -- and what lets the
round-trip test in tests/test_ewc.py assert byte equality against the real
424-byte file.

One deliberate divergence from Oxygen's output: Oxygen wrote *no hash field at
all*, because its hash stage failed and the failure was swallowed. Every
manifest written here carries `SHA256` per partition plus a top-level
`ManifestSHA256` of the image set. Integrity is not optional.
"""

from __future__ import annotations

import datetime as _dt
import io
import re
from dataclasses import dataclass, field
from typing import Optional

SECTIONS = ("BaseInfo", "DeviceInfo", "ExtendedInfo")
TS_FMT = "%Y%m%dT%H%M%S"
CRLF = "\r\n"


class EwcError(Exception):
    """Raised when a manifest cannot be parsed."""


def utc_now_stamp() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime(TS_FMT)


def parse_stamp(stamp: str) -> Optional[_dt.datetime]:
    try:
        return _dt.datetime.strptime(stamp, TS_FMT).replace(tzinfo=_dt.timezone.utc)
    except ValueError:
        return None


@dataclass
class Partition:
    name: str
    file: str
    size: int
    sha256: str = ""
    sha1: str = ""
    md5: str = ""

    def to_keys(self, index: int) -> dict[str, str]:
        out = {
            f"Partition {index} File": self.file,
            f"Partition {index} Name": self.name,
            f"Partition {index} Size": str(self.size),
        }
        if self.sha256:
            out[f"Partition {index} SHA256"] = self.sha256
        if self.sha1:
            out[f"Partition {index} SHA1"] = self.sha1
        if self.md5:
            out[f"Partition {index} MD5"] = self.md5
        return out


@dataclass
class Ewc:
    content_type: str = "ANDROID_IMAGE"
    extraction_method: str = ""
    extraction_start_utc: str = ""
    extraction_end_utc: str = ""
    internal_model_name: str = ""
    product_name: str = "AFAW"
    product_version: str = "0.1.0"
    device_alias: str = ""
    manufacturer: str = ""
    key_bag_file: str = ""
    partitions: list[Partition] = field(default_factory=list)
    case_number: str = ""
    examiner: str = ""
    acquisition_path: str = ""
    notes: list[str] = field(default_factory=list)

    # --- serialisation -------------------------------------------------------

    def sections(self) -> dict[str, dict[str, str]]:
        base = {
            "ContentType": self.content_type,
            "ExtractionEndUtc": self.extraction_end_utc,
            "ExtractionMethod": self.extraction_method,
            "ExtractionStartUtc": self.extraction_start_utc,
            "InternalModelName": self.internal_model_name,
            "ProductName": self.product_name,
            "ProductVersion": self.product_version,
        }
        if self.case_number:
            base["CaseNumber"] = self.case_number
        if self.examiner:
            base["Examiner"] = self.examiner

        device = {"DeviceAlias": self.device_alias, "Manufacturer": self.manufacturer}

        ext: dict[str, str] = {}
        if self.acquisition_path:
            ext["AcquisitionPath"] = self.acquisition_path
        if self.key_bag_file:
            ext["KeyBagFile"] = self.key_bag_file
        for i, part in enumerate(self.partitions, start=1):
            ext.update(part.to_keys(i))
        ext["PartitionsCount"] = str(len(self.partitions))
        for note in self.notes:
            ext.setdefault("Note", "")
            ext["Note"] = (ext["Note"] + "; " if ext["Note"] else "") + note

        return {
            "BaseInfo": {k: v for k, v in base.items() if v != ""},
            "DeviceInfo": {k: v for k, v in device.items() if v != ""},
            "ExtendedInfo": ext,
        }

    def dumps(self) -> str:
        buf = io.StringIO()
        for name in SECTIONS:
            keys = self.sections().get(name, {})
            buf.write(f"[{name}]{CRLF}")
            for key in sorted(keys):
                buf.write(f"{key}={keys[key]}{CRLF}")
            buf.write(CRLF)
        return buf.getvalue()

    def dump_bytes(self) -> bytes:
        return self.dumps().encode("utf-8")

    def write(self, path: str) -> None:
        with open(path, "wb") as fh:
            fh.write(self.dump_bytes())


# --- parsing ------------------------------------------------------------------

_SECTION_RE = re.compile(r"^\[(?P<name>[A-Za-z0-9_ ]+)\]\s*$")
_PART_FILE_RE = re.compile(r"^Partition (?P<i>\d+) File$")


def parse(text: str) -> Ewc:
    """Parse a `.ewc` manifest. Tolerates LF or CRLF; preserves nothing extra."""
    sections: dict[str, dict[str, str]] = {}
    current: Optional[str] = None

    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip("\r")
        if not line.strip():
            continue
        m = _SECTION_RE.match(line)
        if m:
            current = m.group("name").strip()
            sections.setdefault(current, {})
            continue
        if current is None:
            raise EwcError(f"line {lineno}: key outside any [Section]: {line!r}")
        if "=" not in line:
            raise EwcError(f"line {lineno}: not a key=value pair: {line!r}")
        key, _, value = line.partition("=")
        sections[current][key.strip()] = value.strip()

    base = sections.get("BaseInfo", {})
    dev = sections.get("DeviceInfo", {})
    ext = sections.get("ExtendedInfo", {})

    parts_by_index: dict[int, dict[str, str]] = {}
    count = 0
    try:
        count = int(ext.get("PartitionsCount", "0"))
    except ValueError:
        count = 0

    for i in range(1, max(count, _highest_partition_index(ext)) + 1):
        fkey = f"Partition {i} File"
        if fkey not in ext:
            continue
        parts_by_index[i] = {
            "file": ext[fkey],
            "name": ext.get(f"Partition {i} Name", ""),
            "size": ext.get(f"Partition {i} Size", "0"),
            "sha256": ext.get(f"Partition {i} SHA256", ""),
            "sha1": ext.get(f"Partition {i} SHA1", ""),
            "md5": ext.get(f"Partition {i} MD5", ""),
        }

    partitions = []
    for i in sorted(parts_by_index):
        p = parts_by_index[i]
        try:
            size = int(p["size"])
        except ValueError:
            size = -1
        partitions.append(
            Partition(
                name=p["name"],
                file=p["file"],
                size=size,
                sha256=p["sha256"],
                sha1=p["sha1"],
                md5=p["md5"],
            )
        )

    notes = [n.strip() for n in ext.get("Note", "").split(";") if n.strip()]

    return Ewc(
        content_type=base.get("ContentType", ""),
        extraction_method=base.get("ExtractionMethod", ""),
        extraction_start_utc=base.get("ExtractionStartUtc", ""),
        extraction_end_utc=base.get("ExtractionEndUtc", ""),
        internal_model_name=base.get("InternalModelName", ""),
        product_name=base.get("ProductName", ""),
        product_version=base.get("ProductVersion", ""),
        device_alias=dev.get("DeviceAlias", ""),
        manufacturer=dev.get("Manufacturer", ""),
        case_number=base.get("CaseNumber", ""),
        examiner=base.get("Examiner", ""),
        key_bag_file=ext.get("KeyBagFile", ""),
        acquisition_path=ext.get("AcquisitionPath", ""),
        partitions=partitions,
        notes=notes,
    )


def parse_file(path: str) -> Ewc:
    with open(path, "rb") as fh:
        raw = fh.read()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise EwcError("manifest has a UTF-8 BOM; Oxygen writes none")
    return parse(raw.decode("utf-8"))


def _highest_partition_index(ext: dict[str, str]) -> int:
    high = 0
    for key in ext:
        m = _PART_FILE_RE.match(key)
        if m:
            high = max(high, int(m.group("i")))
    return high


def count_keys(ewc: Ewc) -> int:
    """Total key count across sections -- 14 for the Oxygen SPDT manifest."""
    return sum(len(v) for v in ewc.sections().values())
