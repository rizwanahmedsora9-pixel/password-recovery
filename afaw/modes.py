"""
USB boot-mode identification for Android devices.

Detection only. This module answers one question -- "what mode is the thing on
the other end of this cable in?" -- and classifies the answer as either
ACQUIRABLE (the device is running software that will hand data over to a
consenting, authorized host) or REFUSED (the device is sitting in a BootROM
download mode whose only purpose is factory provisioning, and reaching it
usefully requires defeating the chip's secure boot).

The VID/PID values below are public, published in the USB ID repository and in
every vendor's flashing documentation. They are used here purely to name what
is already visible to the operating system.
"""

from __future__ import annotations

import glob
import json
import os
import subprocess
from dataclasses import dataclass, field
from typing import Iterable, Optional

# --- classification -----------------------------------------------------------

ACQUIRABLE = "acquirable"
CONDITIONAL = "conditional"
REFUSED = "refused"

# Modes we will not drive. Each maps to the reason it is out of scope.
REFUSED_MODES: dict[str, str] = {
    "qualcomm_edl": (
        "Qualcomm Emergency Download (9008). Reading flash here needs a "
        "firehose programmer signed by the OEM, or an exploit against the "
        "PBL's auth check. Neither belongs in this tool."
    ),
    "unisoc_dfu": (
        "Unisoc/Spreadtrum download mode (the mode Oxygen's SPDT method uses). "
        "Useful access here comes from a BootROM vulnerability giving EL3 code "
        "execution -- unpatchable, and not something this tool implements."
    ),
    "mtk_preloader": (
        "MediaTek preloader/BootROM download. Requires a Download Agent, and "
        "on secured chips an exploit against the BROM handshake."
    ),
    "rockchip_maskrom": (
        "Rockchip MaskROM. Requires a vendor loader binary."
    ),
    "samsung_odin": (
        "Samsung Odin download mode. Requires signed Samsung bootloaders and "
        "the Odin protocol; flashing-oriented, not a forensic read path."
    ),
}


@dataclass(frozen=True)
class UsbDevice:
    """A USB device as the host OS reports it."""

    vid: str
    pid: str
    bus: str = ""
    port: str = ""
    manufacturer: str = ""
    product: str = ""

    @property
    def id(self) -> str:
        return f"{self.vid}:{self.pid}"

    def to_dict(self) -> dict:
        return {
            "vid": self.vid,
            "pid": self.pid,
            "id": self.id,
            "bus": self.bus,
            "port": self.port,
            "manufacturer": self.manufacturer,
            "product": self.product,
        }


@dataclass(frozen=True)
class ModeMatch:
    """What we concluded about a device."""

    mode: str
    label: str
    classification: str
    vendor: str
    note: str = ""
    device: Optional[UsbDevice] = field(default=None, compare=False)

    @property
    def acquirable(self) -> bool:
        return self.classification == ACQUIRABLE

    def to_dict(self) -> dict:
        d = {
            "mode": self.mode,
            "label": self.label,
            "classification": self.classification,
            "vendor": self.vendor,
            "note": self.note,
        }
        if self.device is not None:
            d["device"] = self.device.to_dict()
        return d


# --- the identification table -------------------------------------------------
#
# (vid, pid) -> (mode, label, classification, vendor, note)

TABLE: dict[tuple[str, str], ModeMatch] = {
    # Google / generic Android
    ("18d1", "4ee0"): ModeMatch("fastboot", "Android fastboot", CONDITIONAL, "Google",
                                "Usable only if the bootloader is already unlocked."),
    ("18d1", "d00d"): ModeMatch("fastboot", "Android fastboot (generic)", CONDITIONAL, "Google",
                                "Usable only if the bootloader is already unlocked."),
    ("18d1", "4ee1"): ModeMatch("adb", "Android ADB (MTP+ADB)", ACQUIRABLE, "Google"),
    ("18d1", "4ee2"): ModeMatch("adb", "Android ADB (PTP+ADB)", ACQUIRABLE, "Google"),
    ("18d1", "4ee3"): ModeMatch("adb", "Android ADB (no accessory)", ACQUIRABLE, "Google"),
    ("18d1", "4ee4"): ModeMatch("adb", "Android ADB (RNDIS+ADB)", ACQUIRABLE, "Google"),
    ("18d1", "4ee5"): ModeMatch("adb", "Android ADB (audio+ADB)", ACQUIRABLE, "Google"),
    ("18d1", "4ee6"): ModeMatch("adb", "Android ADB (serial+ADB)", ACQUIRABLE, "Google"),
    ("18d1", "4ee7"): ModeMatch("adb", "Android ADB (file transfer)", ACQUIRABLE, "Google"),
    ("18d1", "4eea"): ModeMatch("adb", "Android ADB (Pixel)", ACQUIRABLE, "Google"),
    # Qualcomm
    ("05c6", "9008"): ModeMatch("qualcomm_edl", "Qualcomm HS-USB QDLoader 9008 (EDL)", REFUSED,
                                "Qualcomm", REFUSED_MODES["qualcomm_edl"]),
    ("05c6", "9007"): ModeMatch("qualcomm_edl", "Qualcomm QDLoader 9007", REFUSED,
                                "Qualcomm", REFUSED_MODES["qualcomm_edl"]),
    ("05c6", "900e"): ModeMatch("qualcomm_edl", "Qualcomm QDLoader 900E", REFUSED,
                                "Qualcomm", REFUSED_MODES["qualcomm_edl"]),
    # Unisoc / Spreadtrum
    ("1782", "4d00"): ModeMatch("unisoc_dfu", "Unisoc/Spreadtrum download (DFU)", REFUSED,
                                "Unisoc", REFUSED_MODES["unisoc_dfu"]),
    ("1782", "4d01"): ModeMatch("unisoc_dfu", "Unisoc/Spreadtrum download (DFU)", REFUSED,
                                "Unisoc", REFUSED_MODES["unisoc_dfu"]),
    ("1782", "4d02"): ModeMatch("unisoc_dfu", "Unisoc/Spreadtrum download (DFU)", REFUSED,
                                "Unisoc", REFUSED_MODES["unisoc_dfu"]),
    # MediaTek
    ("0e8d", "0003"): ModeMatch("mtk_preloader", "MediaTek preloader/BootROM", REFUSED,
                                "MediaTek", REFUSED_MODES["mtk_preloader"]),
    ("0e8d", "2000"): ModeMatch("mtk_preloader", "MediaTek USB VCOM (DA)", REFUSED,
                                "MediaTek", REFUSED_MODES["mtk_preloader"]),
    ("0e8d", "2001"): ModeMatch("mtk_preloader", "MediaTek USB VCOM (DA)", REFUSED,
                                "MediaTek", REFUSED_MODES["mtk_preloader"]),
    # Rockchip
    ("2207", "350a"): ModeMatch("rockchip_maskrom", "Rockchip MaskROM", REFUSED,
                                "Rockchip", REFUSED_MODES["rockchip_maskrom"]),
    ("2207", "110a"): ModeMatch("rockchip_maskrom", "Rockchip Loader", REFUSED,
                                "Rockchip", REFUSED_MODES["rockchip_maskrom"]),
    # Samsung
    ("04e8", "685d"): ModeMatch("samsung_odin", "Samsung Odin download mode", REFUSED,
                                "Samsung", REFUSED_MODES["samsung_odin"]),
    ("04e8", "6860"): ModeMatch("adb", "Samsung MTP+ADB", ACQUIRABLE, "Samsung"),
    ("04e8", "6863"): ModeMatch("adb", "Samsung MTP+ADB", ACQUIRABLE, "Samsung"),
}

# Vendor prefixes, used when the exact PID is unknown.
VENDOR_PREFIX: dict[str, str] = {
    "18d1": "Google",
    "05c6": "Qualcomm",
    "1782": "Unisoc/Spreadtrum",
    "0e8d": "MediaTek",
    "2207": "Rockchip",
    "04e8": "Samsung",
    "22d9": "OPPO/OnePlus",
    "2a70": "OnePlus",
    "2717": "Xiaomi",
    "2e04": "Nokia/HMD",
    "12d1": "Huawei",
    "2b4c": "Samsung",
    "18d2": "ZTE",
    "19d2": "ZTE",
    "2916": "Yulong/Coolpad",
    "22b8": "Motorola",
    "2e17": "Infinix/Transsion",
    "17ef": "Lenovo",
}


def classify(dev: UsbDevice) -> ModeMatch:
    """Map a USB device to a mode. Always returns something; unknown is honest."""
    key = (dev.vid.lower(), dev.pid.lower())
    hit = TABLE.get(key)
    if hit is not None:
        return ModeMatch(hit.mode, hit.label, hit.classification, hit.vendor,
                         hit.note, device=dev)

    vendor = VENDOR_PREFIX.get(dev.vid.lower(), "Unknown")
    return ModeMatch(
        mode="unknown",
        label=f"Unrecognised USB device ({dev.id})",
        classification="unknown",
        vendor=vendor,
        note=(
            "Not in the identification table. Could be a normal Android device "
            "under a vendor-specific PID, a charger-only cable, or a device in "
            "a download mode this tool does not catalogue. If `adb devices` "
            "lists it, it is an ordinary ADB device and `acquire adb` applies."
        ),
        device=dev,
    )


# --- host enumeration ---------------------------------------------------------


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def enumerate_linux() -> list[UsbDevice]:
    """Read USB devices out of sysfs. No privileges required."""
    out: list[UsbDevice] = []
    for dev_dir in sorted(glob.glob("/sys/bus/usb/devices/*")):
        base = os.path.basename(dev_dir)
        if ":" in base:  # interface, not the device itself
            continue
        vid = _read(os.path.join(dev_dir, "idVendor"))
        pid = _read(os.path.join(dev_dir, "idProduct"))
        if not vid or not pid:
            continue
        out.append(
            UsbDevice(
                vid=vid,
                pid=pid,
                bus=_read(os.path.join(dev_dir, "busnum")),
                port=_read(os.path.join(dev_dir, "devpath")),
                manufacturer=_read(os.path.join(dev_dir, "manufacturer")),
                product=_read(os.path.join(dev_dir, "product")),
            )
        )
    return out


def enumerate_lsusb() -> list[UsbDevice]:
    """Fall back to parsing `lsusb` output."""
    try:
        raw = subprocess.run(
            ["lsusb"], capture_output=True, text=True, timeout=10, check=False
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    out: list[UsbDevice] = []
    for line in raw.splitlines():
        # Bus 001 Device 005: ID 18d1:4ee7 Google Inc. Pixel
        parts = line.split()
        try:
            i = parts.index("ID")
            vid, pid = parts[i + 1].split(":")[:2]
        except (ValueError, IndexError):
            continue
        desc = " ".join(parts[i + 2:])
        out.append(UsbDevice(vid=vid, pid=pid, bus=parts[1], port=parts[3].rstrip(":"),
                             product=desc))
    return out


def enumerate_from_payload(payload: Iterable[dict]) -> list[UsbDevice]:
    """Build devices from a JSON list -- used for replay and for tests."""
    out: list[UsbDevice] = []
    for item in payload:
        if "vid" not in item or "pid" not in item:
            raise ValueError(f"device record needs 'vid' and 'pid': {item!r}")
        out.append(
            UsbDevice(
                vid=str(item["vid"]).lower(),
                pid=str(item["pid"]).lower(),
                bus=str(item.get("bus", "")),
                port=str(item.get("port", "")),
                manufacturer=str(item.get("manufacturer", "")),
                product=str(item.get("product", "")),
            )
        )
    return out


def detect(json_file: Optional[str] = None) -> list[ModeMatch]:
    """Detect every attached USB device and classify it."""
    if json_file:
        with open(json_file, "r", encoding="utf-8") as fh:
            devices = enumerate_from_payload(json.load(fh))
    else:
        devices = enumerate_linux() or enumerate_lsusb()
    return [classify(d) for d in devices]
