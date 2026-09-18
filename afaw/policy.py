"""
Authorization gate and hard refusals.

Nothing in this package acquires from a device without an Authorization
object. The object is written into the custody log and into the manifest, so
an acquisition that cannot state who authorized it, and on what basis, cannot
produce an admissible artifact.
"""

from __future__ import annotations

import datetime as _dt
import getpass
import json
import platform
from dataclasses import asdict, dataclass, field

from . import PRODUCT_NAME, __version__
from .modes import REFUSED, REFUSED_MODES, ModeMatch


class Refused(Exception):
    """Raised when the requested acquisition is out of scope for this tool."""


class NotAuthorized(Exception):
    """Raised when an acquisition was attempted without an Authorization."""


@dataclass(frozen=True)
class Authorization:
    """Who authorized this acquisition, and on what basis."""

    case_number: str
    examiner: str
    legal_basis: str
    device_alias: str = ""
    device_owner_consent: bool = False
    issued_utc: str = field(
        default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).strftime(
            "%Y%m%dT%H%M%S"
        )
    )

    def __post_init__(self) -> None:
        missing = [
            name
            for name in ("case_number", "examiner", "legal_basis")
            if not str(getattr(self, name)).strip()
        ]
        if missing:
            raise NotAuthorized(
                "authorization is incomplete; missing: " + ", ".join(missing)
            )

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class HostInfo:
    """Provenance for the acquiring machine."""

    hostname: str
    platform: str
    user: str
    tool: str
    tool_version: str

    @staticmethod
    def capture() -> "HostInfo":
        return HostInfo(
            hostname=platform.node(),
            platform=f"{platform.system()} {platform.release()} {platform.machine()}",
            user=_safe_user(),
            tool=PRODUCT_NAME,
            tool_version=__version__,
        )

    def to_dict(self) -> dict:
        return asdict(self)


def _safe_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # pragma: no cover - getuser can raise on odd hosts
        return "unknown"


def assert_acquirable(match: ModeMatch) -> None:
    """Refuse modes that would require defeating device security.

    `fastboot` is CONDITIONAL, not refused: an unlocked bootloader means the
    owner removed the security boundary themselves, so reading partitions
    through it is not a bypass. The unlock check happens in acquire.py.
    """
    if match.classification == REFUSED:
        reason = REFUSED_MODES.get(
            match.mode, "This boot mode is out of scope for this tool."
        )
        raise Refused(
            f"Device is in {match.label} ({match.device.id if match.device else '?'}). "
            f"{reason}\n\n"
            "What this tool will do instead:\n"
            "  * `detect`  -- report the mode and the chipset, for your notes\n"
            "  * `verify`  -- validate an image another tool already produced\n"
            "If the device is yours or you hold the owner's consent, power it "
            "into Android, enable USB debugging, accept the RSA prompt, and use "
            "`acquire adb`. If it is evidence and you have legal authority, "
            "acquire it with a licensed forensic product that is accountable "
            "for the exploit it ships."
        )
    if match.classification == "unknown":
        raise Refused(
            f"{match.label}: {match.note}\n"
            "Resolve what the device is before acquiring. If `adb devices` "
            "lists it, it is an ADB device and `acquire adb` applies."
        )


def write_authorization_record(path: str, auth: Authorization, host: HostInfo) -> None:
    """Persist the authorization alongside the evidence."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(
            {"authorization": auth.to_dict(), "host": host.to_dict()},
            fh,
            indent=2,
            sort_keys=True,
        )
        fh.write("\n")
