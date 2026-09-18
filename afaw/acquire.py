"""
Acquisition engines.

Three engines, all of them read paths against a device that is cooperating:

  * block  -- image a file or block device opened O_RDONLY. This is the engine
              you use behind a hardware write blocker, or against any device
              that enumerates as mass storage.
  * adb    -- logical acquisition from a powered-on Android device that has
              accepted this host's RSA key. The phone's owner tapped "Allow".
  * fastboot -- *inspection* only. The fastboot protocol has no partition-read
              command; it is a flash protocol. What it is genuinely useful for
              forensically is provenance: serial, hardware revision, and above
              all whether the bootloader is unlocked. This module reads those
              variables and refuses to go further.

There is deliberately no engine for BootROM download modes.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Optional, Sequence

from . import PRODUCT_NAME, __version__
from . import ewc as ewc_mod
from .custody import CustodyLog
from .integrity import (
    DEFAULT_ALGOS,
    Progress,
    SourceNotReadable,
    hash_file,
    open_readonly,
    source_size,
    stream_copy,
)
from .policy import Authorization, HostInfo, Refused, write_authorization_record

Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]


def default_runner(args: Sequence[str]) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(list(args), capture_output=True, text=True, timeout=120,
                          check=False)


class ToolMissing(Exception):
    """adb/fastboot not on PATH."""


@dataclass
class AcquisitionResult:
    manifest_path: str
    custody_path: str
    authorization_path: str
    artifacts: list[str] = field(default_factory=list)
    total_bytes: int = 0
    digests: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "manifest": self.manifest_path,
            "custody": self.custody_path,
            "authorization": self.authorization_path,
            "artifacts": self.artifacts,
            "total_bytes": self.total_bytes,
            "digests": self.digests,
        }


def _require_tool(name: str, runner: Runner = default_runner) -> str:
    found = shutil.which(name)
    if not found:
        raise ToolMissing(
            f"`{name}` is not on PATH. Install Android platform-tools "
            "(https://developer.android.com/tools/releases/platform-tools) "
            "and retry."
        )
    return found


def _out_dir(dest: str, case: str) -> str:
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    path = os.path.join(dest, f"{case}_{stamp}")
    os.makedirs(path, exist_ok=True)
    return path


# --- block engine -------------------------------------------------------------


def acquire_block(
    source: str,
    dest_root: str,
    auth: Authorization,
    partition_name: str = "userdata",
    device_alias: str = "",
    manufacturer: str = "",
    model: str = "",
    algos: tuple[str, ...] = DEFAULT_ALGOS,
    progress: Optional[Progress] = None,
    runner: Runner = default_runner,
) -> AcquisitionResult:
    """Image `source` to an evidence folder. Source is opened strictly read-only."""
    host = HostInfo.capture()
    out = _out_dir(dest_root, auth.case_number)
    custody_path = os.path.join(out, "custody.jsonl")
    auth_path = os.path.join(out, "authorization.json")
    manifest_path = os.path.join(out, "device.ewc")
    image_path = os.path.join(out, f"{partition_name}.bin")

    write_authorization_record(auth_path, auth, host)

    with CustodyLog(custody_path, auth.case_number, auth.examiner) as log:
        log.record("AUTHORIZATION_RECORDED", **auth.to_dict())
        log.record("HOST_CAPTURED", **host.to_dict())
        log.record("ACQUISITION_OPEN", engine="block", source=source,
                   destination=image_path)

        try:
            total = source_size(source)
        except SourceNotReadable as exc:
            log.record("ACQUISITION_ABORT", reason=str(exc))
            raise

        log.record("SOURCE_SIZED", path=source, size=total)

        try:
            fd = open_readonly(source)
        except SourceNotReadable as exc:
            log.record("ACQUISITION_ABORT", reason=str(exc))
            raise
        log.record("SOURCE_OPENED_READONLY", path=source, fd=fd)

        start = ewc_mod.utc_now_stamp()
        if progress is None:
            progress = Progress(total=total)
        else:
            progress.total = total

        try:
            result = stream_copy(fd, image_path, total, algos=algos, progress=progress)
        finally:
            os.close(fd)
            log.record("SOURCE_CLOSED", path=source)

        end = ewc_mod.utc_now_stamp()
        log.record(
            "ACQUISITION_COMPLETE",
            engine="block",
            size=result.size,
            seconds=round(progress.elapsed, 3),
            throughput_mbps=round(progress.rate / 1e6, 3),
            largest_stall_seconds=round(progress.largest_gap, 3),
            **result.digests,
        )

        if result.size != total:
            log.record("SIZE_MISMATCH", declared=total, actual=result.size)
            raise IOError(
                f"short read: declared {total} bytes, wrote {result.size}. "
                "The image is truncated -- do not rely on it."
            )

        manifest = ewc_mod.Ewc(
            content_type="ANDROID_IMAGE",
            extraction_method="AFAW_BlockReadOnly",
            extraction_start_utc=start,
            extraction_end_utc=end,
            internal_model_name=model,
            product_name=PRODUCT_NAME,
            product_version=__version__,
            device_alias=device_alias or auth.device_alias,
            manufacturer=manufacturer,
            case_number=auth.case_number,
            examiner=auth.examiner,
            acquisition_path=f"block:{source}",
            partitions=[
                ewc_mod.Partition(
                    name=partition_name,
                    file=os.path.basename(image_path),
                    size=result.size,
                    sha256=result.digests.get("sha256", ""),
                    sha1=result.digests.get("sha1", ""),
                    md5=result.digests.get("md5", ""),
                )
            ],
            notes=["Source opened O_RDONLY; no write path exists to the source."],
        )
        manifest.write(manifest_path)
        log.record("MANIFEST_WRITTEN", path=manifest_path, keys=ewc_mod.count_keys(manifest))

    return AcquisitionResult(
        manifest_path=manifest_path,
        custody_path=custody_path,
        authorization_path=auth_path,
        artifacts=[image_path],
        total_bytes=result.size,
        digests=result.digests,
    )


# --- adb engine ---------------------------------------------------------------

# Shared storage and anything else readable without root. `tar` skips what it
# cannot open rather than failing the whole run.
ADB_LOGICAL_PATHS: tuple[str, ...] = (
    "/sdcard",
    "/data/local/tmp",
    "/data/media/0",
)

ADB_GETPROP_KEYS = (
    "ro.product.manufacturer",
    "ro.product.model",
    "ro.product.device",
    "ro.build.fingerprint",
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.serialno",
    "ro.boot.serialno",
    "ro.boot.verifiedbootstate",
    "ro.crypto.state",
    "ro.crypto.type",
    "persist.sys.timezone",
)


def adb_state(serial: str, runner: Runner = default_runner) -> dict:
    """Is the device authorized? Returns {'state': ..., 'serial': ...}."""
    _require_tool("adb", runner)
    proc = runner(["adb", "devices", "-l"])
    for line in proc.stdout.splitlines()[1:]:
        parts = line.split()
        if parts and parts[0] == serial:
            return {"serial": serial, "state": parts[1] if len(parts) > 1 else "unknown",
                    "detail": line}
    return {"serial": serial, "state": "absent", "detail": ""}


def adb_prop(serial: str, key: str, runner: Runner = default_runner) -> str:
    proc = runner(["adb", "-s", serial, "shell", "getprop", key])
    return proc.stdout.strip()


def adb_provenance(serial: str, runner: Runner = default_runner) -> dict:
    out = {}
    for key in ADB_GETPROP_KEYS:
        out[key] = adb_prop(serial, key, runner)
    return out


def acquire_adb(
    serial: str,
    dest_root: str,
    auth: Authorization,
    paths: Sequence[str] = ADB_LOGICAL_PATHS,
    algos: tuple[str, ...] = DEFAULT_ALGOS,
    progress: Optional[Progress] = None,
    runner: Runner = default_runner,
) -> AcquisitionResult:
    """Logical acquisition from an authorized, powered-on device.

    The device must be in state `device` -- which only happens after someone
    tapped "Allow USB debugging" on the handset. An `unauthorized` device is a
    device whose owner has not consented, and this engine stops there.
    """
    if not auth.device_owner_consent:
        raise Refused(
            "acquire adb requires --owner-consent. ADB hands data over only "
            "after the handset accepts this host's key, which is the owner "
            "consenting on the device. Confirm that happened, then re-run "
            "with the flag."
        )

    _require_tool("adb", runner)
    host = HostInfo.capture()
    out = _out_dir(dest_root, auth.case_number)
    custody_path = os.path.join(out, "custody.jsonl")
    auth_path = os.path.join(out, "authorization.json")
    manifest_path = os.path.join(out, "device.ewc")
    image_path = os.path.join(out, "logical.tar")

    write_authorization_record(auth_path, auth, host)

    with CustodyLog(custody_path, auth.case_number, auth.examiner) as log:
        log.record("AUTHORIZATION_RECORDED", **auth.to_dict())
        log.record("HOST_CAPTURED", **host.to_dict())

        state = adb_state(serial, runner)
        log.record("ADB_STATE", **state)
        if state["state"] != "device":
            log.record("ACQUISITION_ABORT", reason=f"adb state={state['state']}")
            raise Refused(
                f"adb reports state '{state['state']}' for {serial}. Only "
                "'device' is acquirable -- that state means the handset "
                "accepted this host's RSA key. 'unauthorized' means no one "
                "consented on the device, and this tool will not go around it."
            )

        prov = adb_provenance(serial, runner)
        log.record("DEVICE_PROVENANCE", **prov)

        start = ewc_mod.utc_now_stamp()
        cmd = ["adb", "-s", serial, "exec-out", "tar", "-cf", "-",
               "--ignore-failed-read", *paths]
        log.record("ACQUISITION_OPEN", engine="adb",
                   command=" ".join(shlex.quote(c) for c in cmd),
                   destination=image_path)

        if progress is None:
            progress = Progress(total=0)

        hs = {a: hashlib.new(a) for a in algos}
        size = 0
        tmp = image_path + ".part"
        try:
            # Popen as a context manager closes the pipes and reaps the child,
            # including when the read loop raises.
            with subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL) as proc:
                assert proc.stdout is not None
                with open(tmp, "wb", buffering=0) as fh:
                    while True:
                        buf = proc.stdout.read(4 * 1024 * 1024)
                        if not buf:
                            break
                        fh.write(buf)
                        size += len(buf)
                        for h in hs.values():
                            h.update(buf)
                        progress.advance(len(buf))
            os.replace(tmp, image_path)
        finally:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

        end = ewc_mod.utc_now_stamp()
        digests = {a: h.hexdigest() for a, h in hs.items()}
        log.record("ACQUISITION_COMPLETE", engine="adb", size=size,
                   seconds=round(progress.elapsed, 3),
                   throughput_mbps=round(progress.rate / 1e6, 3), **digests)

        manifest = ewc_mod.Ewc(
            content_type="ANDROID_LOGICAL",
            extraction_method="AFAW_AdbLogical",
            extraction_start_utc=start,
            extraction_end_utc=end,
            internal_model_name=prov.get("ro.product.device", ""),
            product_name=PRODUCT_NAME,
            product_version=__version__,
            device_alias=auth.device_alias,
            manufacturer=prov.get("ro.product.manufacturer", ""),
            case_number=auth.case_number,
            examiner=auth.examiner,
            acquisition_path=f"adb:{serial}",
            partitions=[
                ewc_mod.Partition(
                    name="logical_tar",
                    file=os.path.basename(image_path),
                    size=size,
                    sha256=digests.get("sha256", ""),
                    sha1=digests.get("sha1", ""),
                    md5=digests.get("md5", ""),
                )
            ],
            notes=[
                "Logical acquisition: shared storage and world-readable paths only.",
                "Requires the handset to have accepted this host's ADB RSA key.",
                "Paths: " + " ".join(paths),
            ],
        )
        manifest.write(manifest_path)
        log.record("MANIFEST_WRITTEN", path=manifest_path,
                   keys=ewc_mod.count_keys(manifest))

    return AcquisitionResult(
        manifest_path=manifest_path,
        custody_path=custody_path,
        authorization_path=auth_path,
        artifacts=[image_path],
        total_bytes=size,
        digests=digests,
    )


# --- fastboot inspection ------------------------------------------------------

FASTBOOT_VARS = ("unlocked", "serialno", "version-bootloader", "product",
                 "variant", "secure", "off-mode-charge")


def fastboot_inspect(serial: str, runner: Runner = default_runner) -> dict:
    """Read fastboot variables. No flash, no unlock, no partition read."""
    _require_tool("fastboot", runner)
    out: dict[str, str] = {}
    for var in FASTBOOT_VARS:
        proc = runner(["fastboot", "-s", serial, "getvar", var])
        text = (proc.stderr or "") + (proc.stdout or "")
        for line in text.splitlines():
            if line.startswith(f"{var}:"):
                out[var] = line.split(":", 1)[1].strip()
                break
        out.setdefault(var, "")
    return out


def bootloader_unlocked(vars_: dict) -> bool:
    return str(vars_.get("unlocked", "")).strip().lower() in ("yes", "true", "1")
