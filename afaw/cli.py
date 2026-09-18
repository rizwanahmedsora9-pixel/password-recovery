"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional, Sequence

from . import PRODUCT_NAME, __version__
from . import acquire as acq
from . import modes as modes_mod
from . import verify as verify_mod
from .integrity import DEFAULT_ALGOS, Progress, compact, describe_alignment, human
from .policy import Authorization, NotAuthorized, Refused

BANNER = f"""{PRODUCT_NAME} {__version__} — Android Forensic Acquisition Workbench

Reads data off devices that are willing to give it up, and proves what it read.
It does not exploit BootROM download modes and never writes to a source device.
"""

REFUSAL_FOOTER = """
This refusal is deliberate, not a missing feature. Reaching flash on a device
that has not consented means either a BootROM exploit (unpatchable, and a
device-compromise capability rather than a forensic tool) or a vendor-signed
loader binary. Both are what licensed forensic products are licensed for.
"""


def _add_auth_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--case", required=True, help="case / exhibit number")
    p.add_argument("--examiner", required=True, help="examiner name")
    p.add_argument("--basis", required=True,
                   help="legal basis, e.g. 'owner consent', 'warrant 2026-114', "
                        "'corporate policy AUP-4'")
    p.add_argument("--device-alias", default="", help="friendly device name")


def _make_auth(args: argparse.Namespace) -> Authorization:
    return Authorization(
        case_number=args.case,
        examiner=args.examiner,
        legal_basis=args.basis,
        device_alias=getattr(args, "device_alias", "") or "",
        device_owner_consent=getattr(args, "owner_consent", False),
    )


def _progress_printer() -> Progress:
    prog = Progress()
    last = [0.0]

    def notify(done: int, total: int, rate: float) -> None:
        import time as _t

        now = _t.monotonic()
        if now - last[0] < 1.0 and total and done < total:
            return
        last[0] = now
        pct = (done / total * 100) if total else 0.0
        sys.stderr.write(
            f"\r  {compact(done)}"
            + (f" / {compact(total)}" if total else "")
            + f"  {pct:5.1f}%  {rate / 1e6:6.2f} MB/s"
            + (f"  ETA {prog.eta_seconds / 60:5.1f} min" if prog.remaining else "")
            + "        "
        )
        sys.stderr.flush()

    prog.notify = notify
    return prog


# --- subcommands --------------------------------------------------------------


def cmd_detect(args: argparse.Namespace) -> int:
    matches = modes_mod.detect(args.from_json)
    if not matches:
        print("No USB devices found. On Linux this reads /sys/bus/usb/devices; "
              "if that is empty, `lsusb` is the fallback and it is not on PATH.")
        return 0

    refused = [m for m in matches if m.classification == modes_mod.REFUSED]
    ok = [m for m in matches if m.classification == modes_mod.ACQUIRABLE]
    cond = [m for m in matches if m.classification == modes_mod.CONDITIONAL]
    unk = [m for m in matches if m.classification == "unknown"]

    marks = {modes_mod.ACQUIRABLE: "ACQUIRABLE", modes_mod.CONDITIONAL: "CONDITIONAL",
             modes_mod.REFUSED: "REFUSED", "unknown": "UNKNOWN"}

    for m in matches:
        print(f"[{marks[m.classification]:<11}] {m.label}")
        print(f"              id={m.device.id}  vendor={m.vendor}"
              + (f"  bus={m.device.bus} port={m.device.port}" if m.device.bus else "")
              + (f"\n              product={m.device.product}" if m.device.product else ""))
        if m.note:
            print(f"              {m.note}")
        print()

    print(f"{len(matches)} device(s): {len(ok)} acquirable, {len(cond)} conditional, "
          f"{len(refused)} refused, {len(unk)} unknown")
    if refused:
        print(REFUSAL_FOOTER.rstrip())
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump([m.to_dict() for m in matches], fh, indent=2)
            fh.write("\n")
        print(f"\nwrote {args.json}")
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    if args.mode == "adb":
        state = acq.adb_state(args.serial)
        print(json.dumps(state, indent=2))
        if state["state"] == "device":
            print("\nprovenance:")
            print(json.dumps(acq.adb_provenance(args.serial), indent=2))
        else:
            print(f"\nadb state is '{state['state']}', not 'device' — "
                  "nothing further will be read.")
        return 0

    vars_ = acq.fastboot_inspect(args.serial)
    print(json.dumps(vars_, indent=2))
    if acq.bootloader_unlocked(vars_):
        print("\nbootloader: UNLOCKED — the owner removed the security boundary. "
              "Partition reads are a vendor `fastboot oem` matter; this tool "
              "records provenance only and does not flash or unlock.")
    else:
        print("\nbootloader: LOCKED — fastboot is a flash protocol with no "
              "partition-read command, so there is nothing to acquire here.")
    return 0


def cmd_acquire_block(args: argparse.Namespace) -> int:
    auth = _make_auth(args)
    if os.path.isdir(args.source):
        print(f"error: {args.source} is a directory, not an image", file=sys.stderr)
        return 2
    print(f"source:      {args.source}")
    print(f"authorization: case={auth.case_number} examiner={auth.examiner} "
          f"basis={auth.legal_basis!r}")
    prog = _progress_printer()
    res = acq.acquire_block(
        source=args.source,
        dest_root=args.dest,
        auth=auth,
        partition_name=args.partition,
        device_alias=auth.device_alias,
        manufacturer=args.manufacturer,
        model=args.model,
        progress=prog,
    )
    sys.stderr.write("\n")
    print(f"\nacquired {human(res.total_bytes)}")
    for algo, value in res.digests.items():
        print(f"  {algo.upper():<7} {value}")
    print(f"\nmanifest:      {res.manifest_path}")
    print(f"custody log:   {res.custody_path}")
    print(f"authorization: {res.authorization_path}")
    return 0


def cmd_acquire_adb(args: argparse.Namespace) -> int:
    auth = _make_auth(args)
    print(f"serial:        {args.serial}")
    print(f"authorization: case={auth.case_number} examiner={auth.examiner} "
          f"basis={auth.legal_basis!r}")
    prog = _progress_printer()
    res = acq.acquire_adb(
        serial=args.serial,
        dest_root=args.dest,
        auth=auth,
        paths=args.paths or acq.ADB_LOGICAL_PATHS,
        progress=prog,
    )
    sys.stderr.write("\n")
    print(f"\nacquired {human(res.total_bytes)}")
    for algo, value in res.digests.items():
        print(f"  {algo.upper():<7} {value}")
    print(f"\nmanifest:      {res.manifest_path}")
    print(f"custody log:   {res.custody_path}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    rep = verify_mod.verify_folder(
        args.folder, algos=DEFAULT_ALGOS, compute_hashes=not args.no_hash
    )
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(rep.to_dict(), fh, indent=2)
            fh.write("\n")
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(rep.markdown())
    if args.quiet:
        print("PASS" if rep.ok else "FAIL")
        return 0 if rep.ok else 1
    print(rep.markdown())
    if args.json:
        print(f"JSON written to {args.json}")
    if args.md:
        print(f"Markdown written to {args.md}")
    return 0 if rep.ok else 1


def cmd_manifest(args: argparse.Namespace) -> int:
    """Compute a hash for an existing image and write a manifest carrying it."""
    from . import ewc as ewc_mod
    from .integrity import hash_file, source_size

    size = source_size(args.image)
    print(f"image:   {args.image}")
    print(f"size:    {human(size)}")
    print(f"aligned: {', '.join(describe_alignment(size)) or 'none'}")
    print("hashing…")
    h = hash_file(args.image)
    for algo, value in h.digests.items():
        print(f"  {algo.upper():<7} {value}")

    manifest = ewc_mod.Ewc(
        content_type=args.content_type,
        extraction_method="AFAW_RetroactiveHash",
        extraction_start_utc=ewc_mod.utc_now_stamp(),
        extraction_end_utc=ewc_mod.utc_now_stamp(),
        internal_model_name=args.model,
        device_alias=args.device_alias,
        manufacturer=args.manufacturer,
        case_number=args.case,
        examiner=args.examiner,
        partitions=[
            ewc_mod.Partition(
                name=args.partition,
                file=os.path.basename(args.image),
                size=size,
                sha256=h.digests["sha256"],
                sha1=h.digests.get("sha1", ""),
                md5=h.digests.get("md5", ""),
            )
        ],
        notes=[
            "Hash computed after acquisition by AFAW; the original extractor "
            "recorded none."
        ],
    )
    out = args.out or os.path.join(
        os.path.dirname(os.path.abspath(args.image)) or ".", "device.ewc"
    )
    if os.path.exists(out) and not args.force:
        print(f"\nrefusing to overwrite existing {out} (use --force)", file=sys.stderr)
        return 2
    manifest.write(out)
    print(f"\nmanifest written: {out} ({ewc_mod.count_keys(manifest)} keys)")
    return 0


# --- parser -------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="afaw",
        description="Android Forensic Acquisition Workbench — authorized read "
                    "paths, with integrity guaranteed in flight.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=BANNER,
    )
    p.add_argument("--version", action="version", version=f"{PRODUCT_NAME} {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("detect", help="identify attached devices and their boot mode")
    d.add_argument("--from-json", metavar="FILE",
                   help="replay devices from a JSON list instead of the host bus")
    d.add_argument("--json", metavar="FILE", help="write the detection result here")
    d.set_defaults(func=cmd_detect)

    ins = sub.add_parser("inspect", help="read provenance from a device (no data)")
    ins.add_argument("mode", choices=("adb", "fastboot"))
    ins.add_argument("--serial", required=True)
    ins.set_defaults(func=cmd_inspect)

    ac = sub.add_parser("acquire", help="acquire from a cooperating device")
    acsub = ac.add_subparsers(dest="engine", required=True)

    b = acsub.add_parser("block", help="read-only image of a file or block device")
    b.add_argument("--source", required=True, help="file or /dev/… to read")
    b.add_argument("--dest", required=True, help="evidence root directory")
    b.add_argument("--partition", default="userdata")
    b.add_argument("--manufacturer", default="")
    b.add_argument("--model", default="")
    _add_auth_args(b)
    b.set_defaults(func=cmd_acquire_block)

    a = acsub.add_parser("adb", help="logical acquisition from an authorized handset")
    a.add_argument("--serial", required=True)
    a.add_argument("--dest", required=True)
    a.add_argument("--paths", nargs="*", help="device paths to include")
    a.add_argument("--manufacturer", default="")
    a.add_argument("--model", default="")
    a.add_argument("--owner-consent", action="store_true",
                   help="confirm the handset accepted this host's ADB key")
    _add_auth_args(a)
    a.set_defaults(func=cmd_acquire_adb)

    v = sub.add_parser("verify", help="verify an existing extraction folder")
    v.add_argument("folder")
    v.add_argument("--json", metavar="FILE")
    v.add_argument("--md", metavar="FILE")
    v.add_argument("--no-hash", action="store_true",
                   help="skip hashing (size and structure checks only)")
    v.add_argument("--quiet", action="store_true", help="print PASS/FAIL only")
    v.set_defaults(func=cmd_verify)

    m = sub.add_parser("manifest", help="hash an existing image and write a manifest")
    m.add_argument("--image", required=True)
    m.add_argument("--out", help="where to write device.ewc")
    m.add_argument("--partition", default="userdata")
    m.add_argument("--content-type", default="ANDROID_IMAGE")
    m.add_argument("--case", default="")
    m.add_argument("--examiner", default="")
    m.add_argument("--device-alias", default="")
    m.add_argument("--manufacturer", default="")
    m.add_argument("--model", default="")
    m.add_argument("--force", action="store_true")
    m.set_defaults(func=cmd_manifest)

    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Refused as exc:
        print(f"\nREFUSED\n\n{exc}", file=sys.stderr)
        return 3
    except NotAuthorized as exc:
        print(f"\nNOT AUTHORIZED\n\n{exc}", file=sys.stderr)
        return 4
    except acq.ToolMissing as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 5
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
