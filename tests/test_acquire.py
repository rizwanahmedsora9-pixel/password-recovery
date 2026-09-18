"""Tests for the acquisition engines.

The ADB engine is exercised end to end by putting a stand-in `adb` on PATH and
letting the real code shell out to it, so the Popen streaming loop, the hashing
and the manifest writing all run for real.
"""

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from afaw import acquire as acq  # noqa: E402
from afaw import custody as custody_mod  # noqa: E402
from afaw import ewc as ewc_mod  # noqa: E402
from afaw.integrity import SourceNotReadable, hash_file, open_readonly, source_size  # noqa: E402
from afaw.policy import Authorization, Refused  # noqa: E402

FAKE_ADB = r"""#!/bin/sh
state="${AFAW_FAKE_STATE:-device}"
case "$*" in
  "devices -l")
    echo "List of devices attached"
    echo "ABC123                 $state product:redfin model:Pixel_5 device:redfin transport_id:1"
    exit 0 ;;
  *"shell getprop"*)
    key=$(printf '%s\n' "$*" | awk '{print $NF}')
    case "$key" in
      ro.product.manufacturer) echo "Google" ;;
      ro.product.model)        echo "Pixel 5" ;;
      ro.product.device)       echo "redfin" ;;
      ro.crypto.state)         echo "encrypted" ;;
      ro.crypto.type)          echo "file" ;;
      *)                       echo "fake-$key" ;;
    esac
    exit 0 ;;
  *"exec-out tar"*)
    tar -cf - -C "$AFAW_FAKE_ROOT" . 2>/dev/null
    exit 0 ;;
esac
exit 0
"""

FAKE_FASTBOOT = r"""#!/bin/sh
for arg in "$@"; do :; done
var=$(printf '%s\n' "$*" | awk '{print $NF}')
case "$var" in
  unlocked)          echo "unlocked: ${AFAW_FAKE_UNLOCKED:-yes}" >&2 ;;
  serialno)          echo "serialno: 1234567890ABCDEF" >&2 ;;
  version-bootloader) echo "version-bootloader: b5-0.4-9" >&2 ;;
  product)           echo "product: redfin" >&2 ;;
  secure)            echo "secure: yes" >&2 ;;
  *)                 echo "$var: " >&2 ;;
esac
exit 0
"""


class FakeBinMixin:
    """Install stand-in binaries at the front of PATH for the test."""

    def install(self, name: str, body: str) -> str:
        import shutil

        d = tempfile.mkdtemp(prefix="afaw_bin_")
        path = os.path.join(d, name)
        with open(path, "w") as fh:
            fh.write(body)
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP)

        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = d + os.pathsep + old_path

        def restore() -> None:
            os.environ["PATH"] = old_path
            shutil.rmtree(d, ignore_errors=True)

        self.addCleanup(restore)
        return d


def auth(**kw):
    base = dict(case_number="2026-114", examiner="J. Doe",
                legal_basis="owner consent", device_alias="Test handset")
    base.update(kw)
    return Authorization(**base)


class TestReadOnlyGuarantee(unittest.TestCase):
    def test_opened_fd_rejects_writes(self):
        """The write-block guarantee: the descriptor physically cannot write."""
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b"payload")
            path = fh.name
        self.addCleanup(os.unlink, path)
        fd = open_readonly(path)
        try:
            with self.assertRaises(OSError):
                os.write(fd, b"x")
        finally:
            os.close(fd)

    def test_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(SourceNotReadable):
                open_readonly(td)

    def test_missing_source_is_refused(self):
        with self.assertRaises(SourceNotReadable):
            open_readonly("/nonexistent/image.bin")

    def test_source_size(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b"z" * 4096)
            path = fh.name
        self.addCleanup(os.unlink, path)
        self.assertEqual(source_size(path), 4096)

    def test_char_device_sizes_to_zero(self):
        if not os.path.exists("/dev/null"):
            self.skipTest("no /dev/null")
        self.assertEqual(source_size("/dev/null"), 0)


class TestBlockEngine(unittest.TestCase):
    def test_end_to_end_acquisition(self):
        payload = os.urandom(6 * 1024 * 1024 + 12345)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".img") as fh:
            fh.write(payload)
            src = fh.name
        self.addCleanup(os.unlink, src)
        expected = hash_file(src)

        with tempfile.TemporaryDirectory() as dest:
            res = acq.acquire_block(
                source=src, dest_root=dest, auth=auth(),
                partition_name="userdata", manufacturer="Infinix", model="X6511",
            )
            self.assertEqual(res.total_bytes, len(payload))
            self.assertEqual(res.digests["sha256"], expected.digests["sha256"])
            self.assertEqual(res.digests["sha1"], expected.digests["sha1"])
            self.assertEqual(res.digests["md5"], expected.digests["md5"])

            # The image on disk is byte-identical to the source.
            with open(res.artifacts[0], "rb") as fh:
                self.assertEqual(fh.read(), payload)

            # The manifest parses, declares the right size, and carries hashes.
            m = ewc_mod.parse_file(res.manifest_path)
            self.assertEqual(m.extraction_method, "AFAW_BlockReadOnly")
            self.assertEqual(m.manufacturer, "Infinix")
            self.assertEqual(m.internal_model_name, "X6511")
            self.assertEqual(m.case_number, "2026-114")
            self.assertEqual(len(m.partitions), 1)
            self.assertEqual(m.partitions[0].size, len(payload))
            self.assertEqual(m.partitions[0].sha256, expected.digests["sha256"])
            self.assertEqual(m.acquisition_path, f"block:{src}")

            # ...and verifies clean.
            from afaw import verify as verify_mod

            rep = verify_mod.verify_folder(os.path.dirname(res.manifest_path))
            self.assertTrue(rep.ok, [i["code"] for i in rep.issues])

    def test_custody_log_is_complete_and_ordered(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b"x" * 8192)
            src = fh.name
        self.addCleanup(os.unlink, src)

        with tempfile.TemporaryDirectory() as dest:
            res = acq.acquire_block(source=src, dest_root=dest, auth=auth())
            summary = custody_mod.summarize(res.custody_path)
            self.assertTrue(summary["append_only_intact"])
            self.assertEqual(summary["corrupt_lines"], 0)
            for event in ("AUTHORIZATION_RECORDED", "HOST_CAPTURED",
                          "ACQUISITION_OPEN", "SOURCE_SIZED",
                          "SOURCE_OPENED_READONLY", "SOURCE_CLOSED",
                          "ACQUISITION_COMPLETE", "MANIFEST_WRITTEN"):
                self.assertIn(event, summary["events"], event)

            entries = custody_mod.read(res.custody_path)
            complete = [e for e in entries if e["event"] == "ACQUISITION_COMPLETE"][0]
            self.assertIn("sha256", complete)
            self.assertEqual(complete["size"], 8192)

    def test_authorization_is_persisted(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b"x" * 16)
            src = fh.name
        self.addCleanup(os.unlink, src)

        with tempfile.TemporaryDirectory() as dest:
            res = acq.acquire_block(source=src, dest_root=dest, auth=auth())
            with open(res.authorization_path, encoding="utf-8") as fh:
                rec = json.load(fh)
            self.assertEqual(rec["authorization"]["case_number"], "2026-114")
            self.assertEqual(rec["authorization"]["legal_basis"], "owner consent")
            self.assertIn("tool", rec["host"])
            self.assertIn("platform", rec["host"])

    def test_missing_source_aborts_with_a_custody_entry(self):
        with tempfile.TemporaryDirectory() as dest:
            with self.assertRaises(SourceNotReadable):
                acq.acquire_block(source="/nonexistent/x.bin", dest_root=dest,
                                  auth=auth())
            folders = [f for f in os.listdir(dest) if os.path.isdir(os.path.join(dest, f))]
            self.assertEqual(len(folders), 1)
            entries = custody_mod.read(os.path.join(dest, folders[0], "custody.jsonl"))
            self.assertTrue(any(e["event"] == "ACQUISITION_ABORT" for e in entries))


class TestAdbEngine(FakeBinMixin, unittest.TestCase):
    def test_refused_without_owner_consent(self):
        with tempfile.TemporaryDirectory() as dest:
            with self.assertRaises(Refused) as ctx:
                acq.acquire_adb(serial="ABC123", dest_root=dest, auth=auth())
            self.assertIn("--owner-consent", str(ctx.exception))
            self.assertEqual(os.listdir(dest), [], "no evidence folder should exist")

    def test_missing_tool_is_reported(self):
        with tempfile.TemporaryDirectory() as dest:
            # Ensure no adb anywhere on PATH.
            old = os.environ["PATH"]
            os.environ["PATH"] = ""
            self.addCleanup(lambda: os.environ.__setitem__("PATH", old))
            with self.assertRaises(acq.ToolMissing) as ctx:
                acq.acquire_adb(serial="X", dest_root=dest,
                                auth=auth(device_owner_consent=True))
            self.assertIn("platform-tools", str(ctx.exception))

    def test_unauthorized_device_is_refused(self):
        self.install("adb", FAKE_ADB)
        os.environ["AFAW_FAKE_STATE"] = "unauthorized"
        self.addCleanup(lambda: os.environ.pop("AFAW_FAKE_STATE", None))

        with tempfile.TemporaryDirectory() as dest:
            with self.assertRaises(Refused) as ctx:
                acq.acquire_adb(serial="ABC123", dest_root=dest,
                                auth=auth(device_owner_consent=True))
            self.assertIn("unauthorized", str(ctx.exception))
            self.assertIn("consented", str(ctx.exception))

    def test_end_to_end_logical_acquisition(self):
        self.install("adb", FAKE_ADB)

        # A stand-in for the handset's shared storage.
        fake_root = tempfile.mkdtemp(prefix="afaw_sdcard_")
        self.addCleanup(lambda: shutil.rmtree(fake_root, ignore_errors=True))
        os.makedirs(os.path.join(fake_root, "DCIM"))
        with open(os.path.join(fake_root, "DCIM", "photo.jpg"), "wb") as fh:
            fh.write(os.urandom(50_000))
        with open(os.path.join(fake_root, "notes.txt"), "w") as fh:
            fh.write("case notes\n")
        os.environ["AFAW_FAKE_ROOT"] = fake_root
        self.addCleanup(lambda: os.environ.pop("AFAW_FAKE_ROOT", None))

        with tempfile.TemporaryDirectory() as dest:
            res = acq.acquire_adb(serial="ABC123", dest_root=dest,
                                  auth=auth(device_owner_consent=True),
                                  paths=(fake_root,))
            self.assertGreater(res.total_bytes, 50_000)

            # The tar really contains what the handset "had".
            names = subprocess.run(["tar", "-tf", res.artifacts[0]],
                                   capture_output=True, text=True, check=True).stdout
            self.assertIn("photo.jpg", names)
            self.assertIn("notes.txt", names)

            m = ewc_mod.parse_file(res.manifest_path)
            self.assertEqual(m.content_type, "ANDROID_LOGICAL")
            self.assertEqual(m.extraction_method, "AFAW_AdbLogical")
            self.assertEqual(m.manufacturer, "Google")
            self.assertEqual(m.internal_model_name, "redfin")
            self.assertEqual(m.partitions[0].size, res.total_bytes)
            self.assertEqual(len(m.partitions[0].sha256), 64)
            self.assertTrue(any("Logical acquisition" in n for n in m.notes))

            summary = custody_mod.summarize(res.custody_path)
            for event in ("ADB_STATE", "DEVICE_PROVENANCE", "ACQUISITION_OPEN",
                          "ACQUISITION_COMPLETE", "MANIFEST_WRITTEN"):
                self.assertIn(event, summary["events"], event)

            prov = [e for e in custody_mod.read(res.custody_path)
                    if e["event"] == "DEVICE_PROVENANCE"][0]
            self.assertEqual(prov["ro.crypto.state"], "encrypted")

    def test_adb_state_parsing(self):
        self.install("adb", FAKE_ADB)
        s = acq.adb_state("ABC123")
        self.assertEqual(s["state"], "device")
        absent = acq.adb_state("NOPE")
        self.assertEqual(absent["state"], "absent")

    def test_provenance_uses_getprop(self):
        self.install("adb", FAKE_ADB)
        prov = acq.adb_provenance("ABC123")
        self.assertEqual(prov["ro.product.manufacturer"], "Google")
        self.assertEqual(prov["ro.product.model"], "Pixel 5")
        self.assertIn("ro.crypto.type", prov)


class TestFastbootInspection(FakeBinMixin, unittest.TestCase):
    def test_unlocked_detected(self):
        self.install("fastboot", FAKE_FASTBOOT)
        os.environ["AFAW_FAKE_UNLOCKED"] = "yes"
        self.addCleanup(lambda: os.environ.pop("AFAW_FAKE_UNLOCKED", None))
        v = acq.fastboot_inspect("ABC")
        self.assertEqual(v["unlocked"], "yes")
        self.assertEqual(v["product"], "redfin")
        self.assertTrue(acq.bootloader_unlocked(v))

    def test_locked_detected(self):
        self.install("fastboot", FAKE_FASTBOOT)
        os.environ["AFAW_FAKE_UNLOCKED"] = "no"
        self.addCleanup(lambda: os.environ.pop("AFAW_FAKE_UNLOCKED", None))
        v = acq.fastboot_inspect("ABC")
        self.assertFalse(acq.bootloader_unlocked(v))

    def test_unlock_parsing_variants(self):
        self.assertTrue(acq.bootloader_unlocked({"unlocked": "yes"}))
        self.assertTrue(acq.bootloader_unlocked({"unlocked": "TRUE"}))
        self.assertTrue(acq.bootloader_unlocked({"unlocked": "1"}))
        self.assertFalse(acq.bootloader_unlocked({"unlocked": "no"}))
        self.assertFalse(acq.bootloader_unlocked({}))


if __name__ == "__main__":
    unittest.main()
