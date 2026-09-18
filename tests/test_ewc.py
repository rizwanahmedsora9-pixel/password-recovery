"""Tests for the AFAW manifest reader/writer."""

import os
import unittest

from afaw import ewc as ewc_mod

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REAL_EWC = os.path.join(REPO, "device.ewc")


class TestRealManifest(unittest.TestCase):
    """Round-trip the actual 424-byte Oxygen manifest byte-for-byte."""

    def setUp(self):
        self.assertTrue(os.path.exists(REAL_EWC), "device.ewc missing from repo")
        with open(REAL_EWC, "rb") as fh:
            self.raw = fh.read()
        self.ewc = ewc_mod.parse(self.raw.decode("utf-8"))

    def test_byte_count(self):
        self.assertEqual(len(self.raw), 424)

    def test_line_endings_and_bom(self):
        self.assertEqual(self.raw.count(b"\r\n"), self.raw.count(b"\n"))
        self.assertFalse(self.raw.startswith(b"\xef\xbb\xbf"))
        self.assertTrue(self.raw.endswith(b"\r\n\r\n"))

    def test_parses(self):
        self.assertEqual(self.ewc.content_type, "ANDROID_IMAGE")
        self.assertEqual(self.ewc.extraction_method, "SPDT_Method")
        self.assertEqual(self.ewc.internal_model_name, "X6511")
        self.assertEqual(self.ewc.manufacturer, "Infinix")
        self.assertEqual(self.ewc.device_alias, "Smart 6")
        self.assertEqual(self.ewc.product_name, "DeviceExtractor")
        self.assertEqual(self.ewc.product_version, "2.17.1")
        self.assertEqual(self.ewc.key_bag_file, "keys.json")

    def test_partition(self):
        self.assertEqual(len(self.ewc.partitions), 1)
        p = self.ewc.partitions[0]
        self.assertEqual(p.name, "userData")
        self.assertEqual(p.file, "userData.bin")
        self.assertEqual(p.size, 31_268_536_320)
        self.assertEqual(p.sha256, "", "Oxygen recorded no hash")

    def test_key_count_is_14(self):
        self.assertEqual(ewc_mod.count_keys(self.ewc), 14)

    def test_roundtrip_is_byte_identical(self):
        """The writer must reproduce Oxygen's exact bytes."""
        self.assertEqual(self.ewc.dump_bytes(), self.raw)

    def test_no_hash_field_anywhere(self):
        for keys in self.ewc.sections().values():
            for k in keys:
                self.assertNotIn("hash", k.lower())
                self.assertNotIn("sha", k.lower())
                self.assertNotIn("md5", k.lower())

    def test_timestamps_parse_and_ordering(self):
        start = ewc_mod.parse_stamp(self.ewc.extraction_start_utc)
        end = ewc_mod.parse_stamp(self.ewc.extraction_end_utc)
        self.assertIsNotNone(start)
        self.assertIsNotNone(end)
        self.assertLess(start, end)
        self.assertEqual(int((end - start).total_seconds()), 3268)

    def test_bom_is_rejected(self):
        """Oxygen writes no BOM; a BOM'd manifest is not an Oxygen manifest."""
        import tempfile

        with tempfile.NamedTemporaryFile("wb", suffix=".ewc", delete=False) as fh:
            fh.write(b"\xef\xbb\xbf" + self.raw)
            path = fh.name
        try:
            with self.assertRaises(ewc_mod.EwcError):
                ewc_mod.parse_file(path)
        finally:
            os.unlink(path)


class TestNewManifest(unittest.TestCase):
    def test_written_manifest_carries_hashes(self):
        m = ewc_mod.Ewc(
            extraction_method="AFAW_BlockReadOnly",
            extraction_start_utc="20260918T040001",
            extraction_end_utc="20260918T045429",
            internal_model_name="X6511",
            device_alias="Smart 6",
            manufacturer="Infinix",
            case_number="2026-114",
            examiner="J. Doe",
            partitions=[
                ewc_mod.Partition(
                    name="userdata",
                    file="userdata.bin",
                    size=4096,
                    sha256="ab" * 32,
                    sha1="cd" * 20,
                    md5="ef" * 16,
                )
            ],
        )
        blob = m.dump_bytes()
        self.assertTrue(blob.endswith(b"\r\n\r\n"))
        self.assertEqual(blob.count(b"\r\n"), blob.count(b"\n"))
        text = blob.decode("utf-8")
        self.assertIn("Partition 1 SHA256=" + "ab" * 32, text)
        self.assertIn("CaseNumber=2026-114", text)

        again = ewc_mod.parse(text)
        self.assertEqual(again.partitions[0].sha256, "ab" * 32)
        self.assertEqual(again.case_number, "2026-114")
        self.assertEqual(again.partitions[0].size, 4096)

    def test_sections_alphabetical(self):
        m = ewc_mod.Ewc(extraction_method="X", product_version="1",
                         internal_model_name="M", content_type="ANDROID_IMAGE")
        for keys in m.sections().values():
            names = list(keys)
            self.assertEqual(names, sorted(names))

    def test_multiple_partitions_index_from_one(self):
        m = ewc_mod.Ewc(
            partitions=[
                ewc_mod.Partition(name="boot", file="boot.bin", size=1),
                ewc_mod.Partition(name="userdata", file="userdata.bin", size=2),
            ]
        )
        text = m.dumps()
        self.assertIn("Partition 1 Name=boot", text)
        self.assertIn("Partition 2 Name=userdata", text)
        self.assertIn("PartitionsCount=2", text)
        self.assertEqual(len(ewc_mod.parse(text).partitions), 2)

    def test_missing_section_is_a_parse_error(self):
        with self.assertRaises(ewc_mod.EwcError):
            ewc_mod.parse("orphan=value\r\n")


if __name__ == "__main__":
    unittest.main()
