"""Tests for the verification engine, run against the real artifacts in this repo."""

import json
import os
import tempfile
import unittest

from afaw import verify as verify_mod
from afaw.integrity import describe_alignment, gib, human

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(REPO, "extraction_SPDT_2026-09-18 09-00-01.log")
KEYS = os.path.join(REPO, "keys.json")


class TestLogAnalysis(unittest.TestCase):
    """These numbers were derived independently from the raw log first."""

    @classmethod
    def setUpClass(cls):
        cls.la = verify_mod.analyze_log(LOG)

    def test_exists(self):
        self.assertTrue(os.path.exists(LOG))

    def test_size_and_lines(self):
        self.assertEqual(self.la.bytes, 3_334_798)
        self.assertEqual(self.la.lines, 25_087)
        self.assertEqual(self.la.crlf, 25_087)
        self.assertTrue(self.la.valid_utf8)

    def test_progress_vs_substantive(self):
        # 24,985 lines mention setStageProgress. Of those, 24,965 carry a
        # parseable progress value; the other 20 are stage state transitions,
        # which are tracked separately as stage_events.
        self.assertEqual(self.la.set_stage_progress_lines, 24_985)
        self.assertEqual(self.la.progress_lines, 24_965)
        self.assertEqual(self.la.substantive_lines, 102)
        self.assertEqual(self.la.qt_noise_lines, 51)
        self.assertEqual(self.la.lines, 24_985 + 102)

    def test_distinct_tokens(self):
        self.assertEqual(self.la.distinct_tokens, 29)
        # 15 Class::method + Qt::Warning + Qt::Debug carry '::'
        self.assertEqual(self.la.qualified_tokens, 17)
        self.assertEqual(self.la.free_function_tokens, 6)
        self.assertEqual(self.la.marker_tokens, 6)

    def test_stage_timeline_reconstructed(self):
        states = {e["stage"]: e["state"] for e in self.la.stage_events}
        self.assertEqual(len(self.la.stage_events), 20)
        self.assertEqual(states.get("Stage::ReadFullDump"), "Completed")
        self.assertEqual(states.get("Stage::CalcExtractionHashes"), "Completed")
        self.assertEqual(states.get("Stage::STG_ExtractHardwareKeys"), "Completed")

    def test_stage_timeline_captures_the_dfu_prompt(self):
        msgs = " ".join(e["message"] for e in self.la.stage_events)
        self.assertIn("DFU mode", msgs)

    def test_stage_timeline_is_html_stripped(self):
        for e in self.la.stage_events:
            self.assertNotIn("<", e["message"])
            self.assertNotIn("font", e["message"])

    def test_exactly_one_error_line(self):
        self.assertEqual(len(self.la.error_lines), 1)
        e = self.la.error_lines[0]
        self.assertEqual(e["line"], 25_064)
        self.assertIn("calculateFileHash", e["text"])
        self.assertIn("Error open file", e["text"])

    def test_declared_total(self):
        self.assertEqual(self.la.read_window["declared_total"], 31_268_536_320)

    def test_progress_ticks(self):
        self.assertEqual(self.la.read_window["first_tick"], 1)
        self.assertEqual(self.la.read_window["last_tick"], 1000)
        self.assertEqual(self.la.read_window["ticks"], 1000)

    def test_last_sample_reached_the_declared_total(self):
        self.assertEqual(self.la.read_window["last_byte"], 31_268_536_320)

    def test_throughput_matches_the_published_figure(self):
        """The analysis document says ~9.7 MB/s flat throughout."""
        self.assertAlmostEqual(self.la.throughput["overall_mbps"], 9.7, delta=0.5)

    def test_largest_stall_is_under_two_seconds(self):
        """Documented as 1.503 s — the only gap worth naming in the run."""
        self.assertLess(self.la.throughput["largest_stall_seconds"], 2.0)
        self.assertGreater(self.la.throughput["largest_stall_seconds"], 0.5)

    def test_no_stalls_over_five_seconds(self):
        self.assertEqual(self.la.throughput["stalls_over_5s"], 0)
        self.assertEqual(self.la.throughput["stalls_over_10s"], 0)

    def test_read_window_duration(self):
        # 09:00:35 -> 09:54:29 local, ~53.9 minutes
        self.assertAlmostEqual(self.la.read_window["seconds"], 3234, delta=2)

    def test_tool_metadata_extracted(self):
        self.assertIn("2.17.1.1105", self.la.tool.get("version", ""))
        self.assertIn("Windows 10", self.la.tool.get("os", ""))
        self.assertIn("DeviceExtractor.exe", self.la.tool.get("started", ""))

    def test_stages_include_the_real_pipeline(self):
        for stage in ("ReadFullDump", "CalcExtractionHashes", "DeviceConnection",
                      "PatchBoot"):
            self.assertIn(stage, self.la.stages)


class TestKeybagAnalysis(unittest.TestCase):
    def setUp(self):
        self.kb = verify_mod.analyze_keybag(KEYS)

    def test_three_keys_all_wellformed(self):
        self.assertTrue(self.kb.present)
        self.assertEqual(len(self.kb.keys), 3)
        for k in self.kb.keys:
            self.assertTrue(k["valid_hex"], k["name"])
            self.assertEqual(k["bytes"], 32, k["name"])
            self.assertEqual(k["hex_chars"], 64, k["name"])

    def test_key_names(self):
        names = {k["name"] for k in self.kb.keys}
        self.assertEqual(names, {"SPRD_UK_KEY", "SPRD_GK_KEY", "SPRD_KM_KEY"})

    def test_chain_type_decodes_to_spdt(self):
        self.assertEqual(self.kb.chain_type, "53504454")
        self.assertEqual(self.kb.chain_type_ascii, "SPDT")

    def test_keys_are_masked_in_the_report(self):
        """No report may carry a usable key."""
        blob = json.dumps(self.kb.to_dict())
        with open(KEYS, "r", encoding="utf-8") as fh:
            real = json.load(fh)
        for name, value in real.items():
            if name == "ChainType":
                continue
            self.assertNotIn(value, blob, f"{name} leaked into the report")
            self.assertNotIn(value[10:], blob, f"{name} suffix leaked")

    def test_mask_shows_only_a_fingerprint(self):
        m = verify_mod.mask("ab" * 32)
        self.assertIn("64 hex chars", m)
        self.assertLess(len(m), 40)

    def test_missing_keybag(self):
        kb = verify_mod.analyze_keybag("/nonexistent/keys.json")
        self.assertFalse(kb.present)
        self.assertEqual(kb.verdict, "no keybag file")


class TestFolderVerification(unittest.TestCase):
    def test_real_repo_folder_fails_for_the_right_reasons(self):
        rep = verify_mod.verify_folder(REPO, compute_hashes=False)
        codes = {i["code"] for i in rep.issues}
        self.assertFalse(rep.ok)
        # The two defects the analysis document identified.
        self.assertIn("NO_HASH_IN_MANIFEST", codes)
        self.assertIn("PARTITION_FILE_MISSING", codes)

    def test_real_repo_folder_records_no_false_positives(self):
        rep = verify_mod.verify_folder(REPO, compute_hashes=False)
        codes = {i["code"] for i in rep.issues}
        # The manifest is genuine and well-formed; these must not fire.
        for absent in ("NO_MANIFEST", "MANIFEST_PARSE", "MANIFEST_BOM",
                       "NO_PARTITIONS", "KEYBAG_MISSING", "KEYBAG_UNPARSEABLE",
                       "LOG_TOTAL_MISMATCH"):
            self.assertNotIn(absent, codes, f"false positive: {absent}")

    def test_real_folder_manifest_metadata(self):
        rep = verify_mod.verify_folder(REPO, compute_hashes=False)
        self.assertEqual(rep.manifest["bytes"], 424)
        self.assertEqual(rep.manifest["key_count"], 14)
        self.assertEqual(rep.manifest["line_endings"], "CRLF")
        self.assertFalse(rep.manifest["bom"])
        self.assertTrue(rep.manifest["ends_with_blank_line"])
        self.assertFalse(rep.manifest["has_any_hash_field"])
        self.assertEqual(rep.manifest["model"], "X6511")
        self.assertEqual(rep.manifest["duration_seconds"], 3268)

    def test_real_folder_log_total_agrees_with_manifest(self):
        rep = verify_mod.verify_folder(REPO, compute_hashes=False)
        self.assertEqual(rep.manifest["log_declared_total"], 31_268_536_320)
        self.assertEqual(rep.partitions[0]["declared_size"], 31_268_536_320)

    def test_log_error_is_surfaced(self):
        rep = verify_mod.verify_folder(REPO, compute_hashes=False)
        self.assertTrue(any(i["code"] == "LOG_ERROR" for i in rep.issues))

    def test_markdown_renders(self):
        rep = verify_mod.verify_folder(REPO, compute_hashes=False)
        md = rep.markdown()
        self.assertIn("# Verification report", md)
        self.assertIn("FAIL", md)
        self.assertIn("NO_HASH_IN_MANIFEST", md)
        self.assertIn("|", md)

    def test_missing_folder(self):
        rep = verify_mod.verify_folder("/nonexistent/folder")
        self.assertFalse(rep.ok)
        self.assertEqual(rep.issues[0]["code"], "NO_FOLDER")


class TestSyntheticExtraction(unittest.TestCase):
    """Build a complete, sound extraction folder and prove it passes."""

    def test_sound_folder_passes(self):
        from afaw import ewc as ewc_mod
        from afaw.integrity import hash_file

        with tempfile.TemporaryDirectory() as td:
            payload = b"AFAW test payload\n" * 512
            img = os.path.join(td, "userdata.bin")
            with open(img, "wb") as fh:
                fh.write(payload)
            h = hash_file(img)

            m = ewc_mod.Ewc(
                content_type="ANDROID_IMAGE",
                extraction_method="AFAW_BlockReadOnly",
                extraction_start_utc="20260918T040001",
                extraction_end_utc="20260918T045429",
                internal_model_name="X6511",
                product_name="AFAW",
                product_version="0.1.0",
                device_alias="Smart 6",
                manufacturer="Infinix",
                case_number="2026-114",
                examiner="J. Doe",
                partitions=[
                    ewc_mod.Partition(name="userdata", file="userdata.bin",
                                      size=len(payload), sha256=h.digests["sha256"])
                ],
            )
            m.write(os.path.join(td, "device.ewc"))

            rep = verify_mod.verify_folder(td, compute_hashes=True)
            codes = [i["code"] for i in rep.issues]
            self.assertTrue(rep.ok, f"expected PASS, got {codes}")
            self.assertEqual(rep.partitions[0]["delta"], 0)
            self.assertEqual(rep.partitions[0]["computed_sha256"], h.digests["sha256"])

    def test_truncated_image_is_caught(self):
        from afaw import ewc as ewc_mod

        with tempfile.TemporaryDirectory() as td:
            img = os.path.join(td, "userdata.bin")
            with open(img, "wb") as fh:
                fh.write(b"x" * 1000)
            m = ewc_mod.Ewc(
                extraction_method="X", product_name="AFAW", product_version="0.1.0",
                partitions=[
                    ewc_mod.Partition(name="userdata", file="userdata.bin",
                                      size=1024, sha256="ab" * 32)
                ],
            )
            m.write(os.path.join(td, "device.ewc"))

            rep = verify_mod.verify_folder(td, compute_hashes=True)
            codes = {i["code"] for i in rep.issues}
            self.assertFalse(rep.ok)
            self.assertIn("SIZE_MISMATCH", codes)
            self.assertEqual(rep.partitions[0]["delta"], -24)

    def test_altered_image_is_caught(self):
        from afaw import ewc as ewc_mod

        with tempfile.TemporaryDirectory() as td:
            img = os.path.join(td, "userdata.bin")
            with open(img, "wb") as fh:
                fh.write(b"y" * 1024)
            m = ewc_mod.Ewc(
                extraction_method="X", product_name="AFAW", product_version="0.1.0",
                partitions=[
                    ewc_mod.Partition(name="userdata", file="userdata.bin",
                                      size=1024, sha256="ab" * 32)
                ],
            )
            m.write(os.path.join(td, "device.ewc"))

            rep = verify_mod.verify_folder(td, compute_hashes=True)
            codes = {i["code"] for i in rep.issues}
            self.assertIn("SHA256_MISMATCH", codes)
            self.assertFalse(rep.ok)


class TestSizeMaths(unittest.TestCase):
    def test_the_28gb_vs_29gb_trap(self):
        """The exact confusion the analysis document flags."""
        declared = 31_268_536_320
        self.assertAlmostEqual(gib(declared), 29.12, places=2)
        self.assertAlmostEqual(declared / 1e9, 31.27, places=2)
        self.assertIn("29.12 GiB", human(declared))
        self.assertIn("31.27 GB", human(declared))
        self.assertIn("31,268,536,320 bytes", human(declared))

    def test_alignment(self):
        a = describe_alignment(31_268_536_320)
        self.assertTrue(any("512 B sector" in x for x in a))
        self.assertTrue(any("1 MiB" in x for x in a))
        self.assertTrue(any("4 MiB" in x for x in a))
        self.assertEqual(describe_alignment(1025), [])


if __name__ == "__main__":
    unittest.main()


class TestReportHelpers(unittest.TestCase):
    def test_br_becomes_a_separator_not_nothing(self):
        raw = ('<font color="#333">Selected device: <font color="#0064c7">Smart 6'
               '<font color="#333"><br/><font color="#0064c7">Connect the device '
               "via USB in DFU mode <a href='h'><img src='i'/></a>")
        out = verify_mod._strip_html(raw)
        self.assertIn("Smart 6 — Connect the device via USB in DFU mode", out)
        self.assertNotIn("<", out)
        self.assertNotIn("Smart 6Connect", out)

    def test_clip_breaks_on_a_word(self):
        self.assertEqual(verify_mod._clip(""), "—")
        self.assertEqual(verify_mod._clip("short", 72), "short")
        clipped = verify_mod._clip("alpha beta gamma delta epsilon", 15)
        self.assertTrue(clipped.endswith("…"))
        self.assertLessEqual(len(clipped), 17)
        self.assertFalse(clipped[:-1].endswith("gam"))

    def test_short_hash(self):
        self.assertEqual(verify_mod._short_hash(None), "—")
        self.assertEqual(verify_mod._short_hash(""), "—")
        self.assertIn("ab" * 8, verify_mod._short_hash("ab" * 32))
