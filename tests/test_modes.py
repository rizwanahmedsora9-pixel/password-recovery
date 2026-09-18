"""Tests for mode identification and the refusal policy."""

import unittest

from afaw import modes as modes_mod
from afaw.policy import Authorization, NotAuthorized, Refused, assert_acquirable


def dev(vid, pid):
    return modes_mod.UsbDevice(vid=vid, pid=pid, bus="1", port="2",
                               product="test")


class TestClassification(unittest.TestCase):
    def test_adb_is_acquirable(self):
        for pid in ("4ee1", "4ee7", "4eea"):
            m = modes_mod.classify(dev("18d1", pid))
            self.assertEqual(m.classification, modes_mod.ACQUIRABLE, pid)
            self.assertEqual(m.mode, "adb")

    def test_qualcomm_edl_is_refused(self):
        m = modes_mod.classify(dev("05c6", "9008"))
        self.assertEqual(m.mode, "qualcomm_edl")
        self.assertEqual(m.classification, modes_mod.REFUSED)
        self.assertIn("firehose", m.note)

    def test_unisoc_dfu_is_refused(self):
        """The mode the SPDT extraction in this repo used must be refused."""
        m = modes_mod.classify(dev("1782", "4d00"))
        self.assertEqual(m.mode, "unisoc_dfu")
        self.assertEqual(m.classification, modes_mod.REFUSED)
        self.assertIn("BootROM", m.note)

    def test_all_bootrom_modes_refused(self):
        cases = {
            "05c6:9008": "qualcomm_edl",
            "1782:4d00": "unisoc_dfu",
            "0e8d:0003": "mtk_preloader",
            "2207:350a": "rockchip_maskrom",
            "04e8:685d": "samsung_odin",
        }
        for idstr, expected in cases.items():
            vid, pid = idstr.split(":")
            m = modes_mod.classify(dev(vid, pid))
            self.assertEqual(m.mode, expected, idstr)
            self.assertEqual(m.classification, modes_mod.REFUSED, idstr)

    def test_fastboot_is_conditional_not_refused(self):
        m = modes_mod.classify(dev("18d1", "4ee0"))
        self.assertEqual(m.classification, modes_mod.CONDITIONAL)
        self.assertIn("unlocked", m.note)

    def test_unknown_pid_falls_back_to_vendor(self):
        m = modes_mod.classify(dev("2e17", "9999"))
        self.assertEqual(m.classification, "unknown")
        self.assertEqual(m.vendor, "Infinix/Transsion")

    def test_totally_unknown_vendor(self):
        m = modes_mod.classify(dev("ffff", "0001"))
        self.assertEqual(m.vendor, "Unknown")
        self.assertEqual(m.classification, "unknown")

    def test_every_refused_mode_has_a_reason(self):
        for m in modes_mod.TABLE.values():
            if m.classification == modes_mod.REFUSED:
                self.assertIn(m.mode, modes_mod.REFUSED_MODES)
                self.assertTrue(m.note)

    def test_enumerate_from_payload(self):
        devs = modes_mod.enumerate_from_payload(
            [{"vid": "18D1", "pid": "4EE7"}, {"vid": "05c6", "pid": "9008"}]
        )
        self.assertEqual(devs[0].vid, "18d1")
        self.assertEqual(len(devs), 2)
        with self.assertRaises(ValueError):
            modes_mod.enumerate_from_payload([{"vid": "18d1"}])


class TestPolicyGate(unittest.TestCase):
    def test_refused_mode_raises(self):
        with self.assertRaises(Refused) as ctx:
            assert_acquirable(modes_mod.classify(dev("1782", "4d00")))
        self.assertIn("Unisoc", str(ctx.exception))
        self.assertIn("licensed", str(ctx.exception))

    def test_edl_refusal_mentions_what_to_do_instead(self):
        with self.assertRaises(Refused) as ctx:
            assert_acquirable(modes_mod.classify(dev("05c6", "9008")))
        msg = str(ctx.exception)
        self.assertIn("acquire adb", msg)
        self.assertIn("verify", msg)

    def test_unknown_raises(self):
        with self.assertRaises(Refused):
            assert_acquirable(modes_mod.classify(dev("ffff", "0001")))

    def test_adb_passes(self):
        assert_acquirable(modes_mod.classify(dev("18d1", "4ee7")))  # no raise

    def test_fastboot_passes_the_gate(self):
        """Conditional, not refused — the unlock check lives in acquire."""
        assert_acquirable(modes_mod.classify(dev("18d1", "4ee0")))


class TestAuthorization(unittest.TestCase):
    def test_complete_is_accepted(self):
        a = Authorization(case_number="2026-114", examiner="J. Doe",
                          legal_basis="owner consent")
        self.assertEqual(a.case_number, "2026-114")
        self.assertFalse(a.device_owner_consent)
        self.assertEqual(len(a.issued_utc), 15)

    def test_missing_field_is_rejected(self):
        for kwargs in (
            {"case_number": "", "examiner": "x", "legal_basis": "y"},
            {"case_number": "x", "examiner": "", "legal_basis": "y"},
            {"case_number": "x", "examiner": "y", "legal_basis": ""},
            {"case_number": "  ", "examiner": "y", "legal_basis": "z"},
        ):
            with self.assertRaises(NotAuthorized, msg=str(kwargs)):
                Authorization(**kwargs)

    def test_serialises(self):
        a = Authorization(case_number="c", examiner="e", legal_basis="b")
        d = a.to_dict()
        for key in ("case_number", "examiner", "legal_basis", "issued_utc"):
            self.assertIn(key, d)


if __name__ == "__main__":
    unittest.main()
