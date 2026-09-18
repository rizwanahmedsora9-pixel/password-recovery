"""
AFAW -- Android Forensic Acquisition Workbench.

A tool for acquiring and verifying mobile forensic images over the paths that
do not require defeating the device's security.

Design rules, enforced in code rather than in documentation:

  1. Every acquisition is opened strictly read-only. There is no write path to
     a source device anywhere in this package.
  2. Acquisition requires a recorded authorization (case number, examiner,
     legal basis). See policy.py.
  3. Boot-ROM download modes -- Qualcomm EDL, Unisoc/SPRD DFU, MediaTek
     preloader, Rockchip maskrom, Samsung Odin -- are *detected and reported*
     but never driven. Doing so requires either an unpatchable BootROM exploit
     or vendor-signed loader binaries; this package contains neither and will
     not fetch, generate, or accept them. See modes.py:REFUSED_MODES.
  4. Integrity is computed while bytes are in flight, never after the fact,
     and every hash is written into the manifest and the custody log.
"""

__version__ = "0.1.0"
PRODUCT_NAME = "AFAW"

__all__ = ["__version__", "PRODUCT_NAME"]
