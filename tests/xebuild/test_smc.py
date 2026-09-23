"""Knowing an SMC before writing one.

Every number here was read off the nineteen images the release ships, by handing each
one to the original and keeping what it printed. So the made-up half is small -- an SMC
is not a structure to be constructed, it is code -- and the measured half is the point:
given the release's own images, this says exactly what the original said about each.
"""

import binascii
import os
import unittest

from xebuild.smc import CLEAN, MOTHERBOARDS, Smc

# What the original printed for each of the nineteen, as `checksum, type, clean`.
MEASURED = {
    "CORONA_CLEAN.bin": (0xBA42AB9F, "Corona v6.2(2.05)", True),
    "CORONA_CR4.bin": (0xFD7C6B42, "Corona v6.2(2.05)", False),
    "CORONA_SMC+.bin": (0xAC75B875, "Corona v6.2(2.05)", False),
    "FALCON_CLEAN.bin": (0x1D0C613E, "Falcon v3.1(1.06)", True),
    "FALCON_CR4.bin": (0x45EBE68A, "Falcon v3.1(1.06)", False),
    "FALCON_SMC+.bin": (0xDF1FFF40, "Falcon v3.1(1.06)", False),
    "JASPER_CLEAN.bin": (0x5B3AED00, "Jasper v4.1(2.03)", True),
    "JASPER_CR4.bin": (0x496EBD95, "Jasper v4.1(2.03)", False),
    "JASPER_SMC+.bin": (0x2C68E839, "Jasper v4.1(2.03)", False),
    "SMCaud.bin": (0x260EED31, "Jasper v4.1(2.03)", False),
    "SMCfzj.bin": (0xC507F5BA, "Jasper v4.1(2.03)", False),
    "SMCx.bin": (0xC69F53A0, "Xenon v1.2(1.51)", False),
    "TRINITY_CLEAN.bin": (0xF9C96639, "Trinity v5.1(3.01)", True),
    "TRINITY_CR4.bin": (0x716AD3AE, "Trinity v5.1(3.01)", False),
    "TRINITY_SMC+.bin": (0xEB13F7C6, "Trinity v5.1(3.01)", False),
    "WINCHESTER_CLEAN.bin": (0x3A0059DB, "Unknown v7.1(1.03)", True),
    "XENON_CLEAN.bin": (0xB92ED1BA, "Xenon v1.2(1.51)", False),
    "XENON_SMC+.bin": (0x6E4F4675, "Xenon v1.2(1.51)", False),
    "ZEPHYR_CLEAN.bin": (0x9AD5B7EE, "Zephyr v2.1(1.10)", True),
}

# Where the signature is in each image that still has one. Measured the same way, and
# "glitch hack found in SMC binary!" is printed for exactly the ones missing here.
LIMITS = {
    "CORONA_CLEAN.bin": 0x13B4, "FALCON_CLEAN.bin": 0x12A3,
    "JASPER_CLEAN.bin": 0x12BA, "SMCaud.bin": 0x12BA, "SMCfzj.bin": 0x12BA,
    "SMCx.bin": 0x1180, "TRINITY_CLEAN.bin": 0x13B3, "WINCHESTER_CLEAN.bin": 0x137F,
    "XENON_CLEAN.bin": 0x1180, "ZEPHYR_CLEAN.bin": 0x1257,
}


def an_smc(nibbles: int = 0x51, revision=(3, 1), limit_at: int = 0x400) -> bytes:
    """Enough of an image for this to read: the version bytes and a signature.

    The signature goes at 0x400 by default and not lower: laying it over 0x100 buries
    the version bytes, which is what the first draft of this did.
    """
    out = bytearray(0x3000)
    out[0x100] = nibbles
    out[0x101], out[0x102] = revision
    if limit_at >= 0:
        out[limit_at : limit_at + 6] = bytes.fromhex("053ce53cb405")
    return bytes(out)


class WhatAnSmcSaysAboutItself(unittest.TestCase):
    def test_the_version_is_spelled_the_way_the_original_spells_it(self):
        self.assertEqual(Smc(an_smc(0x51, (3, 1))).version, "v5.1(3.01)")
        self.assertEqual(Smc(an_smc(0x62, (2, 5))).version, "v6.2(2.05)")

    def test_all_seven_motherboards_and_the_one_with_no_name(self):
        self.assertEqual(len(MOTHERBOARDS), 7)
        self.assertEqual(Smc(an_smc(0x51)).motherboard, "Trinity")
        self.assertEqual(Smc(an_smc(0x71)).motherboard, "Unknown")

    def test_a_board_number_that_is_none_of_the_seven(self):
        self.assertEqual(Smc(an_smc(0xF1)).motherboard, "")
        self.assertEqual(Smc(an_smc(0xF1)).named, "Unknown v15.1(3.01)")

    def test_the_checksum_skips_the_cipher_s_seed(self):
        """The same image under two seeds has one checksum, which is the whole point."""
        body = bytearray(an_smc())
        was = Smc(bytes(body)).checksum
        body[:4] = b"\xde\xad\xbe\xef"
        self.assertEqual(Smc(bytes(body)).checksum, was)
        self.assertEqual(was, binascii.crc32(bytes(body)[4:]) & 0xFFFFFFFF)

    def test_nothing_made_up_here_is_vouched_for(self):
        self.assertFalse(Smc(an_smc()).clean)
        self.assertEqual(len(CLEAN), 6)

    def test_an_image_with_no_reset_limit_is_one_a_glitch_has_had(self):
        self.assertEqual(Smc(an_smc(limit_at=0x400)).reset_limit, 0x400)
        self.assertFalse(Smc(an_smc(limit_at=0x400)).glitched)
        self.assertEqual(Smc(an_smc(limit_at=-1)).reset_limit, -1)
        self.assertTrue(Smc(an_smc(limit_at=-1)).glitched)

    def test_patching_zeroes_two_bytes_and_moves_nothing_else(self):
        one = Smc(an_smc(limit_at=0x400))
        out = one.patched()
        self.assertEqual(out[0x400:0x406], bytes.fromhex("0000e53cb405"))
        self.assertEqual(len(out), len(one.plain))
        self.assertEqual(out[:0x400], one.plain[:0x400])
        self.assertEqual(out[0x406:], one.plain[0x406:])

    def test_patching_one_that_has_no_limit_changes_nothing(self):
        one = Smc(an_smc(limit_at=-1))
        self.assertEqual(one.patched(), one.plain)


class AgainstEveryImageTheReleaseShips(unittest.TestCase):
    """Skipped unless `XEBUILD_SMC_DIR` names the directory holding them."""

    @classmethod
    def setUpClass(cls):
        where = os.environ.get("XEBUILD_SMC_DIR", "")
        if not where or not os.path.isdir(where):
            raise unittest.SkipTest("XEBUILD_SMC_DIR does not name a directory")
        cls.where = where

    def an_image(self, name):
        path = os.path.join(self.where, name)
        if not os.path.isfile(path):
            self.skipTest("%s is not here" % name)
        with open(path, "rb") as handle:
            return Smc(handle.read())

    def test_each_one_says_what_the_original_said_about_it(self):
        for name, (checksum, named, clean) in MEASURED.items():
            with self.subTest(image=name):
                one = self.an_image(name)
                self.assertEqual(one.checksum, checksum)
                self.assertEqual(one.named, named)
                self.assertEqual(one.clean, clean)

    def test_xenon_s_stock_image_is_not_in_the_original_s_table(self):
        """A gap in its table rather than anything about the image, and worth a test
        of its own: guessing that every CLEAN file is vouched for gets this wrong."""
        self.assertFalse(self.an_image("XENON_CLEAN.bin").clean)
        self.assertTrue(self.an_image("ZEPHYR_CLEAN.bin").clean)

    def test_winchester_s_board_has_no_name_in_the_original(self):
        self.assertEqual(self.an_image("WINCHESTER_CLEAN.bin").named,
                         "Unknown v7.1(1.03)")

    def test_the_reset_limit_is_where_it_was_measured(self):
        for name, at in LIMITS.items():
            with self.subTest(image=name):
                self.assertEqual(self.an_image(name).reset_limit, at)

    def test_every_glitch_image_has_no_limit_and_every_other_one_has(self):
        """The equivalence, with no exception either way over all nineteen."""
        for name in MEASURED:
            with self.subTest(image=name):
                self.assertEqual(self.an_image(name).glitched, name not in LIMITS)
