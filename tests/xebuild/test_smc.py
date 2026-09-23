"""Knowing an SMC before writing one.

Every number here was read off the nineteen images the release ships, by handing each
one to the original and keeping what it printed. So the made-up half is small -- an SMC
is not a structure to be constructed, it is code -- and the measured half is the point:
given the release's own images, this says exactly what the original said about each.
"""

import binascii
import unittest

from xebuild.smc import CLEAN, MOTHERBOARDS, Smc


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
