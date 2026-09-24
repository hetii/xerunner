"""Knowing an SMC before writing one.

Every number here was read off the nineteen images the release ships, by handing each
one to the original and keeping what it printed. So the made-up half is small -- an SMC
is not a structure to be constructed, it is code -- and the measured half is the point:
given the release's own images, this says exactly what the original said about each.
"""

import binascii
import unittest

from xebuild.crypto import smc as cipher
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


class AnSmcHandedIn(unittest.TestCase):
    """`handed_in`: the original's test at 0x41BABC, four zeros at the end or not."""

    def test_one_in_the_clear_is_taken_as_it_stands(self):
        plain = an_smc()
        self.assertEqual(Smc.handed_in(plain).plain, plain)

    def test_a_sealed_one_is_opened(self):
        plain = an_smc()
        opened = Smc.handed_in(cipher.sealed(plain, b"\x12\x34\x56\x78"))
        self.assertEqual(opened.plain[4:], plain[4:])

    def test_one_that_does_not_open_to_four_zeros_is_none(self):
        noise = bytes((at * 37 + 11) & 0xFF for at in range(0x3000))
        self.assertIsNone(Smc.handed_in(noise[:-4] + b"\x01\x02\x03\x04"))

    def test_nothing_but_one_byte_is_blank(self):
        self.assertTrue(Smc(bytes(0x3000)).blank)
        self.assertTrue(Smc(b"\xff" * 0x3000).blank)
        self.assertFalse(Smc(an_smc()).blank)


class CleanForAnImageType(unittest.TestCase):
    """`clean_for`, the classifier at 0x40BD80, for an SMC none of the stock ones."""

    def a_marked_smc(self, limit: bool) -> Smc:
        out = bytearray(an_smc(limit_at=0x400 if limit else -1))
        out[0x800:0x803] = bytes.fromhex("78bab6")
        return Smc(bytes(out))

    def test_by_type_with_the_reset_limit_and_no_mark(self):
        one = Smc(an_smc(limit_at=0x400))
        self.assertEqual([one.clean_for(n) for n in (1, 2, 3, 4, 5, 6)],
                         [True, True, True, False, False, True])

    def test_by_type_with_neither(self):
        one = Smc(an_smc(limit_at=-1))
        self.assertEqual([one.clean_for(n) for n in (1, 2, 3, 4, 5, 6)],
                         [False, True, False, False, False, False])

    def test_a_hack_mark_is_what_jtag_asks_about(self):
        self.assertFalse(self.a_marked_smc(limit=True).clean_for(2))
        self.assertTrue(self.a_marked_smc(limit=True).clean_for(3))
        self.assertFalse(self.a_marked_smc(limit=True).clean_for(1))
