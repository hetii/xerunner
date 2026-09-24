"""The two loaders a JTAG image runs on, and what the original patches in them.

Held against the copies built into xeBuild.exe, which is what the original recognises;
the images that measured the patches are named in `jtag.loaders`.
"""

import unittest

from xebuild import jtag


class TheBuiltInLoaders(unittest.TestCase):

    def test_both_are_the_lengths_the_original_carries(self):
        """File offsets 0x49360 and 0x49560 of xeBuild.exe: 0x200 and 0xD40 bytes."""
        self.assertEqual(len(jtag.builtin("payload.bin")), 0x200)
        self.assertEqual(len(jtag.builtin("freeboot.bin")), 0xD40)


class ThePayload(unittest.TestCase):

    def test_the_known_one_takes_the_core_s_length_in_words(self):
        """"patching payload.bin to load size 0xd40 (0x350 reps)"."""
        known = jtag.builtin("payload.bin")
        self.assertEqual(known[0x50:0x54], bytes.fromhex("3880ffff"))
        out = jtag.payload_for(known, 0xD40)
        self.assertEqual(out[0x50:0x54], bytes.fromhex("38800350"))
        self.assertEqual(out[:0x52] + out[0x54:], known[:0x52] + known[0x54:])

    def test_one_byte_changed_and_it_goes_in_as_it_stands(self):
        other = bytearray(jtag.builtin("payload.bin"))
        other[0x100] ^= 1
        self.assertEqual(jtag.payload_for(bytes(other), 0xD40), bytes(other))


class TheCore(unittest.TestCase):

    def test_the_known_one_takes_the_release_s_version_over_its_x_s(self):
        known = jtag.builtin("freeboot.bin")
        blank = known.find(b"X" * 0x20)
        out = jtag.core_for(known, "17559")
        self.assertEqual(out[blank:blank + 0x20], b"17559".ljust(0x20, b"\x00"))
        self.assertEqual(out[:blank] + out[blank + 0x20:],
                         known[:blank] + known[blank + 0x20:])

    def test_more_behind_the_known_bytes_is_still_the_known_one(self):
        longer = jtag.builtin("freeboot.bin") + b"\x5a" * 0x40
        out = jtag.core_for(longer, "17559")
        self.assertNotEqual(out, longer)
        self.assertEqual(out[0xD40:], b"\x5a" * 0x40)

    def test_9199_moves_the_hold_address_back(self):
        """"9199 ini string detected, patching to old hold address"."""
        out = jtag.core_for(jtag.builtin("freeboot.bin"), "9199")
        self.assertNotIn(bytes.fromhex("8000000001003078"), out)
        self.assertEqual(out.count(bytes.fromhex("80000000001ffff8")), 1)

    def test_one_byte_changed_and_it_goes_in_as_it_stands(self):
        other = bytearray(jtag.builtin("freeboot.bin"))
        other[0x10] ^= 1
        self.assertEqual(jtag.core_for(bytes(other), "17559"), bytes(other))


if __name__ == "__main__":
    unittest.main()
