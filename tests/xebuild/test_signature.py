"""The bootloader signature check under a key made up for it.

No console key and no release file is needed: the key below is a pair of primes drawn
here, and `sign` lays out the block the check expects and raises it to the private
exponent. What it proves is what the check covers and how it reads the key -- that a
stage verifies is proved against the release's own stages in `e2e/e2e_signature.py`.
"""

import random
import hashlib
import unittest

from xebuild.crypto import rc4, signature


class AStageUnderAMadeUpKey(unittest.TestCase):

    P = int("ead9a0c296384f6e890df2cb56397cb4c904705a93490d88149eb09fe84610cb6065adf9"
            "8f4d6a0753ba06a6d102cf6c9681e58a1c04cad49f7a4072302fe04c82c530b933d1fb7c"
            "72699ce3cfcb808debf69badd1f4675d50eddf820413ce02cb23ae1c9407e63e6f51237c"
            "38d6123bbf2dc27662c3faa51f47a635dbf9fb6d", 16)
    Q = int("d1a0d8629707d6aff0512c3394cd6e939ab274152f6e5d050edcdf37aa4fea27a1fa46ea"
            "b3b4c56690de9fe7492e66cf2bd57c97a75e4c889e4e38d2c3cc35c72724f309b69470cb"
            "7e7f614791f74138957a62f2723717bc7ef2aae166b216fc130d8c1e791db29db38e7851"
            "fd0f6b1f10c015681e4f092d444661178c3c2a19", 16)
    E = 0x10001
    # Not a multiple of sixteen, so the rounding up is in what is covered.
    LENGTH = 0x3F5

    @classmethod
    def setUpClass(cls):
        cls.modulus = cls.P * cls.Q
        cls.private = pow(cls.E, -1, (cls.P - 1) * (cls.Q - 1))
        cls.key = cls.key_for(cls.modulus)
        made = random.Random(0x1B1)
        stage = bytearray(made.randbytes(0x500))
        stage[0:2] = b"CB"
        stage[0x0C:0x10] = cls.LENGTH.to_bytes(4, "big")
        cls.stage = cls.sign(stage)

    @classmethod
    def key_for(cls, modulus: int) -> bytes:
        """The key file's layout: quad count, exponent, eight reserved, the modulus a
        quad at a time with the least significant quad first."""
        wide = modulus.to_bytes(0x100, "big")
        return (bytes.fromhex("00000020") + cls.E.to_bytes(4, "big") + bytes(8)
                + b"".join(wide[at:at + 8] for at in range(0xF8, -8, -8)))

    @classmethod
    def sign(cls, stage: bytearray) -> bytes:
        salt = b"XBOX_ROM_B"
        covered = stage[0x140:(cls.LENGTH + 15) & ~15]
        hashed = hashlib.sha1(bytes(8) + signature._rotsum_sha(stage[:0x10], covered)
                              + salt).digest()
        block = bytearray(0x100)
        block[0xE0] = 1
        block[0xE1:0xEB] = salt
        block[0xEB:0xFF] = hashed
        block[0xFF] = 0xBC
        block[:0xEB] = rc4.rc4(hashed, bytes(block[:0xEB]))
        block[0] &= 0x7F
        scaled = int.from_bytes(block, "big") * pow(2, 2048 * (cls.E - 1), cls.modulus)
        signed = pow(scaled % cls.modulus, cls.private, cls.modulus)
        wide = signed.to_bytes(0x100, "big")
        stage[0x40:0x140] = b"".join(wide[at:at + 8] for at in range(0xF8, -8, -8))
        return bytes(stage)

    def flipped(self, at: int) -> bytes:
        stage = bytearray(self.stage)
        stage[at] ^= 1
        return bytes(stage)

    def test_it_verifies(self):
        self.assertTrue(signature.verify_stage(self.stage, self.key))

    def test_a_byte_changed_where_it_is_covered_fails(self):
        """The header's first sixteen, the signature, and the body to the length
        rounded up to sixteen -- 0x3FA is past the length but inside the rounding."""
        for at in (0x00, 0x0B, 0x0F, 0x40, 0x80, 0x13F, 0x140, 0x3F4, 0x3FA, 0x3FF):
            with self.subTest(at=hex(at)):
                self.assertFalse(signature.verify_stage(self.flipped(at), self.key))

    def test_a_byte_changed_where_it_is_not_covered_passes(self):
        """0x10 to 0x40 is the nonce and what follows it, and nothing past the
        rounded length is read."""
        for at in (0x10, 0x20, 0x3F, 0x400, 0x4FF):
            with self.subTest(at=hex(at)):
                self.assertTrue(signature.verify_stage(self.flipped(at), self.key))

    def test_another_modulus_fails(self):
        self.assertFalse(signature.verify_stage(
            self.stage, self.key_for(self.P * (self.Q + 2))))

    def test_a_modulus_written_most_significant_quad_first_fails(self):
        wide = self.modulus.to_bytes(0x100, "big")
        self.assertFalse(signature.verify_stage(self.stage, self.key[:0x10] + wide))


class TheRotatingSumHash(unittest.TestCase):

    def test_over_nothing_it_is_the_state_twice_and_turned_over_twice(self):
        self.assertEqual(signature._rotsum_sha(b"", b""),
                         hashlib.sha1(bytes(64) + b"\xff" * 64).digest())

    def test_known_answers(self):
        """Pinned from this implementation, which the release's sixty stages verify
        through. The last has three bytes over a quad: they are hashed, not summed."""
        head, body = bytes(range(16)), bytes(range(256)) * 4
        for first, second, wanted in (
                (head, body, "259a713f2db1ea529d770ede5723814125baed49"),
                (head, body + b"\x01\x02\x03",
                 "279c87f519f1d933af5cd5b58a27005df893ff91")):
            with self.subTest(wanted=wanted):
                self.assertEqual(signature._rotsum_sha(first, second).hex(), wanted)


if __name__ == "__main__":
    unittest.main()
