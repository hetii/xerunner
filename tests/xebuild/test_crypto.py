"""The ciphers against the known answers in the standards that define them.

A cipher is the one thing in this project that can be proved without a console: FIPS-197
publishes what AES-128 does to a named block under a named key, and NIST SP 800-38A does
the same for chaining. So these are not round trips that would pass just as well with
a consistent mistake in them -- they are the numbers the standard says, and the numbers
the console's own code produces.

The table the cipher substitutes through is computed here rather than typed in, so the
first two tests are about the table itself: get it wrong and every other test still
passes, because the mistake would be consistent in both directions.
"""

import hashlib
import hmac
import unittest

from xebuild.crypto import aes, keys, rc4


def hexed(text: str) -> bytes:
    return bytes.fromhex(text)


class TheSubstitutionTable(unittest.TestCase):
    """Computed from the field, so worth checking against the values FIPS-197 prints."""

    def test_the_values_the_standard_names(self):
        for byte, wanted in ((0x00, 0x63), (0x53, 0xED), (0x01, 0x7C), (0xFF, 0x16)):
            with self.subTest(byte=byte):
                self.assertEqual(aes.SBOX[byte], wanted)

    def test_it_is_a_permutation_and_its_inverse_undoes_it(self):
        self.assertEqual(len(set(aes.SBOX)), 256)
        for byte in range(256):
            self.assertEqual(aes.INVERSE_SBOX[aes.SBOX[byte]], byte)

    def test_the_round_constants_are_powers_of_two_in_the_field(self):
        self.assertEqual(aes.RCON,
                         (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36))


class OneBlockOfAes(unittest.TestCase):
    """FIPS-197 appendix C.1, and the worked example in appendix B."""

    KEY = hexed("000102030405060708090a0b0c0d0e0f")
    PLAIN = hexed("00112233445566778899aabbccddeeff")
    CIPHER = hexed("69c4e0d86a7b0430d8cdb78070b4c55a")

    def test_the_standard_s_own_answer(self):
        self.assertEqual(aes.encrypt_block(aes.expand(self.KEY), self.PLAIN),
                         self.CIPHER)

    def test_and_back_again(self):
        self.assertEqual(aes.decrypt_block(aes.expand(self.KEY), self.CIPHER),
                         self.PLAIN)

    def test_the_worked_example(self):
        self.assertEqual(
            aes.encrypt_block(aes.expand(hexed("2b7e151628aed2a6abf7158809cf4f3c")),
                              hexed("3243f6a8885a308d313198a2e0370734")),
            hexed("3925841d02dc09fbdc118597196a0b32"),
        )

    def test_eleven_round_keys_and_the_first_is_the_key(self):
        rounds = aes.expand(self.KEY)
        self.assertEqual(len(rounds), 11)
        self.assertEqual(rounds[0], self.KEY)
        for one in rounds:
            self.assertEqual(len(one), aes.BLOCK)

    def test_only_one_key_width_is_taken(self):
        for wrong in (b"", b"\x00" * 15, b"\x00" * 24, b"\x00" * 32):
            with self.subTest(length=len(wrong)), self.assertRaises(ValueError):
                aes.expand(wrong)

    def test_a_block_that_is_not_a_block_is_refused_rather_than_shortened(self):
        rounds = aes.expand(self.KEY)
        with self.assertRaises(ValueError):
            aes.encrypt_block(rounds, b"\x00" * 15)


class ChainedBlocks(unittest.TestCase):
    """NIST SP 800-38A, the CBC vectors for a 128-bit key."""

    KEY = hexed("2b7e151628aed2a6abf7158809cf4f3c")
    IV = hexed("000102030405060708090a0b0c0d0e0f")
    PLAIN = hexed("6bc1bee22e409f96e93d7e117393172a"
                  "ae2d8a571e03ac9c9eb76fac45af8e51")
    CIPHER = hexed("7649abac8119b246cee98e9b12e9197d"
                   "5086cb9b507219ee95db113a917678b2")

    def test_the_standard_s_own_answer(self):
        self.assertEqual(aes.cbc_encrypt(self.KEY, self.PLAIN, self.IV), self.CIPHER)

    def test_and_back_again(self):
        self.assertEqual(aes.cbc_decrypt(self.KEY, self.CIPHER, self.IV), self.PLAIN)

    def test_each_block_depends_on_the_one_before_it(self):
        """What chaining means: one byte moved changes everything after it."""
        moved = bytearray(self.PLAIN)
        moved[0] ^= 0x01
        out = aes.cbc_encrypt(self.KEY, bytes(moved), self.IV)
        self.assertNotEqual(out[:16], self.CIPHER[:16])
        self.assertNotEqual(out[16:], self.CIPHER[16:])

    def test_a_trailing_part_block_is_left_as_it_is(self):
        """The images here carry them, and the original leaves them alone too."""
        data = self.PLAIN + b"\xa5\xa5\xa5"
        out = aes.cbc_decrypt(self.KEY, data, self.IV)
        self.assertEqual(out[-3:], b"\xa5\xa5\xa5")
        self.assertEqual(len(out), len(data))


class TheStreamCipher(unittest.TestCase):
    """RC4's published vectors, and the property the bootloaders rely on."""

    def test_the_published_vectors(self):
        for key, plain, wanted in ((b"Key", b"Plaintext", "bbf316e8d940af0ad3"),
                                   (b"Wiki", b"pedia", "1021bf0420"),
                                   (b"Secret", b"Attack at dawn",
                                    "45a01f645fc35b383552544b9bf5")):
            with self.subTest(key=key):
                self.assertEqual(rc4.rc4(key, plain).hex(), wanted)

    def test_it_is_its_own_inverse(self):
        key, body = b"\x11" * 16, bytes(range(256)) * 3
        self.assertEqual(rc4.rc4(key, rc4.rc4(key, body)), body)

    def test_a_different_key_gives_a_different_stream(self):
        body = b"\x00" * 32
        self.assertNotEqual(rc4.rc4(b"\x01" * 16, body), rc4.rc4(b"\x02" * 16, body))

    def test_no_key_is_refused(self):
        with self.assertRaises(ValueError):
            rc4.rc4(b"", b"anything")


class TheOneDerivation(unittest.TestCase):
    def test_it_is_hmac_sha1_cut_to_sixteen_bytes(self):
        secret, message = b"k" * 16, b"n" * 16
        self.assertEqual(
            keys.derive(secret, message),
            hmac.new(secret, message, hashlib.sha1).digest()[:16],
        )
        self.assertEqual(len(keys.derive(secret, message)), 16)

    def test_a_key_longer_than_the_hash_block_is_cut_not_hashed(self):
        """Where the console parts company with the standard, from `xecrypt.c`.

        The standard hashes a long key down first; this truncates it. No key in this
        domain is long enough for the two to differ, which is why it is worth pinning.
        """
        long_key = b"a" * 70
        self.assertEqual(
            keys.derive(long_key, b"x"),
            hmac.new(long_key[:64], b"x", hashlib.sha1).digest()[:16],
        )
        self.assertNotEqual(
            keys.derive(long_key, b"x"),
            hmac.new(long_key, b"x", hashlib.sha1).digest()[:16],
        )

    def test_a_different_secret_or_message_gives_a_different_key(self):
        self.assertNotEqual(keys.derive(b"a" * 16, b"n"), keys.derive(b"b" * 16, b"n"))
        self.assertNotEqual(keys.derive(b"a" * 16, b"n"), keys.derive(b"a" * 16, b"m"))


if __name__ == "__main__":
    unittest.main()
