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

import hmac
import hashlib
import unittest

from xebuild.build import security
from xebuild.crypto import aes, formats, keys, rc4, smc


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
        self.assertEqual(aes.encrypt_aesecb(aes.aeskey(self.KEY), self.PLAIN),
                         self.CIPHER)

    def test_and_back_again(self):
        self.assertEqual(aes.decrypt_aesecb(aes.aeskey(self.KEY), self.CIPHER),
                         self.PLAIN)

    def test_the_worked_example(self):
        self.assertEqual(
            aes.encrypt_aesecb(aes.aeskey(hexed("2b7e151628aed2a6abf7158809cf4f3c")),
                              hexed("3243f6a8885a308d313198a2e0370734")),
            hexed("3925841d02dc09fbdc118597196a0b32"),
        )

    def test_eleven_round_keys_and_the_first_is_the_key(self):
        rounds = aes.aeskey(self.KEY)
        self.assertEqual(len(rounds), 11)
        self.assertEqual(rounds[0], self.KEY)
        for one in rounds:
            self.assertEqual(len(one), aes.BLOCK)

    def test_only_one_key_width_is_taken(self):
        for wrong in (b"", b"\x00" * 15, b"\x00" * 24, b"\x00" * 32):
            with self.subTest(length=len(wrong)), self.assertRaises(ValueError):
                aes.aeskey(wrong)

    def test_a_block_that_is_not_a_block_is_refused_rather_than_shortened(self):
        rounds = aes.aeskey(self.KEY)
        with self.assertRaises(ValueError):
            aes.encrypt_aesecb(rounds, b"\x00" * 15)


class ChainedBlocks(unittest.TestCase):
    """NIST SP 800-38A, the CBC vectors for a 128-bit key."""

    KEY = hexed("2b7e151628aed2a6abf7158809cf4f3c")
    IV = hexed("000102030405060708090a0b0c0d0e0f")
    PLAIN = hexed("6bc1bee22e409f96e93d7e117393172a"
                  "ae2d8a571e03ac9c9eb76fac45af8e51")
    CIPHER = hexed("7649abac8119b246cee98e9b12e9197d"
                   "5086cb9b507219ee95db113a917678b2")

    def test_the_standard_s_own_answer(self):
        self.assertEqual(aes.encrypt_aescbc(self.KEY, self.PLAIN, self.IV), self.CIPHER)

    def test_and_back_again(self):
        self.assertEqual(aes.decrypt_aescbc(self.KEY, self.CIPHER, self.IV), self.PLAIN)

    def test_each_block_depends_on_the_one_before_it(self):
        """What chaining means: one byte moved changes everything after it."""
        moved = bytearray(self.PLAIN)
        moved[0] ^= 0x01
        out = aes.encrypt_aescbc(self.KEY, bytes(moved), self.IV)
        self.assertNotEqual(out[:16], self.CIPHER[:16])
        self.assertNotEqual(out[16:], self.CIPHER[16:])

    def test_a_trailing_part_block_is_left_as_it_is(self):
        """The images here carry them, and the original leaves them alone too."""
        data = self.PLAIN + b"\xa5\xa5\xa5"
        out = aes.decrypt_aescbc(self.KEY, data, self.IV)
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
            keys.hmacsha(secret, message),
            hmac.new(secret, message, hashlib.sha1).digest()[:16],
        )
        self.assertEqual(len(keys.hmacsha(secret, message)), 16)

    def test_a_key_longer_than_the_hash_block_is_cut_not_hashed(self):
        """Where the console parts company with the standard, from `xecrypt.c`.

        The standard hashes a long key down first; this truncates it. No key in this
        domain is long enough for the two to differ, which is why it is worth pinning.
        """
        long_key = b"a" * 70
        self.assertEqual(
            keys.hmacsha(long_key, b"x"),
            hmac.new(long_key[:64], b"x", hashlib.sha1).digest()[:16],
        )
        self.assertNotEqual(
            keys.hmacsha(long_key, b"x"),
            hmac.new(long_key, b"x", hashlib.sha1).digest()[:16],
        )

    def test_a_different_secret_or_message_gives_a_different_key(self):
        key = keys.hmacsha(b"a" * 16, b"n")
        self.assertNotEqual(key, keys.hmacsha(b"b" * 16, b"n"))
        self.assertNotEqual(key, keys.hmacsha(b"a" * 16, b"m"))


class APartBlock(unittest.TestCase):
    """What XeCrypt's AES library does with data that is not whole blocks: nothing."""

    def test_cbc_leaves_it_as_it_was_both_ways(self):
        key, iv, data = bytes(range(16)), bytes(16), bytes(range(21))
        self.assertEqual(aes.encrypt_aescbc(key, data, iv), data)
        self.assertEqual(aes.decrypt_aescbc(key, data, iv), data)


class WhatXeCryptDoesToAKey(unittest.TestCase):
    """`XeCryptHammingWeight` and `XeCryptUidEccEncode` over the bench console's key."""

    KEY = bytes.fromhex("DF3B246CD38EEBB6C0148DA0552A677D")

    def test_the_weight_counts_every_set_bit(self):
        self.assertEqual(keys.hammingweight(b"\x00\x01\xff"), 9)
        self.assertEqual(keys.hammingweight(b""), 0)

    def test_a_real_key_s_check_bits_are_already_its_own(self):
        self.assertEqual(keys.uideccencode(self.KEY), self.KEY)

    def test_a_key_with_a_bit_changed_comes_back_different(self):
        spoiled = bytearray(self.KEY)
        spoiled[0] ^= 1
        self.assertNotEqual(keys.uideccencode(bytes(spoiled)), bytes(spoiled))


class TheSmcSCipher(unittest.TestCase):
    """The one cipher here with no key from outside, so the vector is the whole proof.

    Measured off an image the original built, from a plaintext of this side's choosing:
    all zeros, which makes the sealed bytes the bare stream. `smcnocheck` is what lets a
    plaintext like that past the three checks that would otherwise stop the build.
    """

    # Plaintext of zeros, seed cc7ac1e7, and what the original wrote.
    MEASURED = hexed(
        "cc7ac1e77cef828b442315440451830470243cfbc34b84b0d4d3347aa4166691"
    )

    def test_it_reproduces_what_the_original_wrote(self):
        made = formats.encrypt_smc(b"\x00" * len(self.MEASURED), self.MEASURED[:4])
        self.assertEqual(made, self.MEASURED)

    def test_the_same_bytes_open_back_to_the_plaintext(self):
        """From byte four. The first four are the seed and mean nothing opened."""
        rest = len(self.MEASURED) - 4
        self.assertEqual(formats.decrypt_smc(self.MEASURED)[4:], b"\x00" * rest)

    def test_the_seed_is_carried_in_the_clear(self):
        made = formats.encrypt_smc(bytes(0x40), hexed("deadbeef"))
        self.assertEqual(made[:4], hexed("deadbeef"))

    def test_the_plaintext_s_first_four_bytes_go_nowhere(self):
        """Measured: a build with a 1 at offset 0 gave the same image as one without."""
        seed = hexed("cc7ac1e7")
        body = bytes(range(0x40))
        one = formats.encrypt_smc(b"\x00" * 4 + body, seed)
        other = formats.encrypt_smc(b"\x01\x02\x03\x04" + body, seed)
        self.assertEqual(one, other)

    def test_a_byte_changes_every_byte_after_it_and_none_before(self):
        """Measured: a 1 at offset 4 moved the byte at 4 by one and everything after."""
        seed = hexed("cc7ac1e7")
        plain = bytearray(0x40)
        was = formats.encrypt_smc(bytes(plain), seed)
        plain[4] = 0x01
        now = formats.encrypt_smc(bytes(plain), seed)
        self.assertEqual(now[:4], was[:4])
        self.assertEqual(now[4], was[4] ^ 0x01)
        self.assertNotEqual(now[5:9], was[5:9])

    def test_two_seeds_give_unrelated_streams(self):
        """Which is why an image resealed under a new seed shares no bytes to speak of.

        Not *no* bytes: two unrelated byte streams agree about one time in 256 by
        chance. What is asserted is that they agree at chance and not at all.
        """
        plain = bytes(0x200)
        one = formats.encrypt_smc(plain, hexed("cc7ac1e7"))[4:]
        other = formats.encrypt_smc(plain, hexed("fbd75a10"))[4:]
        same = sum(a == b for a, b in zip(one, other, strict=True))
        self.assertNotEqual(one, other)
        self.assertLess(same, len(one) // 20)

    def test_a_seed_that_is_not_four_bytes_is_refused(self):
        for seed in (b"", b"\x01\x02\x03", b"\x01\x02\x03\x04\x05"):
            with self.subTest(seed=seed), self.assertRaises(ValueError):
                formats.encrypt_smc(bytes(0x40), seed)

    def test_the_compiled_in_seed_seals_to_what_the_original_writes(self):
        """8E0375CC in the clear is the cc7ac1e7 the original writes under -norandom
        with no console SMC -- measured on a trinity, a falcon JTAG and a corona build
        with three different SMCs, twice over."""
        self.assertEqual(formats.sealed_seed(security.COMPILED_IN["smc.bin"]),
                         hexed("cc7ac1e7"))

    def test_something_shorter_than_its_own_seed_is_refused(self):
        with self.assertRaises(ValueError):
            formats.encrypt_smc(b"\x00\x00", hexed("cc7ac1e7"))


class TheSmcSFingerprint(unittest.TestCase):
    """The digest the bootloaders take of a sealed SMC to say which one they are for.

    Not proved against a console's stored field yet -- that needs the chain. These
    vectors come from a literal transcription of J-Runner's `Nand.CalculateSMCHash`,
    which agrees with this to the byte, and they are here so that a later tidy-up of the
    arithmetic cannot change the answer quietly.
    """

    VECTORS = (
        ("00000001", "0000000020000000ffffffffffffffff"),
        ("000102030405060708090a0b0c0d0e0f", "4db3a444e3a024381978d8379dfdad5d"),
    )

    def test_the_vectors_the_other_two_implementations_give(self):
        for given, wanted in self.VECTORS:
            with self.subTest(given=given):
                self.assertEqual(smc.fingerprint(hexed(given)).hex(), wanted)

    def test_a_longer_one_where_both_accumulators_settle(self):
        """`bytes(range(64))` four times over: every word repeats, so the two
        accumulators end up nearly all one byte, which a rotation bug would disturb."""
        self.assertEqual(smc.fingerprint(bytes(range(64)) * 4).hex(),
                         "a4a4a4a4a4a4a4a47f7f7f7f7f7f7f80")

    def test_nothing_in_gives_nothing_out(self):
        self.assertEqual(smc.fingerprint(bytes(4)), bytes(16))
        self.assertEqual(smc.fingerprint(b""), bytes(16))

    def test_it_is_sixteen_bytes_whatever_goes_in(self):
        for length in (0, 3, 4, 5, 0x3000, 0x3800):
            with self.subTest(length=length):
                self.assertEqual(len(smc.fingerprint(bytes(length))), 16)

    def test_a_trailing_part_word_is_not_read(self):
        """The loop steps four bytes at a time, so three spare bytes change nothing."""
        body = bytes(range(16))
        self.assertEqual(smc.fingerprint(body + b"\x01\x02\x03"),
                         smc.fingerprint(body))

    def test_one_bit_anywhere_changes_it(self):
        body = bytearray(bytes(range(64)) * 4)
        was = smc.fingerprint(bytes(body))
        for at in (0, 1, 0x3F, 0xFF):
            other = bytearray(body)
            other[at] ^= 0x01
            with self.subTest(at=at):
                self.assertNotEqual(smc.fingerprint(bytes(other)), was)


if __name__ == "__main__":
    unittest.main()


class ADaeThatIsNotAChainOfRecords(unittest.TestCase):
    """The original stops at the first header that is not a record's and takes the file
    for one it cannot open; nothing is quietly cut off."""

    def a_record(self, length=0x160):
        return b"DAEP" + length.to_bytes(2, "big") + bytes(length - 6)

    def test_no_record_at_all_does_not_open(self):
        with self.assertRaisesRegex(ValueError, "expected header"):
            formats.decrypt_dae(bytes(range(256)) * 0x40, bytes(16), bytes(16))

    def test_bytes_left_after_the_records_do_not_open(self):
        with self.assertRaisesRegex(ValueError, "expected header"):
            formats.decrypt_dae(self.a_record() + b"junk" * 0x60, bytes(16), bytes(16))

    def test_where_the_records_tile_the_file_the_walk_finds_them_all(self):
        blob = self.a_record() + self.a_record(0x170)
        self.assertEqual(formats.records(blob), [(0, 0x160), (0x160, 0x170)])
