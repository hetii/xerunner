"""The five security files: which are handed in open, which sealed, and what opens.

Every rule here was read out of the original's code and held against images it built
from files made for the purpose; the addresses are in `build.security`. Made-up records
stand in for real ones: what matters is the shape -- a header whose hash at 0x0C vouches
for everything from 0x150 on -- not any console's content.
"""

from __future__ import annotations

import hashlib
import unittest

from xebuild.build import security
from xebuild.crypto import formats
from xebuild.crypto.keys import hmacsha
from xebuild.crypto.rc4 import rc4

KEY = bytes(range(0x10))
OTHER = bytes(range(0x10, 0x20))
WHEN = 0x5A123457


def a_record(magic: bytes, length: int, fill: int) -> bytes:
    """A signed record in the clear: magic, length, a hash vouching for 0x150 on."""
    out = bytearray(length)
    out[0:4] = magic
    out[4:6] = length.to_bytes(2, "big")
    for at in range(0x150, length):
        out[at] = (at * 7 + fill) & 0xFF
    out[0x0C:0x20] = hashlib.sha1(bytes(out[0x150:])).digest()
    return bytes(out)


def a_crl(cpu_key: bytes = KEY, clear: bool = False) -> bytes:
    plain = a_record(b"CRLP", 0xA00, 1)
    if clear:
        return plain
    return security.crl(plain, cpu_key, WHEN, 14, bytes(0x10), bytes(range(3, 0x13)),
                        clear=True)


def a_dae(cpu_key: bytes = KEY, clear: bool = False) -> bytes:
    plain = a_record(b"DAEP", 0x400, 2) + a_record(b"DAEP", 0x300, 3)
    if clear:
        return plain
    return security.dae(plain, cpu_key, WHEN, 14, bytes(7), bytes(0x10))


class TellingOpenFromSealed(unittest.TestCase):
    """`in_the_clear`: the question the original asks of a file beside the build."""

    def test_a_crl_is_open_when_its_hash_vouches_for_it_as_it_stands(self):
        self.assertTrue(security.in_the_clear("crl.bin", a_crl(clear=True), KEY))
        self.assertFalse(security.in_the_clear("crl.bin", a_crl(), KEY))

    def test_an_extended_is_open_with_a_zero_nonce_or_the_one_its_body_derives(self):
        """0x41D6A0: all zero, or HMAC(cpu, body + 07 12); anything else is sealed."""
        body = bytes(range(256)) * 0x3F + bytes(0xF0)
        zero = bytes(0x10) + body
        derived = hmacsha(KEY, body + b"\x07\x12") + body
        sealed = security.extended(derived, body[:8], KEY, clear=True)
        self.assertTrue(security.in_the_clear("extended.bin", zero, KEY))
        self.assertTrue(security.in_the_clear("extended.bin", derived, KEY))
        self.assertFalse(security.in_the_clear("extended.bin", sealed, KEY))
        self.assertFalse(security.in_the_clear("extended.bin", b"\x01" * 0x10 + body,
                                               KEY))

    def test_a_secdata_handed_in_is_never_opened(self):
        """0x41D9B0 has no decryption at all: a sealed copy is read as plaintext."""
        sealed = security.secdata(None, KEY, WHEN, 14)
        self.assertTrue(security.in_the_clear("secdata.bin", sealed, KEY))


class WhatOpens(unittest.TestCase):

    def test_a_crl_opens_under_its_console_s_key_and_not_another_s(self):
        self.assertTrue(security.opens("crl.bin", a_crl(), KEY))
        self.assertFalse(security.opens("crl.bin", a_crl(OTHER), KEY))

    def test_a_dae_opens_record_by_record_and_may_be_mixed(self):
        """0x41E1CA: each record open, or under the console's key or the shipped."""
        sealed, plain = a_dae(), a_dae(clear=True)
        records = formats.records(sealed)
        first = records[0][1]
        mixed = plain[:first] + sealed[first:]
        for blob in (sealed, plain, mixed):
            with self.subTest(len(blob)):
                self.assertTrue(security.opens("dae.bin", blob, KEY))
        self.assertFalse(security.opens("dae.bin", a_dae(OTHER), KEY))

    def test_a_dae_sealed_from_open_records_seals_the_same_as_from_sealed_ones(self):
        """Whatever state it came in, what goes into the image is the same."""
        mixed = a_dae(clear=True)[:0x400] + a_dae()[0x400:]
        self.assertEqual(security.dae(mixed, KEY, WHEN, 14, bytes(7), bytes(0x10)),
                         a_dae())

    def test_an_open_crl_seals_the_same_as_a_sealed_one(self):
        iv, key = bytes(0x10), bytes(range(3, 0x13))
        self.assertEqual(
            security.crl(a_crl(clear=True), KEY, WHEN, 14, iv, key, clear=True),
            security.crl(a_crl(), KEY, WHEN, 14, iv, key),
        )


class TheKeyvaultStyleTwo(unittest.TestCase):

    def test_a_secdata_read_open_keeps_its_body_and_takes_the_build_s_fields(self):
        body = bytes(range(256)) * 3 + bytes(0xF0)
        handed = b"\x55" * 0x10 + body
        sealed = security.secdata(handed, KEY, WHEN, 9, b"HEADHEAD", clear=True)
        plain = rc4(hmacsha(KEY, sealed[:0x10]), sealed[0x10:])
        self.assertEqual(plain[:8], b"HEADHEAD")
        self.assertEqual(plain[8:10], b"\x01\x09")
        # WHEN is odd, and the stamp keeps even seconds.
        self.assertEqual(security.when_in(plain[0x10:]), WHEN - 1)
        self.assertEqual(plain[0x18:], body[0x18:])

    def test_an_extended_that_does_not_verify_is_not_opened(self):
        sealed = security.extended(None, b"HEADHEAD", OTHER)
        self.assertFalse(security.opens("extended.bin", sealed, KEY))
        self.assertTrue(security.opens("extended.bin", sealed, OTHER))


class TheStamp(unittest.TestCase):

    def test_two_seconds_on_and_down_to_an_even_second(self):
        """Measured on a frozen original: 0x5A123456 and 0x5A123457 both stamp the
        FILETIME of 0x5A123458."""
        for when in (0x5A123456, 0x5A123457):
            with self.subTest(when=hex(when)):
                self.assertEqual(security.stamp(when), security.stamp(0x5A123456))
                self.assertEqual(security.when_in(security.stamp(when)), 0x5A123456)


class AFileHandedInBesideTheBuild(unittest.TestCase):
    """`taken_beside`: made up clean, written as it stands, or sealed again."""

    def test_the_wrong_length_is_made_up_clean(self):
        """0x41D6B4 and 0x41D9BF: "is not the correct size!"."""
        self.assertEqual(security.taken_beside("extended.bin", bytes(0x10), KEY),
                         ("clean", False))
        self.assertEqual(security.taken_beside("secdata.bin", bytes(0x3FF), KEY),
                         ("clean", False))

    def test_an_extended_no_key_opens_is_made_up_clean(self):
        sealed = security.extended(None, b"HEADHEAD", OTHER)
        self.assertEqual(security.taken_beside("extended.bin", sealed, KEY),
                         ("clean", False))

    def test_a_crl_or_dae_no_key_opens_goes_in_as_it_stands(self):
        for name, blob in (("crl.bin", a_crl(OTHER)), ("dae.bin", a_dae(OTHER))):
            with self.subTest(name):
                self.assertEqual(security.taken_beside(name, blob, KEY)[0], "as is")

    def test_the_rest_is_used_and_says_whether_it_came_open(self):
        self.assertEqual(security.taken_beside("crl.bin", a_crl(), KEY), ("use", False))
        self.assertEqual(security.taken_beside("crl.bin", a_crl(clear=True), KEY),
                         ("use", True))
        self.assertEqual(security.taken_beside("secdata.bin", bytes(0x400), KEY),
                         ("use", True))
        self.assertEqual(security.taken_beside("odd.bin", b"anything", KEY),
                         ("use", False))


class TheFcrtFile(unittest.TestCase):
    """`security.fcrt`, as the original's 0x41E620 goes."""

    KEY = bytes(range(16))

    def clear(self, body_at=0x140, length=0x4000):
        blob = bytearray(length)
        blob[0x100:0x110] = bytes(range(0x10, 0x20))
        blob[0x11C:0x120] = body_at.to_bytes(4, "big")
        blob[body_at:] = bytes(one & 0xFF for one in range(length - body_at))
        blob[0x12C:0x140] = hashlib.sha1(bytes(blob[body_at:])).digest()
        return bytes(blob)

    def test_a_clear_one_is_sealed_from_where_its_header_says(self):
        for body_at in (0x140, 0x150):
            with self.subTest(body_at=hex(body_at)):
                given = self.clear(body_at)
                sealed = security.fcrt(given, self.KEY)
                self.assertEqual(sealed[:body_at], given[:body_at])
                self.assertNotEqual(sealed[body_at:], given[body_at:])
                self.assertEqual(formats.decrypt_fcrt(sealed, self.KEY),
                                 given[body_at:])

    def test_a_sealed_one_is_carried(self):
        sealed = security.fcrt(self.clear(), self.KEY)
        self.assertEqual(security.fcrt(sealed, self.KEY), sealed)

    def test_the_wrong_length_or_offset_is_left_as_it_is(self):
        longer = self.clear() + b"\xab" * 5
        self.assertEqual(security.fcrt(longer, self.KEY), longer)
        moved = bytearray(self.clear())
        moved[0x11C:0x120] = (0x4000).to_bytes(4, "big")
        self.assertEqual(security.fcrt(bytes(moved), self.KEY), bytes(moved))


if __name__ == "__main__":
    unittest.main()
