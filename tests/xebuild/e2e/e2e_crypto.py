"""The SMC cipher against a console's own sealed bytes.

Needs real material and says which. See `tests/xebuild/e2e/__init__.py`.
"""

import os
import unittest

from xebuild.crypto import formats, smc


def hexed(text: str) -> bytes:
    return bytes.fromhex(text)


class AConsoleSOwnSmc(unittest.TestCase):
    """Skipped unless `XEBUILD_SEALED_SMC` names one, as a dump's own sealed bytes."""

    @classmethod
    def setUpClass(cls):
        where = os.environ.get("XEBUILD_SEALED_SMC", "")
        if not where or not os.path.isfile(where):
            raise unittest.SkipTest("XEBUILD_SEALED_SMC does not name one")
        with open(where, "rb") as handle:
            cls.sealed = handle.read()

    def test_it_opens_to_something_that_looks_like_an_smc(self):
        """Every plaintext SMC the release ships carries these twelve bytes at four."""
        opened = formats.decrypt_smc(self.sealed)
        self.assertEqual(opened[4:16], hexed("01c641bb01c6212d01c601c6"))

    def test_sealing_it_again_under_its_own_seed_gives_the_same_bytes(self):
        opened = formats.decrypt_smc(self.sealed)
        self.assertEqual(formats.encrypt_smc(opened, self.sealed[:4]), self.sealed)

    def test_its_fingerprint_is_taken_over_the_sealed_bytes_and_not_the_open_ones(self):
        """Both give sixteen bytes, so nothing complains if the wrong one is used.

        `XEBUILD_SMC_FINGERPRINT` says what to expect, so a different console can be
        checked without touching this file. Without it, only the difference is asserted,
        which is the part that would go unnoticed.
        """
        over_sealed = smc.fingerprint(self.sealed)
        opened = formats.decrypt_smc(self.sealed)
        self.assertNotEqual(over_sealed, smc.fingerprint(opened))
        wanted = os.environ.get("XEBUILD_SMC_FINGERPRINT", "")
        if wanted:
            self.assertEqual(over_sealed.hex(), wanted.strip().lower())
