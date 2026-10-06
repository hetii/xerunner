"""The bootloader signature check against the release's own stages and the 1BL key.

Skipped unless `XEBUILD_ORIGINAL_DIR` names an unpacked xeBuild; the key is the one a
console hands out in its GTIN answer, which `bootstrap.serving` already carries.
"""

import os
import re
import glob
import shutil
import binascii
import tempfile
import unittest

from xebuild.release import Release
from xebuild.crypto import signature
from .bootstrap.serving import PUBLIC_KEYS
from xebuild.release.recipe import Listed, canonical


class TheReleaseStages(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        where = os.environ.get("XEBUILD_ORIGINAL_DIR", "")
        cls.common = os.path.join(where, "common")
        if not where or not os.path.isdir(cls.common):
            raise unittest.SkipTest("XEBUILD_ORIGINAL_DIR does not name an xeBuild")
        cls.key = PUBLIC_KEYS[0]
        cls.release = os.path.join(where, "17559")
        cls.named = set()
        for ini in glob.glob(os.path.join(where, "*", "*.ini")):
            with open(ini, encoding="latin1") as handle:
                cls.named |= set(re.findall(r"\b(?:cba?|sb)_\w+\.bin\b", handle.read(),
                                            re.IGNORECASE))

    def stage(self, name: str) -> bytes:
        with open(os.path.join(self.common, name), "rb") as handle:
            return handle.read()

    def test_every_stage_a_release_names_verifies(self):
        """The ones the original loads, and says "signature check passed!" of."""
        self.assertTrue(self.named)
        for name in sorted(self.named):
            with self.subTest(name):
                self.assertTrue(signature.verify_stage(self.stage(name), self.key))

    def test_one_byte_changed_in_the_signature_fails(self):
        """The change the original was measured refusing: 0xDC to 0x86 at 0x80 of
        cba_9188.bin, with "loaded cba_9188.bin, but signature check failed!"."""
        stage = bytearray(self.stage("cba_9188.bin"))
        stage[0x80] = 0x86
        self.assertFalse(signature.verify_stage(bytes(stage), self.key))

    def test_a_release_refuses_it_as_the_original_did(self):
        """With the list's checksum put right for it, so that it is the signature and
        not the checksum that turns it away."""
        common = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, common, ignore_errors=True)
        stage = bytearray(self.stage("cba_9188.bin"))
        stage[0x80] = 0x86
        with open(os.path.join(common, "cba_9188.bin"), "wb") as handle:
            handle.write(stage)
        listed = Listed("cba_9188.bin", "%08x" % (
            binascii.crc32(canonical(bytes(stage), "CBA")) & 0xFFFFFFFF))
        with self.assertRaisesRegex(ValueError, "signature check failed"):
            Release(self.release, common, one_bl_pub=self.key).bootloader(listed)
        self.assertEqual(Release(self.release, common).bootloader(listed), stage)

    def test_a_release_takes_a_good_one(self):
        listed = Listed("cba_9188.bin", "5a76752d")
        self.assertEqual(Release(self.release, one_bl_pub=self.key).bootloader(listed),
                         self.stage("cba_9188.bin"))

    def test_a_stage_signed_under_another_key_fails(self):
        self.assertFalse(signature.verify_stage(self.stage("cbb_9188.bin"), self.key))


if __name__ == "__main__":
    unittest.main()
