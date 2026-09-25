"""Every bootloader a release names, against the checksum it states.

Needs real material and says which. See `tests/xebuild/e2e/__init__.py`.
"""

import os
import shutil
import tempfile
import unittest

from xebuild.boards import for_name
from xebuild.release import Release
from xebuild.imagetypes import ALL as TYPES, for_name as type_for


class AgainstTheRealRelease(unittest.TestCase):
    """Every bootloader a release names, against the checksum it states for it.

    Needs `XEBUILD_RELEASE_DIR` naming one release directory, with `common/` beside it.
    """

    @classmethod
    def setUpClass(cls):
        where = os.environ.get("XEBUILD_RELEASE_DIR", "")
        if not where or not os.path.isdir(where):
            raise unittest.SkipTest("XEBUILD_RELEASE_DIR does not name a release")
        cls.release = Release(where)

    def test_every_bootloader_it_names_is_the_one_it_vouches_for(self):
        checked = empty = 0
        for kind in TYPES:
            try:
                recipe = self.release.recipe(kind)
            except OSError:
                continue
            for name in ("xenon", "zephyr", "falcon", "jasper", "trinity", "corona"):
                board, _ = for_name(name)
                try:
                    listed = recipe.stages(board)
                except ValueError:
                    continue
                for one in listed:
                    if one.absent:
                        empty += 1
                        continue
                    with self.subTest(type=kind.name, board=name, file=one.plain):
                        self.assertTrue(one.vouches_for(self.release.bootloader(one)))
                    checked += 1
        self.assertTrue(checked, "a release names bootloaders")

    def test_the_container_holds_the_firmware_the_list_asks_for(self):
        recipe = self.release.recipe(type_for("glitch2"))
        container = self.release.container
        held = set(container.held)
        vouched = 0
        for one in recipe.firmware:
            if one.crc is None or "$flash_" + one.plain not in held:
                continue
            with self.subTest(file=one.plain):
                self.assertTrue(one.vouches_for(container.firmware(one.plain)))
            vouched += 1
        self.assertTrue(vouched, "the container holds firmware the list vouches for")

    def test_some_firmware_is_not_in_the_container_at_all(self):
        """Measured: three of them are not, and the readme says where they come from
        instead -- "backed by files automatically extracted from nanddump.bin or found
        in /common folder". So a build is not finished by the container alone."""
        recipe = self.release.recipe(type_for("glitch2"))
        held = set(self.release.container.held)
        outside = [one.plain for one in recipe.firmware
                   if "$flash_" + one.plain not in held]
        self.assertTrue(outside)

    def test_the_cf_and_cg_come_out_of_the_container_and_match_the_list(self):
        """They are in no directory: the release seals them inside its container."""
        recipe = self.release.recipe(type_for("glitch2"))
        board, _ = for_name("trinity")
        for one in recipe.stages(board):
            if one.kind in ("CF", "CG"):
                with self.subTest(file=one.plain):
                    self.assertTrue(one.vouches_for(self.release.bootloader(one)))

    def test_a_patch_set_reads_and_a_retail_image_has_none(self):
        board, _ = for_name("trinity")
        self.assertIsNotNone(self.release.patches(type_for("glitch2"), board))
        self.assertIsNone(self.release.patches(type_for("retail"), board))

    def test_an_option_that_is_a_patch_file(self):
        self.assertTrue(self.release.option("nofcrt").records)

    def test_a_container_damaged_anywhere_is_not_loaded_at_all(self):
        """Measured on the original: a byte changed in a file's data, or in the
        padding behind xboxupd.bin that no file's checksum covers -- "checks failed!
        Container corrupt!", and nothing is taken from it."""
        name = next(one for one in sorted(os.listdir(self.release.where))
                    if one.lower().startswith("su") and "_" in one)
        with open(os.path.join(self.release.where, name), "rb") as handle:
            raw = handle.read()
        container = self.release.container
        held = container.held["xboxupd.bin"]
        padding = container._at(held.first + held.blocks - 1) + held.length % 0x1000
        data = container._at(container.held["$flash_dash.xex"].first)
        for at in (data + 0x100, padding + 4):
            with self.subTest(at=hex(at)):
                work = tempfile.mkdtemp(prefix="xebuild-release-")
                self.addCleanup(shutil.rmtree, work, ignore_errors=True)
                spoiled = bytearray(raw)
                spoiled[at] ^= 1
                with open(os.path.join(work, name), "wb") as handle:
                    handle.write(spoiled)
                self.assertIsNone(Release(work).container)
