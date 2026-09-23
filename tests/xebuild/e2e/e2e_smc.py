"""Every SMC image the release ships, against what the original said.

Needs real material and says which. See `tests/xebuild/e2e/__init__.py`.
"""

import os
import unittest

from xebuild.smc import CLEAN, Smc

# What the original printed for each of the nineteen, as `checksum, type, clean`.
MEASURED = {
    "CORONA_CLEAN.bin": (0xBA42AB9F, "Corona v6.2(2.05)", True),
    "CORONA_CR4.bin": (0xFD7C6B42, "Corona v6.2(2.05)", False),
    "CORONA_SMC+.bin": (0xAC75B875, "Corona v6.2(2.05)", False),
    "FALCON_CLEAN.bin": (0x1D0C613E, "Falcon v3.1(1.06)", True),
    "FALCON_CR4.bin": (0x45EBE68A, "Falcon v3.1(1.06)", False),
    "FALCON_SMC+.bin": (0xDF1FFF40, "Falcon v3.1(1.06)", False),
    "JASPER_CLEAN.bin": (0x5B3AED00, "Jasper v4.1(2.03)", True),
    "JASPER_CR4.bin": (0x496EBD95, "Jasper v4.1(2.03)", False),
    "JASPER_SMC+.bin": (0x2C68E839, "Jasper v4.1(2.03)", False),
    "SMCaud.bin": (0x260EED31, "Jasper v4.1(2.03)", False),
    "SMCfzj.bin": (0xC507F5BA, "Jasper v4.1(2.03)", False),
    "SMCx.bin": (0xC69F53A0, "Xenon v1.2(1.51)", False),
    "TRINITY_CLEAN.bin": (0xF9C96639, "Trinity v5.1(3.01)", True),
    "TRINITY_CR4.bin": (0x716AD3AE, "Trinity v5.1(3.01)", False),
    "TRINITY_SMC+.bin": (0xEB13F7C6, "Trinity v5.1(3.01)", False),
    "WINCHESTER_CLEAN.bin": (0x3A0059DB, "Unknown v7.1(1.03)", True),
    "XENON_CLEAN.bin": (0xB92ED1BA, "Xenon v1.2(1.51)", False),
    "XENON_SMC+.bin": (0x6E4F4675, "Xenon v1.2(1.51)", False),
    "ZEPHYR_CLEAN.bin": (0x9AD5B7EE, "Zephyr v2.1(1.10)", True),
}


# Where the signature is in each image that still has one. Measured the same way, and
# "glitch hack found in SMC binary!" is printed for exactly the ones missing here.
LIMITS = {
    "CORONA_CLEAN.bin": 0x13B4, "FALCON_CLEAN.bin": 0x12A3,
    "JASPER_CLEAN.bin": 0x12BA, "SMCaud.bin": 0x12BA, "SMCfzj.bin": 0x12BA,
    "SMCx.bin": 0x1180, "TRINITY_CLEAN.bin": 0x13B3, "WINCHESTER_CLEAN.bin": 0x137F,
    "XENON_CLEAN.bin": 0x1180, "ZEPHYR_CLEAN.bin": 0x1257,
}


class AgainstEveryImageTheReleaseShips(unittest.TestCase):
    """Skipped unless `XEBUILD_SMC_DIR` names the directory holding them."""

    @classmethod
    def setUpClass(cls):
        where = os.environ.get("XEBUILD_SMC_DIR", "")
        if not where or not os.path.isdir(where):
            raise unittest.SkipTest("XEBUILD_SMC_DIR does not name a directory")
        cls.where = where

    def an_image(self, name):
        path = os.path.join(self.where, name)
        if not os.path.isfile(path):
            self.skipTest("%s is not here" % name)
        with open(path, "rb") as handle:
            return Smc(handle.read())

    def test_each_one_says_what_the_original_said_about_it(self):
        for name, (checksum, named, clean) in MEASURED.items():
            with self.subTest(image=name):
                one = self.an_image(name)
                self.assertEqual(one.checksum, checksum)
                self.assertEqual(one.named, named)
                self.assertEqual(one.clean, clean)

    def test_xenon_s_stock_image_is_not_in_the_original_s_table(self):
        """A gap in its table rather than anything about the image, and worth a test
        of its own: guessing that every CLEAN file is vouched for gets this wrong."""
        self.assertFalse(self.an_image("XENON_CLEAN.bin").clean)
        self.assertTrue(self.an_image("ZEPHYR_CLEAN.bin").clean)

    def test_winchester_s_board_has_no_name_in_the_original(self):
        self.assertEqual(self.an_image("WINCHESTER_CLEAN.bin").named,
                         "Unknown v7.1(1.03)")

    def test_the_reset_limit_is_where_it_was_measured(self):
        for name, at in LIMITS.items():
            with self.subTest(image=name):
                self.assertEqual(self.an_image(name).reset_limit, at)

    def test_the_file_each_board_names_is_the_one_this_table_vouches_for(self):
        """The one place these two packages touch, and nothing else pins it.

        `boards` says which image goes with a board and this says what that image is;
        correct one and forget the other and nothing would complain. **Xenon is the
        exception and is named here on purpose**: its stock image is absent from the
        original's own table, so anyone "fixing" that by adding it would be adding
        something the original does not have.
        """
        from xebuild.boards import ALL
        checked = set()
        for board in ALL:
            if board.section in checked or not board.smc_clean:
                continue
            checked.add(board.section)
            one = self.an_image(board.smc_clean)
            with self.subTest(board=board.section, image=board.smc_clean):
                if board.section == "xenon":
                    self.assertFalse(one.clean)
                else:
                    self.assertTrue(one.clean)
                    self.assertIn(one.checksum, CLEAN)
        self.assertEqual(len(checked), 7, "seven motherboards name a stock image")

    def test_every_glitch_image_has_no_limit_and_every_other_one_has(self):
        """The equivalence, with no exception either way over all nineteen."""
        for name in MEASURED:
            with self.subTest(image=name):
                self.assertEqual(self.an_image(name).glitched, name not in LIMITS)
