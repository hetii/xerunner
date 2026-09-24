"""What each kind of image reaches for, measured by asking the original.

Every number here came from running it: the file list each of the eleven types tries to
open, the patch file it reads, the words it prints. The two irregularities are the point
of most of these tests -- `devgl16` shares `devgl`'s file list, and `devgl` reads the
manufacturing glitch's patch file -- because a rule fitted to the regular nine would get
both of them wrong.
"""

import unittest

from xebuild import imagetypes
from xebuild.boards import for_name
from xebuild.boards.flash import FlatBigNand


class TheEleven(unittest.TestCase):

    def test_eleven_names_over_nine_numbers(self):
        self.assertEqual(len(imagetypes.ALL), 11)
        self.assertEqual(len({kind.number for kind in imagetypes.ALL}), 9)

    def test_the_three_glitches_share_a_number(self):
        shared = {kind.number for kind in imagetypes.ALL
                  if kind.name in ("glitch", "glitch2", "glitch2m")}
        self.assertEqual(shared, {3})

    def test_every_name_resolves_and_nothing_else_does(self):
        for name in imagetypes.names():
            with self.subTest(name=name):
                self.assertEqual(imagetypes.for_name(name).name, name)
        self.assertEqual(imagetypes.for_name("DevGL16").name, "devgl16")
        with self.assertRaises(ValueError):
            imagetypes.for_name("banana")

    def test_the_order_puts_a_longer_name_before_the_one_it_starts_with(self):
        order = imagetypes.names()
        for longer, shorter in (("glitch2m", "glitch2"), ("glitch2", "glitch"),
                                ("devkit16", "devkit"), ("testkit16", "testkit"),
                                ("devgl16", "devgl")):
            with self.subTest(longer=longer):
                self.assertLess(order.index(longer), order.index(shorter))


class WhichFileListEachReads(unittest.TestCase):

    def test_ten_of_them_are_named_after_themselves(self):
        for name in imagetypes.names():
            if name == "devgl16":
                continue
            with self.subTest(name=name):
                self.assertEqual(imagetypes.for_name(name).file_list(),
                                 "_%s.ini" % name)

    def test_devgl16_reads_devgl_s_own(self):
        """The one irregular name of the eleven, and it cannot be derived."""
        self.assertEqual(imagetypes.for_name("devgl16").file_list(), "_devgl.ini")
        self.assertEqual(imagetypes.for_name("devgl").file_list(), "_devgl.ini")

    def test_the_extension_goes_before_the_suffix(self):
        self.assertEqual(imagetypes.for_name("glitch2").file_list("rgh"),
                         "_glitch2_rgh.ini")


class WhichPatchFileEachReads(unittest.TestCase):

    def test_what_the_original_was_seen_reading(self):
        for name, wanted in (("jtag", "patches_trinity.bin"),
                             ("glitch", "patches_trinity.bin"),
                             ("glitch2", "patches_g2trinity.bin"),
                             ("glitch2m", "patches_g2mtrinity.bin"),
                             ("devgl", "patches_g2mtrinity.bin"),
                             ("devgl16", "patches_g2mtrinity.bin")):
            with self.subTest(name=name):
                kind = imagetypes.for_name(name)
                self.assertEqual(kind.patch_file("trinity"), wanted)

    def test_retail_reads_none(self):
        self.assertIsNone(imagetypes.for_name("retail").patch_file("trinity"))

    def test_a_devkit_image_reads_none(self):
        """Measured on 17489 and 1838 devkit builds, whose logs open no patch file."""
        self.assertIsNone(imagetypes.for_name("devkit").patch_file("falcon"))

    def test_the_three_never_measured_refuse_to_guess(self):
        """No release carries their file lists, so the original never gets that far."""
        for name in ("devkit16", "testkit", "testkit16"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                imagetypes.for_name(name).patch_file("trinity")

    def test_the_extension_goes_on_the_end(self):
        self.assertEqual(imagetypes.for_name("glitch2").patch_file("trinity", "rgh"),
                         "patches_g2trinity_rgh.bin")

    def test_the_board_is_lowered(self):
        self.assertEqual(imagetypes.for_name("jtag").patch_file("TrinityBB"),
                         "patches_trinitybb.bin")


class WhatEachOneIs(unittest.TestCase):

    def test_eight_short_names_serve_eleven_types(self):
        """The 16 variants share theirs with the type they are a variant of."""
        shorts = {kind.name: kind.short for kind in imagetypes.ALL}
        self.assertEqual(len(set(shorts.values())), 8)
        for pair in (("devkit", "devkit16"), ("testkit", "testkit16"),
                     ("devgl", "devgl16")):
            self.assertEqual(shorts[pair[0]], shorts[pair[1]])

    def test_the_name_a_build_makes_up(self):
        self.assertEqual(
            imagetypes.for_name("glitch2").image_name("17559", "TrinityBB"),
            "17559_g2_trinitybb.bin",
        )

    def test_what_it_says_when_it_starts(self):
        printed = {kind.name: kind.text for kind in imagetypes.ALL}
        self.assertEqual(printed["glitch2m"], "building glitch2 mfg image")
        for name in imagetypes.names():
            with self.subTest(name=name):
                self.assertTrue(printed[name].startswith("building "))
                self.assertTrue(printed[name].endswith(" image"))

    def test_which_ones_ask_whether_the_cb_is_split(self):
        asked = {kind.name for kind in imagetypes.ALL if kind.asks_dual_cb}
        self.assertEqual(asked, {"retail", "glitch", "glitch2", "glitch2m",
                                 "devgl", "devgl16"})

    def test_only_the_two_devgl_types_skip_the_smc_checks(self):
        exempt = {kind.name for kind in imagetypes.ALL if not kind.checks_smc}
        self.assertEqual(exempt, {"devgl", "devgl16"})

    def test_only_devkit_and_testkit_force_a_shape(self):
        """64 MB flat on a small block console, measured on falcon, xenon and jasper."""
        falcon = for_name("falcon")[0]
        forced = {kind.name for kind in imagetypes.ALL
                  if kind.shape(falcon)[0] is not falcon.flash}
        self.assertEqual(forced, {"devkit", "testkit"})
        flash, bigffs = imagetypes.for_name("devkit").shape(falcon)
        self.assertIsInstance(flash, FlatBigNand)
        self.assertIs(flash.spare, falcon.flash.spare)
        self.assertFalse(bigffs)

    def test_a_big_block_console_takes_its_own_with_the_larger_filesystem(self):
        """jasperbb's devkit image says "extended size FFS"."""
        jasper = for_name("jasperbb")[0]
        self.assertEqual(imagetypes.for_name("devkit").shape(jasper),
                         (jasper.flash, True))

    def test_the_sixteen_variants_take_the_board_s_own_shape(self):
        """Which is the whole of what the `16` in their names means."""
        falcon = for_name("falcon")[0]
        for name in ("devkit16", "testkit16"):
            with self.subTest(name=name):
                self.assertEqual(imagetypes.for_name(name).shape(falcon),
                                 (falcon.flash, False))


if __name__ == "__main__":
    unittest.main()
