"""Laying an image, and first the directory a console's own things come from.

A directory is cheap to make up, so all of this runs on one built here rather than on a
real one: written, read back, and checked. Where scratch goes is `tests/__init__.py`'s
business.
"""

import os
import shutil
import tempfile
import unittest

from xebuild.boards import for_name
from xebuild.build import Filesystem, Material, layout
from xebuild.image import Directory, Image
from xebuild.image.directory import CHAIN_END
from xebuild.imagetypes import for_name as type_for


def a_directory(case, files=None):
    """A directory holding what was asked for, removed when the class is done."""
    where = tempfile.mkdtemp(prefix="xebuild-material-")
    case.addCleanup(shutil.rmtree, where, ignore_errors=True)
    for name, body in (files or {}).items():
        mode = "w" if isinstance(body, str) else "wb"
        with open(os.path.join(where, name), mode) as handle:
            handle.write(body)
    return where


class WhatTheDirectorySupplies(unittest.TestCase):

    def test_something_that_is_not_a_directory_is_refused(self):
        with self.assertRaises(ValueError):
            Material(os.path.join(a_directory(self), "nothing"))

    def test_a_file_that_is_not_there_is_nothing_rather_than_an_error(self):
        """All of them are optional; what to do about it is the build's business."""
        one = Material(a_directory(self))
        self.assertIsNone(one.dump)
        self.assertIsNone(one.smc)
        self.assertIsNone(one.smc_config)
        self.assertIsNone(one.keyvault)
        self.assertIsNone(one.fcrt)
        self.assertIsNone(one.ini)
        self.assertEqual(one.mobiles, {})

    def test_the_bytes_come_back_whole(self):
        body = bytes(range(256)) * 8
        one = Material(a_directory(self, {"nanddump.bin": body}))
        self.assertEqual(one.dump, body)

    def test_a_file_is_read_once_and_kept(self):
        """A dump is seventeen megabytes; asking twice must not go to the disk twice."""
        where = a_directory(self, {"nanddump.bin": b"hello"})
        one = Material(where)
        first = one.dump
        os.remove(os.path.join(where, "nanddump.bin"))
        self.assertIs(one.dump, first)

    def test_case_does_not_count(self):
        """The original runs where it does not, and these names are hand-assembled."""
        one = Material(a_directory(self, {"NANDDUMP.BIN": b"x" * 4}))
        self.assertEqual(one.dump, b"x" * 4)

    def test_only_the_settings_blobs_that_are_there(self):
        one = Material(a_directory(self, {"MobileB.dat": b"b" * 8,
                                         "MobileE.dat": b"e" * 8}))
        self.assertEqual(sorted(one.mobiles), ["MobileB.dat", "MobileE.dat"])
        self.assertEqual(one.mobiles["MobileE.dat"], b"e" * 8)

    def test_the_settings_file_is_named_rather_than_read(self):
        """Reading it is `config.BuildConfig`'s, which takes a path."""
        where = a_directory(self, {"options.ini": "[nothing]\n"})
        self.assertEqual(Material(where).ini, os.path.join(where, "options.ini"))

    def test_a_loader_is_asked_for_by_name(self):
        """Three are shipped; which a build uses follows the button it starts on."""
        one = Material(a_directory(self, {"xell-2f.bin": b"L" * 16}))
        self.assertEqual(one.xell("xell-2f.bin"), b"L" * 16)
        self.assertIsNone(one.xell("xell-1f.bin"))


class TheTwoKeys(unittest.TestCase):

    KEY = "DF3B246CD38EEBB6C0148DA0552A677D"

    def test_a_key_reads_out_of_its_file(self):
        one = Material(a_directory(self, {"cpukey.txt": self.KEY + "\n"}))
        self.assertEqual(one.key_in_file("cpukey.txt"), bytes.fromhex(self.KEY))

    def test_whitespace_around_it_is_ignored(self):
        """The files on this bench end in a newline and some have spaces."""
        one = Material(a_directory(self, {"cpukey.txt": "  %s  \n\n" % self.KEY}))
        self.assertEqual(one.key_in_file("cpukey.txt"), bytes.fromhex(self.KEY))

    def test_no_file_is_nothing_rather_than_an_error(self):
        """Because the command line and the ini are the other two sources."""
        self.assertIsNone(Material(a_directory(self)).key_in_file("1blkey.txt"))

    def test_an_empty_file_is_refused(self):
        one = Material(a_directory(self, {"cpukey.txt": "\n"}))
        with self.assertRaises(ValueError):
            one.key_in_file("cpukey.txt")

    def test_something_that_is_not_a_key_is_refused(self):
        """A key read wrong seals an image nobody can open, so it is not shrugged at."""
        for said in ("nonsense", self.KEY[:-1], self.KEY + "00"):
            with self.subTest(said=said):
                one = Material(a_directory(self, {"cpukey.txt": said}))
                with self.assertRaises(ValueError):
                    one.key_in_file("cpukey.txt")


class WhichBlockEachFileGets(unittest.TestCase):
    """Packing, and the four things a block can say when it holds no file.

    Both measured on three images the original built -- a 16 MB glitch, a retail and a
    JTAG -- and the same on all three.
    """

    def a_filesystem(self, first=0x34, table_at=0x390):
        board, _ = for_name("trinity")
        return Filesystem(board.flash, first=first, table_at=table_at)

    def test_files_are_laid_back_to_back_with_no_gap(self):
        """Thirty one files on the image measured, no slack between any two."""
        fs = self.a_filesystem()
        fs.add("one.bin", bytes(0x4000))
        fs.add("two.bin", bytes(0x8001))
        fs.add("three.bin", bytes(0x10))
        self.assertEqual([one.sector for one in fs.entries], [0x34, 0x35, 0x38])
        self.assertEqual(fs.after, 0x39)

    def test_a_file_shorter_than_a_block_still_takes_one(self):
        fs = self.a_filesystem()
        fs.add("small.bin", b"x")
        self.assertEqual(fs.after, 0x35)

    def test_a_file_that_would_run_past_the_last_usable_block_is_refused(self):
        """Cut to fit it would read back short with nothing said about it."""
        fs = self.a_filesystem()
        with self.assertRaises(ValueError):
            fs.add("huge.bin", bytes(0x400 * 0x4000))

    def test_a_chain_points_along_itself_and_then_says_it_ends(self):
        fs = self.a_filesystem()
        fs.add("three.bin", bytes(0x9000))
        following = fs.following
        self.assertEqual(following[0x34], 0x35)
        self.assertEqual(following[0x35], 0x36)
        self.assertEqual(following[0x36], CHAIN_END)

    def test_the_table_it_writes_reads_back_as_what_went_in(self):
        board, _ = for_name("trinity")
        fs = self.a_filesystem()
        fs.add("dash.xex", bytes(0x9000), stamp=0x48EE5ED3)
        fs.add("vk.xex", bytes(0x1000))
        table = Directory(fs.table(), board.flash.blocks)
        self.assertEqual([one.name for one in table.entries], ["dash.xex", "vk.xex"])
        self.assertEqual(table.blocks_of(table.entries[0]), (0x34, 0x35, 0x36))
        self.assertEqual(table.entries[0].stamp, 0x48EE5ED3)

    def test_the_files_land_where_the_table_says(self):
        board, _ = for_name("trinity")
        fs = self.a_filesystem()
        body = bytes(range(256)) * 0x40
        fs.add("one.bin", body)
        image = Image.blank(board.flash)
        fs.over(image)
        at = board.flash.offset_of(0x34)
        self.assertEqual(image.flat[at : at + len(body)], body)

    def test_a_file_that_would_not_fit_in_the_image_is_refused(self):
        """By the image, which is the only thing that knows how long it is."""
        board, _ = for_name("trinity")
        fs = self.a_filesystem()
        fs.add("one.bin", bytes(0x4000))
        with self.assertRaises(ValueError):
            fs.over(Image(bytes(0x1000), board.flash))


class WhereEachRegionGoes(unittest.TestCase):
    """Arithmetic, measured across fifteen images the original built."""

    def test_the_slot_rounds_up_by_at_least_0x10000(self):
        """A 16 MB flash rounds by 0x4000 everywhere else: a retail chain ending at
        0x6CB20 puts its slot at 0x70000 and not at 0x6D000."""
        self.assertEqual(layout.slots_at(0x6CB20, xell=False, round_to=0x4000), 0x70000)

    def test_a_big_block_flash_rounds_by_its_own_step(self):
        at = layout.slots_at(0x6CB20, xell=False, round_to=0x20000)
        self.assertEqual(at, 0x80000)

    def test_with_a_loader_it_follows_that_rather_than_the_chain(self):
        """XeLL sits at 0x70000 and is 0x40000 long on every board measured."""
        self.assertEqual(layout.slots_at(0x6C5C0, xell=True, round_to=0x4000), 0xB0000)
        self.assertEqual(layout.slots_at(0x6C5C0, xell=True, round_to=0x20000), 0xC0000)

    def test_the_tail_lands_past_the_slot_and_the_patch_slot(self):
        self.assertEqual(layout.tail_at(0xB0000, base=0), 0xD0000)
        self.assertEqual(layout.tail_at(0x70000, base=0), 0x90000)

    def test_unless_the_filesystem_starts_higher_than_that(self):
        """Which is what a 64 MB image does: its base is 0x2B80000."""
        self.assertEqual(layout.tail_at(0xC0000, base=0x2B80000), 0x2B80000)

    def test_the_tail_is_a_file_only_where_it_falls_inside_the_filesystem(self):
        """Thirty one files against thirty, on two images of the same build."""
        self.assertTrue(layout.tail_is_a_file(0xD0000, base=0))
        self.assertFalse(layout.tail_is_a_file(0x2B80000, base=0x2B80000))

    def test_every_boundary_of_a_glitch_image_on_a_16_mb_flash(self):
        board, _ = for_name("trinity")
        where = layout.for_type(type_for("glitch2"), board.flash, 0x6C5C0)
        self.assertEqual(where["header"], (0, 0x1000))
        self.assertEqual(where["smc"], (0x1000, 0x3000))
        self.assertEqual(where["keyvault"][0], 0x4000)
        self.assertEqual(where["chain"][0], 0x8000)
        self.assertEqual(where["xell"], (0x70000, 0x40000))
        self.assertEqual(where["slot"], (0xB0000, 0x10000))
        self.assertEqual(where["patches"], (0xC0000, 0x10000))
        self.assertEqual(where["tail"][0], 0xD0000)

    def test_a_retail_image_carries_no_loader_and_a_patch_slot_all_the_same(self):
        """It leaves the patch slot erased rather than doing without the region."""
        board, _ = for_name("trinity")
        where = layout.for_type(type_for("retail"), board.flash, 0x6CB20)
        self.assertNotIn("xell", where)
        self.assertEqual(where["slot"][0], 0x70000)
        self.assertEqual(where["patches"][0], 0x80000)

    def test_the_seven_types_no_image_exists_for_are_refused_by_name(self):
        """Each for its own reason, and each reason is in the message."""
        board, _ = for_name("trinity")
        for name in layout.UNMEASURED:
            with self.subTest(name):
                with self.assertRaises(ValueError) as caught:
                    layout.for_type(type_for(name), board.flash, 0x6C570)
                self.assertIn(name, str(caught.exception))
