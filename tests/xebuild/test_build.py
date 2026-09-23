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
from xebuild.build import Filesystem, Material
from xebuild.build.filesystem import CHAIN_END, FREE, POOL, RESERVED, TABLE
from xebuild.image import Directory


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

    def test_the_four_things_a_block_says_when_it_holds_no_file(self):
        board, _ = for_name("trinity")
        top = board.flash.last_block
        fs = self.a_filesystem()
        fs.add("one.bin", bytes(0x4000))
        following = fs.following
        self.assertEqual(following[0x00], RESERVED)
        self.assertEqual(following[0x33], RESERVED)
        self.assertEqual(following[0x100], FREE)
        self.assertEqual(following[0x390], TABLE)
        self.assertEqual(following[top], RESERVED)
        self.assertEqual(following[top + 3], RESERVED)
        self.assertEqual(following[board.flash.blocks - 1], POOL)

    def test_the_pool_is_the_blocks_past_the_reserved_ones(self):
        """Thirty two of them on the images measured, and they say nothing at all."""
        board, _ = for_name("trinity")
        following = self.a_filesystem().following
        pool = [b for b, w in following.items() if w == POOL]
        self.assertEqual(len(pool), 32)
        self.assertEqual(min(pool), board.flash.blocks - 32)

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
        out = fs.over(bytes(board.flash.length))
        at = board.flash.offset_of(0x34)
        self.assertEqual(out[at : at + len(body)], body)

    def test_a_file_that_would_not_fit_in_the_image_is_refused(self):
        fs = self.a_filesystem()
        fs.add("one.bin", bytes(0x4000))
        with self.assertRaises(ValueError):
            fs.over(bytes(0x1000))
