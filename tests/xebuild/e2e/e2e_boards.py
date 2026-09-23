"""A flash taken apart and put back, and the board names the original takes.

Needs real material and says which. See `tests/xebuild/e2e/__init__.py`.
"""

import os
import re
import subprocess
import unittest

from xebuild import boards


class TakingAnImageApartAndPuttingItBack(unittest.TestCase):

    def test_the_spare_comes_out_and_goes_back(self):
        board, _ = boards.for_name("trinity")
        layout = board.spare
        pages = 40
        flat = bytes(one % 251 for one in range(pages * 512))
        fields = [layout.write(index // 32) for index in range(pages)]
        raw = board.flash.unflatten(flat, fields)
        self.assertEqual(len(raw), pages * (512 + layout.length))
        self.assertEqual(board.flash.flatten(raw), flat)
        for at in range(0, len(raw), 512 + layout.length):
            self.assertTrue(layout.ecc_ok(raw[at : at + 512 + layout.length]))

    def test_a_spare_of_nothing_is_left_as_it_is(self):
        """A retired block is zeroed on purpose, code included."""
        board, _ = boards.for_name("trinity")
        raw = board.flash.unflatten(b"\xff" * 512, [bytes(16)])
        self.assertEqual(raw[512:], bytes(16))

    def test_an_emmc_image_is_the_same_either_way(self):
        board, _ = boards.for_name("corona4g")
        flat = b"\x5a" * 4096
        self.assertIsNone(board.spare)
        self.assertEqual(board.flash.flatten(flat), flat)
        self.assertEqual(board.flash.unflatten(flat, []), flat)

    def test_a_short_last_page_is_padded_rather_than_dropped(self):
        board, _ = boards.for_name("trinity")
        raw = board.flash.unflatten(b"\x11" * 600, [bytes(board.spare.length)] * 2)
        self.assertEqual(len(raw), 2 * (512 + board.spare.length))

    def test_against_a_console_s_own_dump(self):
        """The only check that says the code is the one the hardware keeps.

        Skipped unless `XEBUILD_DUMP` names a raw 16 MB NAND dump, so nothing here
        depends on material this repository does not carry.
        """
        where = os.environ.get("XEBUILD_DUMP", "")
        if not os.path.isfile(where):
            raise unittest.SkipTest("XEBUILD_DUMP does not name a dump")
        with open(where, "rb") as handle:
            raw = handle.read()
        board, _ = boards.for_name("trinity")
        self.assertEqual(len(raw), board.raw_length)
        step = 512 + board.spare.length
        for at in range(0, len(raw), step):
            self.assertTrue(board.spare.ecc_ok(raw[at : at + step]),
                            "page at %#x does not carry its code" % at)
        flat = board.flash.flatten(raw)
        self.assertEqual(len(flat), board.length)
        fields = [raw[at + 512 : at + step] for at in range(0, len(raw), step)]
        self.assertEqual(board.flash.unflatten(flat, fields), raw)


class AgainstTheBinary(unittest.TestCase):
    """The spellings, checked against the original's own acceptance table.

    The table sits in the binary as a run of names, each followed by the message the
    original logs when that name is given -- "Using jasper big block ctype (perbox
    file)". Reading the names out of it is how this list was built, and this test is
    what keeps the two the same.
    """

    def setUp(self):
        where = os.environ.get("XEBUILD_REFERENCE", "")
        if not os.path.isfile(where):
            raise unittest.SkipTest("XEBUILD_REFERENCE does not name xeBuild.exe")
        self.binary = where

    def test_the_twenty_one_names_are_the_ones_the_original_takes(self):
        found = subprocess.run(
            ["strings", "-a", self.binary], capture_output=True, text=True, check=True
        ).stdout.splitlines()
        table = {
            one.strip()
            for one in found
            if re.fullmatch(
                r"(xenon|zephyr|falcon|jasper|trinity|corona|winchester)[a-z0-9]*",
                one.strip(),
            )
        }
        self.assertEqual(set(boards.names()), table)
