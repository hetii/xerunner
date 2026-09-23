"""Where the original put each region, against where `build.layout` says it goes.

Needs images the original built. See `tests/xebuild/e2e/__init__.py`.
"""

import os
import unittest

from xebuild.boards import for_name
from xebuild.build import layout
from xebuild.chain import Chain
from xebuild.image import Directory, Image
from xebuild.imagetypes import for_name as type_for


def references() -> tuple:
    """The images to sweep, as `(path, image type, board)`.

    `XEBUILD_REFS` names a directory of images the original built, each called
    `<type>-<board>.bin` after the `-t` and `-c` it was built with, so a sweep can say
    what every file in it should contain without naming any of them here.
    """
    where = os.environ.get("XEBUILD_REFS", "")
    if not os.path.isdir(where):
        return ()
    found = []
    for name in sorted(os.listdir(where)):
        stem, _, ext = name.rpartition(".")
        if ext != "bin" or "-" not in stem:
            continue
        kind, _, board = stem.partition("-")
        found.append((os.path.join(where, name), kind, board))
    return tuple(found)


class WhereTheOriginalPutEachRegion(unittest.TestCase):
    """Every boundary of every reference image, against the arithmetic.

    Skipped unless `XEBUILD_REFS` names a directory of them. An image of a type
    `layout` refuses is swept too: the refusal has to go on standing rather than
    quietly growing into a guess.
    """

    def setUp(self):
        self.refs = references()
        if not self.refs:
            raise unittest.SkipTest("XEBUILD_REFS does not name a directory of images")

    def _where(self, path, kind, board):
        """What the arithmetic says, from the image's own chain."""
        console = for_name(board)[0]
        with open(path, "rb") as handle:
            image = Image(handle.read(), console.flash)
        last = Chain(image, console).walked[-1]
        where = layout.for_type(type_for(kind), console.flash, last.at + last.length)
        return image, console, where

    def _laid(self) -> tuple:
        """The references of a type `layout` lays out."""
        return tuple(one for one in self.refs if one[1] not in layout.UNMEASURED)

    def test_a_type_with_no_reference_image_is_refused_all_the_same(self):
        """A jtag image is the one that builds, so it is the one that can be swept."""
        refused = [one for one in self.refs if one[1] in layout.UNMEASURED]
        if not refused:
            raise unittest.SkipTest("no image of a refused type among the references")
        for path, kind, board in refused:
            with self.subTest(os.path.basename(path)), \
                    self.assertRaises(ValueError):
                self._where(path, kind, board)

    def test_the_slot_begins_with_the_CF(self):
        """Where the rounding says, on every board and every type laid out here."""
        for path, kind, board in self._laid():
            with self.subTest(os.path.basename(path)):
                image, _, where = self._where(path, kind, board)
                at = where["slot"][0]
                self.assertEqual(image.flat[at:at + 2], b"CF")

    def test_the_CG_fills_the_slot_to_its_end(self):
        """The CF is far shorter than a span, and what follows runs to the patches."""
        for path, kind, board in self._laid():
            with self.subTest(os.path.basename(path)):
                image, _, where = self._where(path, kind, board)
                at, span = where["slot"]
                self.assertNotEqual(image.flat[at + span - 0x10:at + span],
                                    b"\xff" * 0x10)

    def test_the_patch_slot_is_written_for_a_hack_and_erased_for_retail(self):
        """A retail image keeps the region and leaves it alone; one block is written."""
        for path, kind, board in self._laid():
            with self.subTest(os.path.basename(path)):
                image, _, where = self._where(path, kind, board)
                at, span = where["patches"]
                first = image.flat[at:at + layout.BLOCK]
                rest = image.flat[at + layout.BLOCK:at + span]
                self.assertEqual(rest, b"\xff" * len(rest))
                if kind == "retail":
                    self.assertEqual(first, b"\xff" * len(first))
                else:
                    self.assertNotEqual(first, b"\xff" * len(first))

    def test_a_loader_is_there_when_the_type_says_and_not_when_it_does_not(self):
        """XeLL's first word is a branch; a retail image leaves 0x70000 to the slot."""
        for path, kind, board in self._laid():
            with self.subTest(os.path.basename(path)):
                image, _, where = self._where(path, kind, board)
                first = image.flat[layout.XELL_AT:layout.XELL_AT + 4]
                if "xell" in where:
                    self.assertEqual(first[0], 0x48)
                elif where["slot"][0] == layout.XELL_AT:
                    self.assertEqual(first[:2], b"CF")
                else:
                    self.assertEqual(first, b"\xff" * 4)

    def test_the_tail_holds_the_part_of_the_CG_that_did_not_fit(self):
        """Whatever else it is, it is written: neither erased nor left at zero."""
        for path, kind, board in self._laid():
            with self.subTest(os.path.basename(path)):
                image, _, where = self._where(path, kind, board)
                head = image.flat[where["tail"][0]:where["tail"][0] + 0x10]
                self.assertNotEqual(head, b"\xff" * 0x10)
                self.assertNotEqual(head, bytes(0x10))

    def test_the_tail_is_listed_only_where_it_falls_inside_the_filesystem(self):
        """Listed as `sysupdate.xexp1` where it is listed, and at the base where not."""
        for path, kind, board in self._laid():
            with self.subTest(os.path.basename(path)):
                image, console, where = self._where(path, kind, board)
                base = console.flash.base_of(False) * layout.BLOCK
                table = Directory(image.blob("fsroot"), console.flash.blocks)
                named = {one.name: one for one in table.entries}
                if layout.tail_is_a_file(where["tail"][0], base):
                    self.assertIn("sysupdate.xexp1", named)
                    sector = (where["tail"][0] - base) // layout.BLOCK
                    self.assertEqual(named["sysupdate.xexp1"].sector, sector)
                else:
                    self.assertNotIn("sysupdate.xexp1", named)
                    self.assertEqual(where["tail"][0], base)
