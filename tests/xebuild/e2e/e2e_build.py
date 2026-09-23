"""Where the original put each region, against where `build.layout` says it goes.

Needs images the original built. See `tests/xebuild/e2e/__init__.py`.
"""

import os
import shutil
import tempfile
import unittest

from xebuild.boards import for_name
from xebuild.build import Build, Material, layout
from xebuild.chain import Chain
from xebuild.config import BuildConfig
from xebuild.crypto import smc as cipher
from xebuild.image import Directory, Image
from xebuild.imagetypes import for_name as type_for
from xebuild.release import Release


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


class WhatABuildProducesForARealConsole(unittest.TestCase):
    """Region by region, against the same region of an image the original built.

    Needs `XEBUILD_REFS` for the images, `XEBUILD_DUMP` for the console's own flash and
    `XEBUILD_RELEASE_DIR` for the release. The SMC is not among these: the reference
    images were built with a chosen `smc.bin` in the per-build directory, and what the
    original does when there is none was settled by sweeping sixty-three builds.
    """

    def setUp(self):
        self.refs = references()
        dump = os.environ.get("XEBUILD_DUMP", "")
        release = os.environ.get("XEBUILD_RELEASE_DIR", "")
        if not self.refs or not os.path.isfile(dump) or not os.path.isdir(release):
            raise unittest.SkipTest(
                "XEBUILD_REFS, XEBUILD_DUMP and XEBUILD_RELEASE_DIR are needed together"
            )
        self.where = tempfile.mkdtemp(prefix="xebuild-e2e-material-")
        self.addCleanup(shutil.rmtree, self.where, ignore_errors=True)
        os.symlink(dump, os.path.join(self.where, "nanddump.bin"))
        key = os.environ.get("XEBUILD_CPUKEY", "")
        if key:
            with open(os.path.join(self.where, "cpukey.txt"), "w") as handle:
                handle.write(key)
        for name in ("xell-gggggg.bin", "xell-1f.bin", "xell-2f.bin"):
            shipped = os.path.join(os.path.dirname(release), "data", name)
            if os.path.isfile(shipped):
                os.symlink(shipped, os.path.join(self.where, name))
        beside = os.path.dirname(release)
        self.release = Release(release, os.path.join(beside, "common"))

    def _build(self, kind, board):
        config = BuildConfig(image_type=kind, console=board)
        return Build(config, Material(self.where), self.release)

    def _reference(self, path, board):
        console = for_name(board)[0]
        with open(path, "rb") as handle:
            return Image(handle.read(), console.flash), console

    def _laid(self) -> tuple:
        return tuple(one for one in self.refs if one[1] not in layout.UNMEASURED)

    def test_a_dump_is_read_with_its_own_geometry_whatever_is_being_built(self):
        """A 16 MB trinity dump builds a 64 MB image and an eMMC one, as the original
        does, and it is read as what it is: its keyvault comes out the console's."""
        for path, kind, board in self._laid():
            with self.subTest(os.path.basename(path)):
                one = self._build(kind, board)
                self.assertEqual(one.dump.flash.raw_length,
                                 os.path.getsize(os.environ["XEBUILD_DUMP"]))

    def test_the_keyvault_is_the_console_s_own_block(self):
        for path, kind, board in self._laid():
            with self.subTest(os.path.basename(path)):
                image, _ = self._reference(path, board)
                head = image.header
                at, length = head.keyvault_at, head.keyvault_size
                self.assertEqual(self._build(kind, board).keyvault(),
                                 bytes(image.flat[at:at + length]))

    def test_the_loader_is_the_bytes_of_the_glitch_one_where_there_is_one(self):
        for path, kind, board in self._laid():
            with self.subTest(os.path.basename(path)):
                image, _ = self._reference(path, board)
                ours = self._build(kind, board).xell()
                if kind == "retail":
                    self.assertIsNone(ours)
                    continue
                at, span = layout.XELL_AT, layout.XELL_SPAN
                self.assertEqual(ours, bytes(image.flat[at:at + span]))

    def test_the_patch_slot_is_the_release_s_last_set_where_it_is_measured(self):
        """A glitch2m image is refused here as it is in `build`, for the same reason."""
        for path, kind, board in self._laid():
            with self.subTest(os.path.basename(path)):
                image, console = self._reference(path, board)
                last = Chain(image, console).walked[-1]
                where = layout.for_type(type_for(kind), console.flash,
                                        last.at + last.length)
                at, span = where["patches"]
                one = self._build(kind, board)
                if kind == "glitch2m":
                    with self.assertRaises(ValueError):
                        one.patch_slot()
                    continue
                self.assertEqual(one.patch_slot(),
                                 bytes(image.flat[at:at + layout.BLOCK]))
                self.assertEqual(set(image.flat[at + layout.BLOCK:at + span]), {0xFF})

    def test_the_header_page_is_the_page_the_original_wrote(self):
        """Every byte of the first page, on every reference image, built from fields.

        What the assembly would hand over is passed in here from the reference itself --
        where its slots begin, its CE version, where its SMC went -- because those are
        what the chain and the SMC decide, and this is the page's own test.
        """
        for path, kind, board in self._laid():
            with self.subTest(os.path.basename(path)):
                image, _ = self._reference(path, board)
                head = image.header
                self.assertEqual(layout.smc_at(head.smc_size), head.smc_at)
                ours = self._build(kind, board).header(
                    head.size, head.version, head.smc_size
                )
                self.assertEqual(ours, bytes(image.flat[:len(ours)]))
                # Zeros from the page to wherever the SMC begins: 0x1000 on a NAND
                # console and 0x800 on the eMMC one, the page being 0x200 either way.
                self.assertEqual(set(image.flat[len(ours):head.smc_at]), {0})

    def test_the_chain_is_the_chain_the_original_laid(self):
        """Every byte of the bootloader region, on every reference image this dump fits.

        The SMC comes out of the reference itself, opened and handed back as an
        `smc.bin`: CB_B binds itself to the SMC beside it, so a build sealing a
        different one cannot match, and taking it from the image keeps this test
        standing on the image alone. That the seal then reproduces the reference's own
        SMC bytes is the seed rule holding as well.

        Needs `XEBUILD_CPUKEY` too: a chain that binds to a console cannot be sealed
        without the key it binds to, and this refuses rather than inventing one.
        """
        if not os.environ.get("XEBUILD_CPUKEY"):
            raise unittest.SkipTest("XEBUILD_CPUKEY is what a chain binds to")
        for path, kind, board in self._laid():
            with self.subTest(os.path.basename(path)):
                image, console = self._reference(path, board)
                head = image.header
                sealed = bytes(image.flat[head.smc_at:head.smc_at + head.smc_size])
                where = tempfile.mkdtemp(prefix="xebuild-e2e-chain-")
                self.addCleanup(shutil.rmtree, where, ignore_errors=True)
                for name in os.listdir(self.where):
                    os.symlink(os.path.join(self.where, name),
                               os.path.join(where, name))
                with open(os.path.join(where, "smc.bin"), "wb") as handle:
                    handle.write(cipher.opened(sealed))
                one = Build(BuildConfig(image_type=kind, console=board),
                            Material(where), self.release)
                self.assertEqual(one.smc(), sealed)
                ours = one.chain()
                at = layout.CHAIN_AT
                self.assertEqual(ours, bytes(image.flat[at:at + len(ours)]))
                last = Chain(image, console).walked[-1]
                ends = last.at + last.length
                self.assertEqual(len(ours), ends + -ends % 0x10 - at)

    def test_the_version_the_page_states_is_the_release_s_own_ce(self):
        for path, kind, board in self._laid():
            with self.subTest(os.path.basename(path)):
                image, _ = self._reference(path, board)
                self.assertEqual(self._build(kind, board).ce_version,
                                 image.header.version)

    def test_the_update_slot_and_its_tail_are_what_the_original_laid(self):
        """CF and CG, sealed, over the slot and on into the tail, byte for byte.

        Where the tail lands is taken from `layout`, which is itself held against these
        images above, and the CF has to say where that is -- so a wrong block count or a
        wrong block number shows up here as a CF that does not match.
        """
        if not os.environ.get("XEBUILD_CPUKEY"):
            raise unittest.SkipTest("XEBUILD_CPUKEY is what a CF binds to")
        for path, kind, board in self._laid():
            with self.subTest(os.path.basename(path)):
                image, console = self._reference(path, board)
                last = Chain(image, console).walked[-1]
                where = layout.for_type(type_for(kind), console.flash,
                                        last.at + last.length)
                slot, tail = where["slot"][0], where["tail"][0]
                run = self._build(kind, board).slot(tail)
                span = layout.SLOT_SPAN
                self.assertEqual(run[:span], bytes(image.flat[slot:slot + span]))
                spill = len(run) - span
                self.assertEqual(run[span:], bytes(image.flat[tail:tail + spill]))
