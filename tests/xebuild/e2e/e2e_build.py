"""Where the original put each region, against where `build.layout` says it goes.

Needs images the original built. See `tests/xebuild/e2e/__init__.py`.
"""

import os
import json
import random
import shutil
import tempfile
import unittest
import functools

from typing import ClassVar
from xebuild.chain import Chain
from xebuild.crypto import formats
from xebuild.crypto.rc4 import rc4
from xebuild.boards import for_name
from xebuild.release import Release
from ..test_chain import ONE_BL_KEY
from xebuild.chain.stage import Stage
from xebuild.config import BuildConfig
from xebuild.crypto.keys import hmacsha
from xebuild.image import Directory, Image, Keyvault
from xebuild.image.settings import checksum
from xebuild.crypto.formats import decrypt_smc
from xebuild.imagetypes import for_name as type_for
from xebuild.build import Build, Material, layout, security

# Every build and release here is handed the 1BL key, as J-Runner's options.ini
# hands it to the original.
Release = functools.partial(Release, one_bl_key=ONE_BL_KEY)
BuildConfig = functools.partial(BuildConfig, one_bl_key=ONE_BL_KEY)


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


def regions(image, console, kind) -> dict:
    """What `layout` says of a reference image, from the image's own chain.

    A JTAG image's second chain is two stages at a fixed place, and how long they are is
    where its filesystem starts from, so that is read off the image as well.
    """
    last = Chain(image, console).walked[-1]
    where = layout.for_type(type_for(kind), console.flash, last.at + last.length)
    if "second chain" in where:
        at = start = where["second chain"][0]
        for _ in range(2):
            at += Stage(image.flat, at).length
        where = layout.for_type(type_for(kind), console.flash, last.at + last.length,
                                second_chain=at - start)
    return where


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
        return image, console, regions(image, console, kind)

    def _laid(self) -> tuple:
        """The references of a type `layout` lays out."""
        return tuple(one for one in self.refs if one[1] not in layout.UNMEASURED)

    def test_a_type_with_no_reference_image_is_refused_all_the_same(self):
        """None of them builds, so none can be among the references; swept if one is."""
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
                at = where["xell"][0] if "xell" in where else layout.XELL_AT
                first = image.flat[at:at + 4]
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

    def test_the_tail_is_always_the_first_file(self):
        """Listed as `sysupdate.xexp1` at the block it lands in -- 0x34 on a 16 MB image
        and block 0 of the filesystem on a 64 MB one, where it opens it."""
        for path, kind, board in self._laid():
            with self.subTest(os.path.basename(path)):
                image, console, where = self._where(path, kind, board)
                base = console.flash.base_of(False) * layout.BLOCK
                table = Directory(image.blob("fsroot"), console.flash.blocks)
                first = table.entries[0]
                self.assertEqual(first.name, "sysupdate.xexp1")
                block = (where["tail"][0] - base) // layout.BLOCK
                self.assertEqual(first.sector, block)

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
        # Links to the shared material rather than copies of it. Every file a test adds
        # beside them is opened "xb": a name that is already a link then fails the
        # test instead of writing through it into the material every run reads.
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
        config = BuildConfig(image_type=kind, console=board, per_build=self.where)
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
                image, console = self._reference(path, board)
                ours = self._build(kind, board).xell()
                if kind == "retail":
                    self.assertIsNone(ours)
                    continue
                at, span = regions(image, console, kind)["xell"]
                self.assertEqual(ours, bytes(image.flat[at:at + span]))

    def test_the_patch_slot_is_the_release_s_last_set_where_it_is_measured(self):
        """A glitch2m image carries the console's fuses in front of the set, and a JTAG
        image the whole file."""
        for path, kind, board in self._laid():
            with self.subTest(os.path.basename(path)):
                image, console = self._reference(path, board)
                at, span = regions(image, console, kind)["patches"]
                ours = self._build(kind, board).patch_slot()
                self.assertEqual(ours, bytes(image.flat[at:at + len(ours)]))
                if kind != "jtag":
                    self.assertEqual(set(image.flat[at + layout.BLOCK:at + span]),
                                     {0xFF})

    def test_the_header_page_is_the_page_the_original_wrote(self):
        """Every byte of the first page, on every reference image, built from fields.

        What the assembly would hand over is passed in here from the reference itself --
        where its slots begin, its CE version, where its SMC went -- because those are
        what the chain and the SMC decide, and this is the page's own test.
        """
        for path, kind, board in self._laid():
            with self.subTest(os.path.basename(path)):
                image, console = self._reference(path, board)
                head = image.header
                self.assertEqual(layout.smc_at(head.smc_size), head.smc_at)
                # A JTAG image's payload sits in the page after this one.
                payload = regions(image, console, kind).get("payload", (0, 0))[1]
                ours = self._build(kind, board).header(
                    head.size, head.version, head.smc_size
                )
                self.assertEqual(ours, bytes(image.flat[:len(ours)]))
                # Zeros from the page to wherever the SMC begins: 0x1000 on a NAND
                # console and 0x800 on the eMMC one, the page being 0x200 either way.
                self.assertEqual(set(image.flat[len(ours) + payload:head.smc_at]), {0})

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
                with open(os.path.join(where, "smc.bin"), "xb") as handle:
                    handle.write(decrypt_smc(sealed))
                one = Build(BuildConfig(image_type=kind, console=board,
                                        per_build=where),
                            Material(where), self.release)
                self.assertEqual(one.smc(), sealed)
                ours = one.chain()
                at = layout.CHAIN_AT
                self.assertEqual(ours, bytes(image.flat[at:at + len(ours)]))
                last = Chain(image, console).walked[-1]
                ends = last.at + last.length
                self.assertEqual(len(ours), ends + -ends % 0x10 - at)

    def test_the_version_the_page_states_is_1888(self):
        for path, kind, board in self._laid():
            with self.subTest(os.path.basename(path)):
                image, _ = self._reference(path, board)
                self.assertEqual(self._build(kind, board).stated_version,
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
                where = regions(image, console, kind)
                slot, tail = where["slot"][0], where["tail"][0]
                one = self._build(kind, board)
                span = layout.SLOT_SPAN
                # A JTAG image's two pairs, each tail straight behind the one before.
                for which in range(len(one._update_pairs())):
                    run = one.slot(tail, which)
                    at = slot + which * span
                    self.assertEqual(run[:span], bytes(image.flat[at:at + span]))
                    spill = len(run) - span
                    self.assertEqual(run[span:], bytes(image.flat[tail:tail + spill]))
                    tail += spill + -spill % layout.BLOCK

    def _with_smc(self, given) -> str:
        """A copy of the material with `given` as its smc.bin."""
        where = tempfile.mkdtemp(prefix="xebuild-e2e-smc-")
        self.addCleanup(shutil.rmtree, where, ignore_errors=True)
        for name in os.listdir(self.where):
            os.symlink(os.path.join(self.where, name), os.path.join(where, name))
        with open(os.path.join(where, "smc.bin"), "xb") as handle:
            handle.write(given)
        return where

    def _smcs_that_do_not_decrypt(self) -> dict:
        """Five ways an smc.bin fails the original's test, the console's own SMC the
        ground for two of them."""
        with open(os.environ["XEBUILD_DUMP"], "rb") as handle:
            dump = Image(handle.read(), for_name("trinity")[0].flash)
        head = dump.header
        sealed = bytes(dump.flat[head.smc_at:head.smc_at + head.smc_size])
        plain = decrypt_smc(sealed)
        noise = random.Random(20260926).randbytes(0x3000)
        return {
            "0xFF": b"\xff" * 0x3000,
            "random bytes": noise,
            "sealed, last byte changed": sealed[:-1] + bytes([sealed[-1] ^ 1]),
            "in the clear, last byte not zero": plain[:-1] + b"\x01",
            "random bytes with a page of 0xFF": noise[:0x1000] + b"\xff" * 0x200
                                                + noise[0x1200:],
        }

    def test_an_smc_that_does_not_decrypt_goes_in_as_it_was_handed_in(self):
        """Under `smcnocheck`, as the original does: no patch and no sealing again.

        Measured on the original with each of these on glitch2, glitch, retail and
        JTAG: the same bytes where the smc sits, and a spare on every page of them,
        a page of 0xFF included.
        """
        for label, given in self._smcs_that_do_not_decrypt().items():
            where = self._with_smc(given)
            for kind, board in (("glitch2", "trinity"), ("jtag", "falcon"),
                                ("retail", "trinity")):
                with self.subTest(smc=label, kind=kind):
                    refused = Build(BuildConfig(image_type=kind, console=board,
                                                per_build=where),
                                    Material(where), self.release)
                    with self.assertRaisesRegex(ValueError, "decryptable"):
                        refused.image()
                    config = BuildConfig(image_type=kind, console=board,
                                         smcnocheck=True, per_build=where)
                    image = Build(config, Material(where), self.release).image()
                    head = image.header
                    self.assertEqual(
                        bytes(image.flat[head.smc_at:head.smc_at + head.smc_size]),
                        given)
                    erased = b"\xff" * len(image.spares[0])
                    for page in range(head.smc_at // 0x200,
                                      (head.smc_at + head.smc_size) // 0x200):
                        self.assertNotEqual(image.spares[page], erased, hex(page))

    def _spoilt(self, changes: dict, files: dict | None = None) -> str:
        """A copy of the material whose dump has `changes` -- flat offset to bytes --
        written in with their codes put right, and `files` beside it."""
        with open(os.environ["XEBUILD_DUMP"], "rb") as handle:
            raw = bytearray(handle.read())
        flash = for_name("trinity")[0].flash
        for at, body in changes.items():
            for page in range(at // 0x200, (at + len(body)) // 0x200):
                data = body[page * 0x200 - at:(page + 1) * 0x200 - at]
                spare = bytes(raw[page * 0x210 + 0x200:(page + 1) * 0x210])
                raw[page * 0x210:(page + 1) * 0x210] = (
                    data + flash.spare.with_ecc(data, spare))
        where = tempfile.mkdtemp(prefix="xebuild-e2e-spoilt-")
        self.addCleanup(shutil.rmtree, where, ignore_errors=True)
        for name in os.listdir(self.where):
            if name != "nanddump.bin":
                os.symlink(os.path.join(self.where, name), os.path.join(where, name))
        with open(os.path.join(where, "nanddump.bin"), "xb") as handle:
            handle.write(raw)
        for name, body in (files or {}).items():
            with open(os.path.join(where, name), "xb") as handle:
                handle.write(body)
        return where

    def _own(self, at: int, length: int) -> bytes:
        """The dump's own flat bytes."""
        with open(os.environ["XEBUILD_DUMP"], "rb") as handle:
            dump = Image(handle.read(), for_name("trinity")[0].flash)
        return bytes(dump.flat[at:at + length])

    def test_a_dump_whose_smc_does_not_decrypt_is_refused_even_when_waived(self):
        """No smc.bin, and the dump's own SMC fails the test: the original discards it
        as the dump is read and then has none, which `smcnocheck` does not waive --
        measured on these three, on glitch2, retail and JTAG."""
        own = self._own(0x1000, 0x3000)
        for label, body in (
                ("random bytes", random.Random(20260926).randbytes(0x3000)),
                ("0xFF", b"\xff" * 0x3000),
                ("sealed, last byte changed", own[:-1] + bytes([own[-1] ^ 1]))):
            where = self._spoilt({0x1000: body})
            for kind, board in (("glitch2", "trinity"), ("jtag", "falcon"),
                                ("retail", "trinity")):
                for waived in (False, True):
                    with self.subTest(smc=label, kind=kind, smcnocheck=waived):
                        config = BuildConfig(image_type=kind, console=board,
                                             smcnocheck=waived, per_build=where)
                        one = Build(config, Material(where), self.release)
                        with self.assertRaisesRegex(ValueError, "does not decrypt"):
                            one.image()

    def test_a_discarded_smc_leaves_the_seal_to_the_compiled_in_seed(self):
        """The dump's SMC spoilt and a good smc.bin given: sealed as with no dump at
        all, the compiled-in 8E0375CC, whatever the spoilt bytes were -- measured."""
        plain = decrypt_smc(self._own(0x1000, 0x3000))
        for label, body in (("random bytes", random.Random(1).randbytes(0x3000)),
                            ("0xFF", b"\xff" * 0x3000)):
            with self.subTest(label):
                where = self._spoilt({0x1000: body}, {"smc.bin": plain})
                config = BuildConfig(image_type="glitch2", console="trinity",
                                     per_build=where)
                image = Build(config, Material(where), self.release).image()
                sealed = bytes(image.flat[0x1000:0x4000])
                self.assertEqual(decrypt_smc(sealed)[:4], bytes.fromhex("8e0375cc"))

    def test_a_header_stating_the_smc_elsewhere_is_read_at_0x1000(self):
        """ "smc.bin should not be at 0x2000, trying 0x1000", measured with 0x2000 and
        0: the SMC is found all the same and carried as the console holds it."""
        page = bytearray(self._own(0, 0x200))
        for stated in (0x2000, 0):
            with self.subTest(hex(stated)):
                page[0x7C:0x80] = stated.to_bytes(4, "big")
                where = self._spoilt({0: bytes(page)})
                config = BuildConfig(image_type="glitch2", console="trinity",
                                     per_build=where)
                one = Build(config, Material(where), self.release)
                image = one.image()
                self.assertEqual(bytes(image.flat[0x1000:0x4000]),
                                 self._own(0x1000, 0x3000))
                # And the report says where it was read, not what the header states.
                with self.assertLogs("xebuild", "INFO") as said:
                    one.dump.survey()
                self.assertIn("smc at 0x1000 ", "\n".join(said.output))

    def test_an_smc_bin_longer_than_0x3800_is_refused(self):
        """ "SMC size 0x3900 not supported!!!", smcnocheck or not."""
        where = self._with_smc(random.Random(2).randbytes(0x3900))
        config = BuildConfig(image_type="glitch2", console="trinity", smcnocheck=True,
                             per_build=where)
        with self.assertRaisesRegex(ValueError, "not supported"):
            Build(config, Material(where), self.release).image()

    def test_the_dump_s_settings_block_is_searched_for_upward(self):
        """A spoilt block at the shape's place and a sound copy 0x200 or 0x400 above
        it: the copy is used, and only its 0x400 go in with 0xFF after -- measured.
        With no sound one the build stops, `smcnocheck` or not."""
        block = self._own(0xF7C000, 0x400)
        spoilt = bytearray(block)
        spoilt[0x10B] ^= 1
        for above in (0x200, 0x400):
            with self.subTest(above=hex(above)):
                where = self._spoilt({0xF7C000: bytes(spoilt), 0xF7C000 + above: block})
                config = BuildConfig(image_type="glitch2", console="trinity",
                                     per_build=where)
                image = Build(config, Material(where), self.release).image()
                self.assertEqual(bytes(image.flat[0xF7C000:0xF7C400]), block)
                self.assertEqual(bytes(image.flat[0xF7C400:0xF7D000]),
                                 b"\xff" * 0xC00)
        for label, body in (("spoilt", bytes(spoilt)), ("erased", b"\xff" * 0x400)):
            for waived in (False, True):
                with self.subTest(label, smcnocheck=waived):
                    where = self._spoilt({0xF7C000: body})
                    config = BuildConfig(image_type="glitch2", console="trinity",
                                         smcnocheck=waived, per_build=where)
                    with self.assertRaisesRegex(ValueError, "no settings block"):
                        Build(config, Material(where), self.release).image()

    def test_config_bin_stands_in_for_smc_config_bin(self):
        """Measured: with no smc_config.bin a config.bin is used, before the dump."""
        block = bytearray(self._own(0xF7C000, 0x400))
        block[0x220:0x226] = bytes.fromhex("0022481234ab")
        block[0:2] = checksum(block).to_bytes(2, "little")
        where = self._spoilt({}, {"config.bin": bytes(block)})
        config = BuildConfig(image_type="glitch2", console="trinity", per_build=where)
        image = Build(config, Material(where), self.release).image()
        self.assertEqual(bytes(image.flat[0xF7C220:0xF7C226]),
                         bytes.fromhex("0022481234ab"))

    def _plain_keyvault(self, serial: str) -> bytes:
        """The console's own keyvault in the clear, its serial replaced so an image
        says which file it was built from."""
        cpu = bytes.fromhex(os.environ["XEBUILD_CPUKEY"])
        plain = bytearray(Keyvault.opened(self._own(0x4000, 0x4000), cpu).plain)
        plain[0xB0:0xBC] = serial.encode()
        return bytes(plain)

    def _serial_built(self, files: dict) -> str:
        where = self._spoilt({}, files)
        config = BuildConfig(image_type="glitch2", console="trinity", per_build=where)
        image = Build(config, Material(where), self.release).image()
        cpu = bytes.fromhex(os.environ["XEBUILD_CPUKEY"])
        vault = Keyvault.opened_if_own(bytes(image.flat[0x4000:0x8000]), cpu)
        return vault.serial

    def test_a_keyvault_is_taken_from_kv_bin_then_keyvault_bin_then_kv_dec_bin(self):
        """Measured with each alone and with two together."""
        if not os.environ.get("XEBUILD_CPUKEY"):
            raise unittest.SkipTest("XEBUILD_CPUKEY is what a keyvault is sealed for")
        kv, named, dec = (self._plain_keyvault(one) for one in
                          ("111111111111", "222222222222", "333333333333"))
        for files, serial in (({"keyvault.bin": named}, "222222222222"),
                              ({"KV_dec.bin": dec}, "333333333333"),
                              ({"keyvault.bin": named, "KV_dec.bin": dec},
                               "222222222222"),
                              ({"kv.bin": kv, "keyvault.bin": named}, "111111111111"),
                              ({"kv.bin": kv[0x10:]}, "111111111111")):
            lengths = [hex(len(body)) for body in files.values()]
            with self.subTest(sorted(files), lengths=lengths):
                self.assertEqual(self._serial_built(files), serial)

    def test_a_kv_bin_of_any_other_length_is_refused(self):
        """The original writes such a file unsealed; see `Keyvault.handed_in`."""
        if not os.environ.get("XEBUILD_CPUKEY"):
            raise unittest.SkipTest("XEBUILD_CPUKEY is what a keyvault is sealed for")
        kv = self._plain_keyvault("444444444444")
        for body in (kv[:0x3F00], kv + bytes(0x100)):
            with self.subTest(hex(len(body))), \
                    self.assertRaisesRegex(ValueError, "not the correct size"):
                self._serial_built({"kv.bin": body})

    def test_a_header_stating_the_keyvault_at_0_is_read_at_0x4000(self):
        """ "KeyVault cannot be at 0x0, trying 0x4000", measured."""
        page = bytearray(self._own(0, 0x200))
        page[0x6C:0x70] = bytes(4)
        where = self._spoilt({0: bytes(page)})
        config = BuildConfig(image_type="glitch2", console="trinity", per_build=where)
        one = Build(config, Material(where), self.release)
        image = one.image()
        self.assertEqual(bytes(image.flat[0x4000:0x8000]), self._own(0x4000, 0x4000))
        # And the report says where it was read, not what the header states.
        with self.assertLogs("xebuild", "INFO") as said:
            one.dump.survey()
        self.assertIn("keyvault at 0x4000 ", "\n".join(said.output))

    def test_an_empty_file_beside_the_build_is_one_that_is_not_there(self):
        """Measured with crl.bin, dae.bin and extended.bin: the image is the one built
        with no such file at all."""
        config = BuildConfig(image_type="glitch2", console="trinity",
                             per_build=self.where)
        when = 0x5A123457
        without = Build(config, Material(self._spoilt({})), self.release).image(when)
        for name in ("crl.bin", "dae.bin", "extended.bin"):
            with self.subTest(name):
                where = self._spoilt({}, {name: b""})
                image = Build(config, Material(where), self.release).image(when)
                self.assertEqual(image.raw, without.raw)

    def test_a_dae_bin_that_is_no_chain_of_records_goes_in_as_it_is(self):
        """Measured: random bytes, and random bytes 0x10 longer, both as they were
        handed in, as the original leaves a file whose first header is not a
        record's."""
        noise = random.Random(3).randbytes(0xAD40)
        for body in (noise[:0xAD30], noise):
            with self.subTest(hex(len(body))):
                where = self._spoilt({}, {"dae.bin": body})
                config = BuildConfig(image_type="glitch2", console="trinity",
                                     per_build=where)
                image = Build(config, Material(where), self.release).image()
                self.assertEqual(image.read("dae.bin"), body)

    def _release_with(self, files: dict) -> Release:
        """A release like the shared one, built of links in a directory of its own,
        with `files` -- a path under the base directory to bytes -- added to it."""
        shared = os.environ["XEBUILD_RELEASE_DIR"]
        base = tempfile.mkdtemp(prefix="xebuild-e2e-base-")
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        release = os.path.join(base, os.path.basename(shared))
        os.makedirs(os.path.join(release, "bin"))
        for name in os.listdir(shared):
            if name != "bin":
                os.symlink(os.path.join(shared, name), os.path.join(release, name))
        for name in os.listdir(os.path.join(shared, "bin")):
            os.symlink(os.path.join(shared, "bin", name),
                       os.path.join(release, "bin", name))
        os.symlink(os.path.join(os.path.dirname(shared), "common"),
                   os.path.join(base, "common"))
        for path, body in files.items():
            with open(os.path.join(base, path.replace("RELEASE", os.path.basename(
                    shared))), "xb") as handle:
                handle.write(body)
        return Release(release, os.path.join(base, "common"))

    def test_xell_is_looked_for_beside_the_build_then_in_bin_then_in_the_base(self):
        """Measured with a copy marked for each place, and with none: the original
        stops, "could not read xell-gggggg.bin"."""
        name = "xell-gggggg.bin"
        with open(os.path.join(self.where, name), "rb") as handle:
            real = handle.read()

        def marked(tag):
            return real[:0x1000] + tag + real[0x1000 + len(tag):]

        in_bin, in_base = marked(b"FROM-RELEASE-BIN"), marked(b"FROM-BASE-PATH")
        where = self._spoilt({})
        os.remove(os.path.join(where, name))
        config = BuildConfig(image_type="glitch2", console="trinity", per_build=where)
        for files, tag in (({"RELEASE/bin/" + name: in_bin}, b"FROM-RELEASE-BIN"),
                           ({name: in_base}, b"FROM-BASE-PATH"),
                           ({"RELEASE/bin/" + name: in_bin, name: in_base},
                            b"FROM-RELEASE-BIN")):
            with self.subTest(sorted(files)):
                image = Build(config, Material(where), self._release_with(files))
                self.assertIn(tag, bytes(image.image().flat[0x70000:0xB0000]))
        with self.assertRaisesRegex(ValueError, "could not read xell-gggggg.bin"):
            Build(config, Material(where), self._release_with({})).image()

    def test_a_glitch_image_over_an_smc_of_zeros_is_refused_unless_waived(self):
        """The one case where refusing a blank SMC is ours: the original builds it."""
        where = self._with_smc(bytes(0x3000))
        refused = Build(BuildConfig(image_type="glitch2", console="trinity",
                                    per_build=where),
                        Material(where), self.release)
        with self.assertRaisesRegex(ValueError, "blank"):
            refused.image()
        config = BuildConfig(image_type="glitch2", console="trinity", smcnocheck=True,
                             per_build=where)
        image = Build(config, Material(where), self.release).image()
        head = image.header
        sealed = bytes(image.flat[head.smc_at:head.smc_at + head.smc_size])
        self.assertEqual(decrypt_smc(sealed)[4:], bytes(0x3000 - 4))

    # The references by type, one test each so that they run side by side; every type
    # among them has to be in one -- `test_no_reference_is_left_out`.
    KINDS: ClassVar[tuple] = (("glitch2",), ("glitch2m",), ("glitch",),
                              ("retail", "jtag"))

    def test_no_reference_is_left_out(self):
        laid = {kind for _path, kind, _board in self._laid()}
        self.assertLessEqual(laid, {kind for group in self.KINDS for kind in group})

    def test_the_whole_file_is_the_original_s_glitch2(self):
        self._whole_files(self.KINDS[0])

    def test_the_whole_file_is_the_original_s_glitch2m(self):
        self._whole_files(self.KINDS[1])

    def test_the_whole_file_is_the_original_s_glitch(self):
        self._whole_files(self.KINDS[2])

    def test_the_whole_file_is_the_original_s_retail_and_jtag(self):
        self._whole_files(self.KINDS[3])

    def _whole_files(self, kinds: tuple):
        """Every byte of the file a programmer writes, spare and codes included.

        The build time comes out of the reference's own crl.bin, whose stamp is the
        clock the original read, and the SMC out of its own flash, since CB_B binds to
        it; everything else is the dump, the release and the arithmetic.
        """
        if not os.environ.get("XEBUILD_CPUKEY"):
            raise unittest.SkipTest("XEBUILD_CPUKEY is what an image is sealed for")
        cpu = bytes.fromhex(os.environ["XEBUILD_CPUKEY"])
        for path, kind, board in self._laid():
            if kind not in kinds:
                continue
            with self.subTest(os.path.basename(path)):
                with open(path, "rb") as handle:
                    raw = handle.read()
                image = Image(raw, for_name(board)[0].flash)
                head = image.header
                where = tempfile.mkdtemp(prefix="xebuild-e2e-whole-")
                self.addCleanup(shutil.rmtree, where, ignore_errors=True)
                for name in os.listdir(self.where):
                    os.symlink(os.path.join(self.where, name),
                               os.path.join(where, name))
                sealed = bytes(image.flat[head.smc_at:head.smc_at + head.smc_size])
                with open(os.path.join(where, "smc.bin"), "xb") as handle:
                    handle.write(decrypt_smc(sealed))
                plain = formats.decrypt_crl(image.read("crl.bin"), cpu)[0]
                one = Build(BuildConfig(image_type=kind, console=board,
                                        per_build=where),
                            Material(where), self.release)
                self.assertEqual(one.image(security.when_in(plain)).raw, raw)


class WhatTheOriginalBuiltFromEachCell(unittest.TestCase):
    """Builds the original made from material staged for one question each.

    `XEBUILD_CELLS` names a directory of cells. A cell holds the per-build `data/` the
    original was given, the `theirs.bin` it built from it, and a `cell.json` saying the
    type, the console and the settings -- `BuildConfig`'s own names. What the cells ask:

    * J-Runner's donor flow: a dead NAND, so no dump, a borrowed `kv.bin`, a shipped
      SMC, the donor `smc_config.bin`, built with `-norandom -o cfldv=14` so that
      nothing is drawn -- across five types and seven consoles.
    * A dump with one block marked bad and one failing its code, plain, with `noremap`
      and with `noecdremap`.
    * A big block dump carrying memory-unit pages, 64 MB and a 256 MB overdump, with
      and without `nandmu`.
    * Every file a console's material may hold, handed in beside a build from a dump:
      a borrowed or sealed kv.bin, a MobileB.dat, smc_config.bin, fcrt.bin, and each
      security file open, sealed, and sealed under another console's key.
    * The settings a build takes from a file before the dump: MobileF.dat, and
      MobileJ.dat under `nomobile`; Statistics.settings and Manufacturing.data whole,
      short and long, and under `nomobile`; and a dump carrying a Manufacturing.data,
      with and without `nomobile`.
    * A `fuses.bin` of 0x60 bytes beside a JTAG and a glitch2m build, and one of 0x20
      that the original passes over.
    * A `.meta` beside each security file handed in, a short one beside crl.bin, one
      beside a firmware file in `common/` on a build with no dump, and one beside a
      loose firmware file of 6717 -- each giving that one file its own time. Where it
      is crl.bin's, the build's clock cannot be read back out of it, so `cell.json`
      states it as `when`.
    * A flash filled so that files and blobs stop fitting; `-i` and `-r` together; a
      release's own payload.bin and freeboot.bin, known and changed; bad blocks on a
      big block dump and on a 16 MB dump built for a big block part.
    * A `blmod.bin` beside a glitch2 build: 0x200 bytes on CB_B, 0x4000 that leave
      XeLL no room, and 0x6000 cut down to what CB_B may hold.
    * Devkit images from 17489 and 1838 on xenon, falcon, jasper and jasperbb, whose
      `[rawpatch]` files no release ships: made up and put in a copy of the release,
      which `cell.json` then names as `release`.

    Every byte of the file is held against the reference; the one thing taken from it
    is the build's clock, out of its crl.bin.
    """

    def setUp(self):
        self.where = os.environ.get("XEBUILD_CELLS", "")
        release = os.environ.get("XEBUILD_RELEASE_DIR", "")
        key = os.environ.get("XEBUILD_CPUKEY", "")
        if not os.path.isdir(self.where) or not os.path.isdir(release) or not key:
            raise unittest.SkipTest(
                "XEBUILD_CELLS, XEBUILD_RELEASE_DIR and XEBUILD_CPUKEY are needed"
            )
        self.cpu = bytes.fromhex(key)
        self.release = Release(release, os.path.join(os.path.dirname(release),
                                                     "common"))

    # The cells by what they ask, one test each so that they run side by side; every
    # cell has to be in one of them -- `test_no_cell_is_left_out`.
    GROUPS: ClassVar[dict] = {
        "bad_blocks": ("badblocks-",),
        "devkit": ("devkit-",),
        "donor": ("donor-",),
        "full_flash": ("fullflash-",),
        "loaders": ("loader-",),
        "security_files": ("material-crl", "material-dae", "material-mixed-dae",
                           "material-own-", "material-ext", "material-plainz-",
                           "material-sec", "material-short-", "material-fcrt"),
        "kv_blobs_and_settings": ("material-kv-", "material-mobile",
                                  "material-smc_config", "material-statistics",
                                  "material-manufacturing", "material-fuses",
                                  "material-meta"),
        "memory_units": ("mu64-", "mu256-"),
        "blmod": ("blmod-",),
        "one_of_a_kind": ("jtag-", "patchname-", "rgh3-"),
    }

    def _cells(self, group: str) -> list:
        return [cell for cell in sorted(os.listdir(self.where))
                if cell.startswith(self.GROUPS[group])]

    def test_no_cell_is_left_out(self):
        grouped = [cell for group in self.GROUPS for cell in self._cells(group)]
        self.assertEqual(sorted(grouped), sorted(os.listdir(self.where)))

    def test_bad_blocks(self):
        self._each_whole_file("bad_blocks")

    def test_devkit(self):
        self._each_whole_file("devkit")

    def test_donor(self):
        self._each_whole_file("donor")

    def test_full_flash(self):
        self._each_whole_file("full_flash")

    def test_loaders(self):
        self._each_whole_file("loaders")

    def test_security_files(self):
        self._each_whole_file("security_files")

    def test_kv_blobs_and_settings(self):
        self._each_whole_file("kv_blobs_and_settings")

    def test_memory_units(self):
        self._each_whole_file("memory_units")

    def test_blmod(self):
        self._each_whole_file("blmod")

    def test_one_of_a_kind(self):
        self._each_whole_file("one_of_a_kind")

    def _each_whole_file(self, group: str):
        """Every byte of each cell's file against what the original built."""
        for cell in self._cells(group):
            here = os.path.join(self.where, cell)
            with self.subTest(cell):
                with open(os.path.join(here, "cell.json")) as handle:
                    told = json.load(handle)
                with open(os.path.join(here, "theirs.bin"), "rb") as handle:
                    raw = handle.read()
                console, bigffs = for_name(told["board"])
                flash, bigffs = type_for(told["type"]).shape(console, bigffs)
                image = Image(raw, flash, bigffs)
                data = os.path.join(here, "data")
                config = BuildConfig(ini=os.path.join(data, "options.ini"),
                                     image_type=told["type"], console=told["board"],
                                     **told["settings"], per_build=data)
                release = self.release
                if "release" in told:
                    release = Release(told["release"], os.path.join(
                        os.path.dirname(told["release"]), "common"))
                one = Build(config, Material(data), release)
                when = told.get("when") or self._clock_of(image)
                self.assertEqual(one.image(when).raw, raw)

    def _clock_of(self, image) -> int:
        """The build's clock, out of its crl.bin -- or its secdata.bin, where the
        crl.bin was one handed in that no key opens and so went in as it stood."""
        try:
            plain = formats.decrypt_crl(image.read("crl.bin"), self.cpu)[0]
        except ValueError:
            sealed = image.read("secdata.bin")
            plain = rc4(hmacsha(self.cpu, sealed[:0x10]), sealed[0x10:])[0x10:]
        return security.when_in(plain)
