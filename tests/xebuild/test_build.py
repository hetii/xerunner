"""Laying an image, and first the directory a console's own things come from.

A directory is cheap to make up, so all of this runs on one built here rather than on a
real one: written, read back, and checked. Where scratch goes is `tests/__init__.py`'s
business.
"""

import os
import shutil
import struct
import binascii
import tempfile
import unittest

from xebuild.crypto.rc4 import rc4
from xebuild.boards import for_name
from xebuild.release import Patches
from xebuild.boards.flash import PAGE
from xebuild.chain.stage import Stage
from xebuild.config import BuildConfig
from xebuild.crypto.keys import hmacsha
from xebuild.release.recipe import Listed
from xebuild.image.directory import CHAIN_END
from xebuild.chain import Chain, Fields, sealing
from xebuild.imagetypes import for_name as type_for
from .test_chain import a_stage, opened_under_the_1bl_key
from xebuild.crypto.formats import decrypt_smc, encrypt_smc
from xebuild.build import Build, Filesystem, Material, layout, security
from xebuild.image import Directory, Header, Image, Keyvault, dump as dumps


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

    def test_a_file_that_would_reach_the_last_usable_block_is_left_out(self):
        """Never cut to fit; skipped, and a smaller one behind it still goes in, as
        the original does on 17489_RGL's `-i flash` list."""
        fs = self.a_filesystem()
        self.assertIsNone(fs.add("huge.bin", bytes(0x400 * 0x4000)))
        self.assertIsNotNone(fs.add("small.bin", b"x"))
        self.assertEqual([one.name for one in fs.entries], ["small.bin"])

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


class WhatFollowsTheFiles(unittest.TestCase):
    """`Filesystem.on`, `lay_blobs` and `lay_table`: the reserve, the settings blobs
    behind the files, and the table behind them."""

    def test_the_reserve_each_kind_of_part_keeps(self):
        """Four held on a 16 MB part, none on a big block chip, and on an eMMC every
        block from the last usable one to the end, with no pool."""
        for name, pool, held in (("trinity", 32, 4), ("jasperbb", 32, 0),
                                 ("corona4g", 0, 6)):
            with self.subTest(board=name):
                board, _ = for_name(name)
                fs = Filesystem.on(board.flash, 0x34)
                self.assertEqual((fs.first, fs.pool, fs.held), (0x34, pool, held))

    def a_filesystem_with_files(self):
        board, _ = for_name("trinity")
        fs = Filesystem.on(board.flash, 0x34)
        fs.add("one.bin", bytes(0x8000))
        return board.flash, fs, Image.blank(board.flash)

    def test_blobs_go_a_stride_apart_behind_the_files_and_the_table_after(self):
        flash, fs, image = self.a_filesystem_with_files()
        blobs = {"MobileC.dat": b"\x0c" * 0x4000, "MobileB.dat": b"\x0b" * 0x4000}
        placed = fs.lay_blobs(image, blobs)
        self.assertEqual(placed, {0x31: (0x36, 0x4000), 0x32: (0x37, 0x4000)})
        self.assertEqual(image.flat[0x36 * 0x4000:0x37 * 0x4000], blobs["MobileB.dat"])
        self.assertEqual(fs.table_at, 0x38)
        page = 0x37 * 0x4000 // PAGE
        self.assertEqual(flash.spare.kind(image.spares[page]), 0x32)

    def test_with_no_blobs_the_table_goes_where_they_would_have_begun(self):
        _flash, fs, image = self.a_filesystem_with_files()
        self.assertEqual(fs.lay_blobs(image, {}), {})
        self.assertEqual(fs.table_at, 0x36)
        self.assertEqual(fs.skipped, range(0))

    def test_a_blob_that_would_reach_the_table_s_block_is_left_out(self):
        board, _ = for_name("trinity")
        fs = Filesystem.on(board.flash, 0x3DA)
        image = Image.blank(board.flash)
        placed = fs.lay_blobs(image, {"MobileB.dat": bytes(0x4000),
                                      "MobileC.dat": bytes(0x4000)})
        self.assertEqual(list(placed), [0x31])
        self.assertEqual(fs.table_at, 0x3DB)

    def test_the_table_lands_in_its_block_with_its_own_kind(self):
        flash, fs, image = self.a_filesystem_with_files()
        fs.lay_blobs(image, {})
        fs.lay_table(image)
        at = flash.offset_of(fs.table_at)
        table = Directory(bytes(image.flat[at:at + 0x4000]), flash.blocks)
        self.assertEqual([one.name for one in table.entries], ["one.bin"])
        self.assertEqual(flash.spare.kind(image.spares[at // PAGE]), 0x30)


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

    def test_the_smc_ends_where_the_keyvault_begins(self):
        """Fifty-seven put a 0x3000 SMC at 0x1000; five put a 0x3800 one at 0x800."""
        self.assertEqual(layout.smc_at(0x3000), 0x1000)
        self.assertEqual(layout.smc_at(0x3800), 0x800)
        with self.assertRaises(ValueError):
            layout.smc_at(0x4000)

    def test_xell_is_left_out_where_the_chain_would_reach_it(self):
        """17489's chain ends at 0xCE0C0: no XeLL, and its slot at 0xD0000. The test
        is on the chain before its patches grow it."""
        falcon = for_name("falcon")[0].flash
        where = layout.for_type(type_for("glitch2m"), falcon, 0xCE460,
                                plain_end=0xCE0C0)
        self.assertNotIn("xell", where)
        self.assertEqual(where["slot"][0], 0xD0000)
        where = layout.for_type(type_for("glitch2m"), falcon, 0x70690,
                                plain_end=0x6F000)
        self.assertIn("xell", where)

    def test_a_devkit_slot_rounds_by_the_part_s_own_step_alone(self):
        """0xD4000 on the flat shape, 0xE0000 on jasperbb; no XeLL region."""
        devkit = type_for("devkit")
        flat, _ = devkit.shape(for_name("falcon")[0])
        where = layout.for_type(devkit, flat, 0xD2B60)
        self.assertEqual(where["slot"][0], 0xD4000)
        self.assertNotIn("xell", where)
        big, bigffs = devkit.shape(for_name("jasperbb")[0])
        self.assertEqual(layout.for_type(devkit, big, 0xD2B60, bigffs)["slot"][0],
                         0xE0000)

    def test_the_tail_lands_past_the_slot_and_the_patch_slot(self):
        self.assertEqual(layout.tail_at(0xB0000, base=0), 0xD0000)
        self.assertEqual(layout.tail_at(0x70000, base=0), 0x90000)

    def test_unless_the_filesystem_starts_higher_than_that(self):
        """Which is what a 64 MB image does: its base is 0x2B80000."""
        self.assertEqual(layout.tail_at(0xC0000, base=0x2B80000), 0x2B80000)

    def test_every_boundary_of_a_glitch_image_on_a_16_mb_flash(self):
        board, _ = for_name("trinity")
        where = layout.for_type(type_for("glitch2"), board.flash, 0x6C5C0)
        self.assertEqual(where["header"], (0, 0x200))
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


# A plaintext SMC that the reset limit can be found in, short enough to make up here.
# The signature is what `smc.LIMIT` looks for, and where it sits does not matter.
AN_SMC = bytes(0x40) + bytes.fromhex("0501e502b405") + bytes(0x3A)


class AChainOfMadeUpStages:
    """What a dump answers about its chain: the stages for their nonces, and the slot
    the console's own values come from, with its CG right behind it. The walk over them
    is the real one."""

    nonce_walk = Chain.nonce_walk
    positional = Chain.positional

    def __init__(self, tags=("CB", "CB", "CD", "CE")):
        self.walked = tuple(
            Stage(a_stage(tag, 0x40, nonce=bytes([index + 1]) * 0x10), 0)
            for index, tag in enumerate(tags)
        )
        update = (a_stage("CF", 0x400, nonce=b"\xcf" * 0x10)
                  + a_stage("CG", 0x100, nonce=b"\xc9" * 0x10))
        self.slot = Stage(update, 0)


class ADumpThatOnlyAnswersWhatIsAsked:
    """Stands in for a console's dump, which is seventeen megabytes of ECC to make up.

    What the regions ask a dump is a handful of things, and a test that built a whole
    flash to hand them over would spend a second and a half on codes nobody looks at.
    The bytes themselves are held against a real dump in `tests/xebuild/e2e/`.
    """

    def __init__(self, smc=AN_SMC, seed=b"\xfb\xd7\x5a\x10", tags=None):
        self.smc = encrypt_smc(smc, seed)
        self.smc_opens = decrypt_smc(self.smc)[-4:] == bytes(4)
        # Sealed for real, under the key the tests hand a build: a keyvault that does
        # not open under its console's key is discarded, as the original discards one.
        self.sealed_keyvault = Keyvault(bytes(range(0x100)) * 0x40).sealed(
            bytes(range(0x10)))
        self.pairing = b"\x78\x02\x27"
        self.ldv = 14
        self.chain = AChainOfMadeUpStages(tags or ("CB", "CB", "CD", "CE"))

    def keyvault(self, cpu_key):
        return Keyvault.opened(self.sealed_keyvault, cpu_key)


class AReleaseWithOnePatchFile:
    """Stands in for a release: one patch file, and stages made up here.

    `stages` is what a file list names, as `(kind, length)` pairs with a length of None
    for the empty slot a list spells `none`. A real release is read in
    `tests/xebuild/e2e/`; what is checked here is which of them a build reaches for.
    """

    def __init__(self, sets, stages=(("CBA", 0x100), ("CBB", 0x200),
                                     ("CD", 0x180), ("CE", 0x140),
                                     ("CF", 0x400), ("CG", 0x14000))):
        self.raw = sets
        self.asked = []
        self.listed = [
            Listed("none" if length is None else "%s_1.bin" % kind.lower(), "")
            for kind, length in stages
        ]
        self.bodies = {}
        for (kind, length), one in zip(stages, self.listed, strict=True):
            if length is None:
                continue
            tag = "CB" if kind in ("CBA", "CBB") else kind
            self.bodies[one.plain] = a_stage(tag, length, nonce=bytes(0x10))

    def patches(self, image_type, board, ext=""):
        named = board if isinstance(board, str) else board.section
        self.asked.append((image_type.name, named))
        return Patches(self.raw)

    def recipe(self, image_type, ext=""):
        return self

    def stages(self, board, ext=""):
        return tuple(self.listed)

    def bootloader(self, listed):
        return self.bodies[listed.plain]


def a_build(case, kind="glitch2", board="trinity", files=None, dump=True, **settings):
    """A build over a made-up directory, with a dump that answers the two questions."""
    config = BuildConfig(image_type=kind, console=board, **settings)
    one = Build(config, Material(a_directory(case, files)),
                AReleaseWithOnePatchFile(b""))
    if dump:
        one._dump = ADumpThatOnlyAnswersWhatIsAsked()
    return one


class WhichSmcGoesIn(unittest.TestCase):
    """What the original does with an SMC, measured over sixty-three builds."""

    def test_the_console_s_own_is_carried_sealed_and_untouched(self):
        """"reading data/smc.bin failed, using smc.bin from nand dump"."""
        one = a_build(self, patchsmc=False)
        self.assertEqual(one.smc(), one.dump.smc)

    def test_a_file_in_the_per_build_directory_wins_and_is_sealed(self):
        """Under the console's own seed, so the dump is still what says how to seal."""
        plain = AN_SMC
        one = a_build(self, files={"smc.bin": plain}, patchsmc=False)
        self.assertEqual(one.smc(), encrypt_smc(plain, one.dump.smc[:4]))

    def test_patchsmc_lifts_the_reset_limit_and_moves_nothing_else(self):
        one = a_build(self, patchsmc=True)
        was, now = decrypt_smc(one.dump.smc), decrypt_smc(one.smc())
        self.assertEqual(now[0x40:0x42], bytes(2))
        self.assertEqual(
            [at for at in range(4, len(now)) if now[at] != was[at]], [0x40, 0x41]
        )

    def test_patchsmc_is_ignored_for_a_retail_image(self):
        """The ini shipped beside the original says so, and a build of a clean image
        with a limit left in it came out with the limit still there."""
        one = a_build(self, kind="retail", patchsmc=True)
        self.assertEqual(one.smc(), one.dump.smc)

    def test_a_build_with_neither_a_file_nor_a_dump_is_refused(self):
        one = a_build(self, dump=False)
        with self.assertRaises(ValueError):
            one.smc()


class WhichKeyvaultGoesIn(unittest.TestCase):

    def test_the_console_s_own_is_carried_as_it_stands(self):
        one = a_build(self)
        self.assertEqual(one.keyvault(), one.dump.sealed_keyvault)

    def test_a_file_in_the_per_build_directory_wins_under_the_console_s_head(self):
        """Its body is written, in the clear or sealed; its eight bytes at 0x10 are the
        console's own keyvault's."""
        key = bytes(range(0x10))
        given = bytes(range(0x40, 0x80)) * 0x100
        for handed in (given, Keyvault(given).sealed(key)):
            with self.subTest(sealed=handed is not given):
                one = a_build(self, files={"kv.bin": handed})
                one.config.cpu_key = key
                plain = Keyvault.opened(one.keyvault(), key).plain
                self.assertEqual(plain[0x18:], given[0x18:])
                self.assertEqual(plain[0x10:0x18],
                                 one.dump.keyvault(key).plain[0x10:0x18])

    def test_with_no_dump_the_head_is_drawn_or_compiled_in(self):
        key = bytes(range(0x10))
        one = a_build(self, dump=False, files={"kv.bin": bytes(0x4000)})
        one.config.cpu_key = key
        one.config.no_random = True
        self.assertEqual(Keyvault.opened(one.keyvault(), key).plain[0x10:0x18],
                         security.COMPILED_IN["kv.bin"])

    def test_a_build_with_neither_is_refused(self):
        with self.assertRaises(ValueError):
            a_build(self, dump=False).keyvault()


class WhatTheSlotForPatchesHolds(unittest.TestCase):
    """One block: 0xFF, the last set as it stands, then zeros. Byte-exact on six."""

    def sets(self, *groups) -> bytes:
        out = bytearray()
        for group in groups:
            for at, words in group:
                out += struct.pack(">II", at, len(words))
                out += struct.pack(">%dI" % len(words), *words)
            out += b"\xff\xff\xff\xff"
        return bytes(out)

    def test_a_retail_image_leaves_the_region_erased(self):
        one = a_build(self, kind="retail")
        self.assertEqual(one.patch_slot(), b"\xff" * layout.BLOCK)

    def test_the_last_set_lands_after_sixteen_bytes_of_0xff(self):
        raw = self.sets([(0x10, (1,))], [(0x20, (2,))])
        one = a_build(self)
        one.release.raw = raw
        slot = one.patch_slot()
        self.assertEqual(len(slot), layout.BLOCK)
        self.assertEqual(slot[:0x10], b"\xff" * 0x10)
        self.assertEqual(slot[0x10:0x10 + 0x10], Patches(raw).set_raw(1))
        self.assertEqual(set(slot[0x20:]), {0})

    def test_a_glitch_image_on_a_fat_console_reads_the_fat_patch_file(self):
        """The original's own log says patches_fat.bin for zephyr, falcon and jasper."""
        one = a_build(self, kind="glitch", board="falcon")
        one.release.raw = self.sets([(0x10, (1,))])
        one.patch_slot()
        self.assertEqual(one.release.asked, [("glitch", "fat")])

    def test_a_glitch2_image_reads_the_file_named_after_the_console(self):
        one = a_build(self, kind="glitch2", board="falcon")
        one.release.raw = self.sets([(0x10, (1,))])
        one.patch_slot()
        self.assertEqual(one.release.asked, [("glitch2", "falcon")])

    def test_a_manufacturing_chain_puts_the_console_s_fuses_in_front(self):
        """Twelve lines of eight bytes, the set moving to 0x60. Read out of the
        original's code by x360mcp, and all four such reference images agree."""
        raw = self.sets([(0x10, (1,))], [(0x20, (2,))])
        one = WhichStagesTheChainIsMadeOf.a_chain(self, kind="glitch2m")
        one.release.raw = raw
        one.release.bodies["cba_1.bin"] = a_stage("CB", 0x100, flags=0x0801)
        cbb = bytearray(a_stage("CB", 0x400, nonce=bytes(0x10)))
        cbb[0x3B0:0x3B4] = (0x03010001).to_bytes(4, "big")
        one.release.bodies["cbb_1.bin"] = bytes(cbb)
        slot = one.patch_slot()
        key = one.cpu_key
        self.assertEqual(slot[0x00:0x08], bytes.fromhex("C0FFFFFFFFFFFFFF"))
        self.assertEqual(slot[0x08:0x10], bytes.fromhex("0F0F0F0F0F0FF0F0"))
        self.assertEqual(slot[0x10:0x18], bytes.fromhex("F000000000000000"))
        self.assertEqual(slot[0x18:0x38], key[:8] * 2 + key[8:] * 2)
        self.assertEqual(slot[0x38:0x40], bytes.fromhex("FFFFFFFFFFFFFF00"))
        self.assertEqual(slot[0x40:0x60], bytes(0x20))
        self.assertEqual(slot[0x60:0x60 + 0x10], Patches(raw).set_raw(1))

class WhichLoaderGoesIn(unittest.TestCase):

    def test_a_retail_image_carries_none(self):
        self.assertIsNone(a_build(self, kind="retail").xell())

    def test_the_glitch_loader_is_taken_from_the_per_build_directory(self):
        one = a_build(self, files={"xell-gggggg.bin": b"loader" * 100})
        self.assertEqual(one.xell(), b"loader" * 100)


class WhatTheHeaderSays(unittest.TestCase):
    """The first page, built from fields; held against sixteen images in `e2e/`."""

    def a_page(self, kind="glitch2", board="trinity", **settings):
        one = a_build(self, kind=kind, board=board, **settings)
        return Header(bytearray(one.header(0xB0000, 0x760, 0x3000)))

    def test_the_slot_offset_is_stated_twice(self):
        """A page that said one and not the other would disagree with itself."""
        head = self.a_page()
        self.assertEqual(head.size, 0xB0000)
        self.assertEqual(head.cf_at, 0xB0000)

    def test_the_fields_that_do_not_depend_on_anything_else(self):
        head = self.a_page()
        self.assertEqual(head.magic, 0xFF4F)
        self.assertEqual(head.entrypoint, 0x8000)
        self.assertEqual(head.keyvault_at, 0x4000)
        self.assertEqual(head.keyvault_size, 0x4000)
        self.assertEqual(head.patch_slots, 2)
        self.assertEqual(head.keyvault_version, 0x712)
        self.assertEqual(head.smc_config_at, 0)

    def test_where_the_smc_went_follows_from_how_long_it_is(self):
        """It ends where the keyvault begins, so the page cannot state a place that
        disagrees with the length: 0x3000 lands at 0x1000 and 0x3800 at 0x800."""
        one = a_build(self)
        for length, at in ((0x3000, 0x1000), (0x3800, 0x800)):
            head = Header(bytearray(one.header(0xB0000, 0x760, length)))
            self.assertEqual((head.smc_at, head.smc_size), (at, length))

    def test_the_word_at_0x48_tells_a_hack_from_a_retail_image(self):
        self.assertEqual(self.a_page(kind="glitch2").before_flags, 1)
        self.assertEqual(self.a_page(kind="retail").before_flags, 0)

    def test_the_three_boot_flag_words_measured(self):
        self.assertEqual(self.a_page(kind="retail").boot_flags, 0)
        self.assertEqual(self.a_page(kind="glitch").boot_flags, 0x12)
        self.assertEqual(self.a_page(kind="glitch2").boot_flags, 0x12)
        self.assertEqual(self.a_page(kind="jtag", board="falcon").boot_flags, 0x40012)

    def test_the_button_xell_starts_on_and_a_second_one(self):
        self.assertEqual(self.a_page(xellbutton="power").boot_flags, 0x11)
        self.assertEqual(self.a_page(xellbutton2="power").boot_flags, 0x1112)
        self.assertEqual(self.a_page(xellbutton2="eject").boot_flags, 0x12)

    def test_the_older_ways_of_starting_clear_the_reason(self):
        self.assertEqual(self.a_page(nodvd=True).boot_flags, 0)
        self.assertEqual(self.a_page(olddvd=True).boot_flags, 0)

    def test_an_alternate_uart_speed_is_one_bit(self):
        """`cygnos` and `demon` write the same byte, which is measured, not a slip."""
        self.assertEqual(self.a_page(cygnos=True).boot_flags, 0x10012)
        self.assertEqual(self.a_page(demon=True).boot_flags, 0x10012)

    def test_a_jtag_image_s_own_bits_and_its_dual_boot_button(self):
        jtag = {"kind": "jtag", "board": "falcon"}
        self.assertEqual(self.a_page(**jtag, nodvd=True).boot_flags, 0x20000)
        self.assertEqual(self.a_page(**jtag, olddvd=True).boot_flags, 0)
        self.assertEqual(self.a_page(**jtag, dualboot="power").boot_flags, 0x11040012)
        self.assertEqual(self.a_page(**jtag, dualboot="eject").boot_flags, 0x40012)
    def test_the_erase_block_is_the_console_s_own_and_not_every_board_states_it(self):
        self.assertEqual(self.a_page(board="trinity").block_size, 0x10000)
        self.assertEqual(self.a_page(board="falcon").block_size, 0)

    def test_the_copyright_year_is_the_board_s_and_jtag_has_its_own(self):
        self.assertIn(b"2004-2010", self.a_page(board="trinity").notice)
        self.assertIn(b"2004-2007", self.a_page(board="falcon").notice)
        self.assertIn(b"2004-2008",
                      self.a_page(kind="jtag", board="jasper").notice)


class WhichStagesTheChainIsMadeOf(unittest.TestCase):
    """The decisions in laying a chain.

    Its bytes are held against nine reference images in `tests/xebuild/e2e/`; what is
    checked here is what a build reaches for.
    """

    def sets(self, *groups) -> bytes:
        out = bytearray()
        for group in groups:
            for at, words in group:
                out += struct.pack(">II", at, len(words))
                out += struct.pack(">%dI" % len(words), *words)
            out += b"\xff\xff\xff\xff"
        return bytes(out)

    def a_chain(self, kind="glitch2", board="trinity", stages=None, tags=None,
                sets=(), **settings):
        one = a_build(self, kind=kind, board=board, **settings)
        one.release = AReleaseWithOnePatchFile(
            self.sets(*sets) if sets else b"",
            stages if stages is not None else (("CBA", 0x100), ("CBB", 0x200),
                                              ("CD", 0x180), ("CE", 0x140),
                                              ("CF", 0x400), ("CG", 0x14000)),
        )
        one._dump = ADumpThatOnlyAnswersWhatIsAsked(tags=tags)
        one.config.cpu_key = bytes(range(0x10))
        return one

    def test_the_list_is_followed_until_ce_and_an_empty_slot_is_skipped(self):
        """A fat glitch list reads `[CB, none, CD, CE, CF, CG]`, and a JTAG list runs
        past the chain with a second CB and CD that nobody lays."""
        one = self.a_chain(stages=(("CB", 0x100), (None, None), ("CD", 0x180),
                                   ("CE", 0x140), ("CB", 0x100), ("CD", 0x100)))
        self.assertEqual([listed.kind for listed in one._chain_files()],
                         ["CB", "CD", "CE"])

    def test_a_jtag_list_names_two_chains_and_two_pairs(self):
        """CB 5770, CD 5770, CE, a CF/CG pair, CB 5771, CD 8453, the release's pair."""
        one = self.a_chain(kind="jtag", board="falcon",
                           stages=(("CB", 0x100), ("CD", 0x180), ("CE", 0x140),
                                   ("CF", 0x400), ("CG", 0x14000), ("CB", 0x100),
                                   ("CD", 0x100), ("CF", 0x400), ("CG", 0x14000)))
        self.assertEqual([listed.kind for listed in one._chain_files(0)],
                         ["CB", "CD", "CE"])
        self.assertEqual([listed.kind for listed in one._chain_files(1)], ["CB", "CD"])
        self.assertEqual(one._chain_files(2), [])
        self.assertEqual(len(one._update_pairs()), 2)

    def test_a_nonce_is_taken_by_kind_and_not_by_position(self):
        """A chain with one CB takes the dump's CB, CD and CE and leaves its CB_B out.
        By position its CD would take a CB_B's nonce, which reads as a chain and is
        not one."""
        one = self.a_chain(stages=(("CB", 0x100), ("CD", 0x180), ("CE", 0x140)))
        stages = [Stage(a_stage(tag, 0x40), 0) for tag in ("CB", "CD", "CE")]
        self.assertEqual([nonce[0] for nonce in one._nonces(stages)], [1, 3, 4])

    def test_a_chain_the_walk_cannot_finish_draws_every_nonce(self):
        """An RGH3 chain: a third CB where the CD is due. The original draws all six,
        and under `-norandom` keeps what it read and the compiled-in rest."""
        one = self.a_chain(tags=("CB", "CB", "CB", "CD", "CE"))
        stages = [Stage(a_stage(tag, 0x40), 0) for tag in ("CB", "CB", "CD", "CE")]
        self.assertTrue(one.drawing)
        self.assertNotIn(bytes([1]) * 0x10, one._nonces(stages))
        one = self.a_chain(tags=("CB", "CB", "CB", "CD", "CE"), no_random=True)
        self.assertEqual(one._nonces(stages),
                         [bytes([1]) * 0x10, bytes([2]) * 0x10,
                          security.COMPILED_IN["CD"], security.COMPILED_IN["CE"]])

    def test_a_single_cb_finishes_the_walk(self):
        one = self.a_chain(tags=("CB", "CD", "CE"))
        self.assertFalse(one.drawing)

    def test_the_second_pass_is_for_a_retail_chain_with_no_cb_b(self):
        single = [Stage(a_stage(tag, 0x40), 0) for tag in ("CB", "CD", "CE")]
        split = [Stage(a_stage(tag, 0x40), 0) for tag in ("CB", "CB", "CD", "CE")]
        self.assertEqual(self.a_chain(kind="retail")._second_pass_at(single), 1)
        self.assertEqual(self.a_chain(kind="retail")._second_pass_at(split), -1)
        self.assertEqual(self.a_chain(kind="glitch")._second_pass_at(single), -1)

    def test_which_patch_set_each_kind_of_stage_takes(self):
        """By role and place: the B stage second takes the first set, a D the second.
        A development chain's SB and SD are the same two."""
        one = self.a_chain()
        self.assertEqual(one._patch_set_for("CBB", 1), 0)
        self.assertEqual(one._patch_set_for("SB", 1), 0)
        self.assertEqual(one._patch_set_for("CD", 2), 1)
        self.assertEqual(one._patch_set_for("SD", 2), 1)
        self.assertIsNone(one._patch_set_for("CBA", 0))
        self.assertIsNone(one._patch_set_for("CB", 0))
        self.assertIsNone(one._patch_set_for("CE", 3))

    def test_a_jtag_chain_takes_no_set_at_all(self):
        """Measured: its CB, CD and CE are the release's files, nothing laid over."""
        one = self.a_chain(kind="jtag", board="falcon")
        for kind in ("CB", "CBB", "CD", "CE"):
            self.assertIsNone(one._patch_set_for(kind, 3))

    def test_a_patch_that_lengthens_a_stage_is_stated_in_its_header(self):
        """The release's CD is 0x4F20 and comes out 0x5290; a header saying the old
        length would have everything that walks by lengths read it short."""
        one = self.a_chain(sets=([(0x10, (1,))], [(0x180, (2, 3))]))
        body = one._stage_body(one._chain_files()[2], 2)
        self.assertEqual(len(body), 0x190)
        self.assertEqual(Stage(body, 0).length, 0x190)

    def test_the_last_stage_is_sealed_over_its_padding_too(self):
        """The region runs past what CE states, to the next 0x10: the stream carries on
        over the padding, which x360mcp saw on a manufacturing image whose CE had moved
        and whose dump held something else at the same place."""
        one = self.a_chain(stages=(("CBA", 0x100), ("CBB", 0x200), ("CD", 0x180),
                                   ("CE", 0x14a)))
        out = one.chain()
        self.assertEqual(len(out), 0x100 + 0x200 + 0x180 + 0x150)
        self.assertNotEqual(out[-6:], bytes(6))

    def opened(self, one):
        """The chain this build lays, read back the way anything reads a chain."""
        out = one.chain()
        stages, at = [], 0
        while at < len(out):
            stage = Stage(out, at)
            stages.append(stage)
            at += stage.length
        keys = sealing.keys(stages, one.cpu_key, one._second_pass_at(stages))
        return stages, [rc4(key, stage.body)
                        for stage, key in zip(stages, keys, strict=True)]

    def test_the_manufacturing_regime_binds_nothing(self):
        """Its CB_A says so in a flag, and the CB_B of an image built that way carries
        sixteen zeros where the binding digest would be."""
        for flags, wanted in ((0, False), (0x0801, True)):
            with self.subTest(flags=flags):
                one = self.a_chain()
                one.release.bodies["cba_1.bin"] = a_stage("CB", 0x100, flags=flags)
                _stages, bodies = self.opened(one)
                digest = bodies[1][Fields.LENGTH:Fields.LENGTH * 2]
                self.assertEqual(digest == bytes(Fields.LENGTH), wanted)

    def test_the_pairing_is_the_console_s_own_and_goes_in_cb_b(self):
        one = self.a_chain()
        _stages, bodies = self.opened(one)
        self.assertEqual(Fields(bodies[1]).pairing, one.dump.pairing)
        self.assertEqual(Fields(bodies[1]).ldv, 0)


class WhatTheUpdateSlotCarries(unittest.TestCase):
    """CF and CG, and what of the console goes into them. Their bytes are held against
    eight reference images in `tests/xebuild/e2e/`."""

    def a_slot(self, kind="glitch2", board="trinity", stages=None, tail_at=0xD0000):
        one = WhichStagesTheChainIsMadeOf.a_chain(self, kind=kind, board=board,
                                                  stages=stages)
        run = one.slot(tail_at)
        return one, opened_under_the_1bl_key(Stage(run, 0)), run

    def test_the_cf_says_where_the_rest_of_cg_is_in_the_flash(self):
        """A count, then block numbers one up from the other, counted in the flash --
        0xAE0 on a 64 MB image, where the filesystem begins."""
        _one, cf, run = self.a_slot(tail_at=0x2B80000)
        spill = len(run) - layout.SLOT_SPAN
        count = -(-spill // layout.BLOCK)
        self.assertEqual(struct.unpack_from(">H", cf, 0x30)[0], count)
        self.assertEqual(struct.unpack_from(">%dH" % count, cf, 0x32),
                         tuple(range(0xAE0, 0xAE0 + count)))

    def test_the_pairing_and_the_lockdown_value_are_the_console_s(self):
        one, cf, _run = self.a_slot()
        self.assertEqual(Fields.in_cf(cf).pairing, one.dump.pairing)
        self.assertEqual(Fields.in_cf(cf).ldv, one.dump.ldv)
        self.assertEqual(cf[0x21B], 0)

    def test_a_chain_with_no_cb_b_leaves_the_pairing_out_and_keeps_the_rest(self):
        """Measured on a fat glitch image: three zeros, and the lockdown value."""
        _one, cf, _run = self.a_slot(
            kind="glitch", board="falcon",
            stages=(("CB", 0x100), (None, None), ("CD", 0x180), ("CE", 0x140),
                    ("CF", 0x400), ("CG", 0x14000)))
        self.assertEqual(Fields.in_cf(cf).pairing, bytes(3))
        self.assertEqual(Fields.in_cf(cf).ldv, 14)

    def test_only_the_last_of_a_jtag_image_s_two_pairs_is_the_console_s(self):
        """Measured on the falcon JTAG image: CF 4532 says where its tail is and nothing
        more of the console; CF 17559 is slot 1 and carries pairing and binding."""
        stages = (("CB", 0x100), ("CD", 0x180), ("CE", 0x140), ("CF", 0x400),
                  ("CG", 0x14000), ("CB", 0x100), ("CD", 0x100), ("CF", 0x400),
                  ("CG", 0x14000))
        one = WhichStagesTheChainIsMadeOf.a_chain(self, kind="jtag", board="falcon",
                                                  stages=stages)
        first = opened_under_the_1bl_key(Stage(one.slot(0xE4000, 0), 0))
        last = opened_under_the_1bl_key(Stage(one.slot(0xE8000, 1), 0))
        self.assertEqual(first[0x218:0x230], bytes(0x18))
        self.assertEqual(struct.unpack_from(">H", first, 0x32)[0], 0xE4000 // 0x4000)
        self.assertEqual(last[0x21B], 1)
        self.assertEqual(Fields.in_cf(last).pairing, one.dump.pairing)
        self.assertNotEqual(last[0x220:0x230], bytes(0x10))

    def test_both_nonces_are_the_console_s_own(self):
        _one, _cf, run = self.a_slot()
        cf = Stage(run, 0)
        self.assertEqual(cf.nonce, b"\xcf" * 0x10)
        self.assertEqual(Stage(run, cf.length).nonce, b"\xc9" * 0x10)

    def test_what_a_slot_cannot_be_built_without_is_refused(self):
        one = WhichStagesTheChainIsMadeOf.a_chain(self)
        one.config.cpu_key = None
        with self.assertRaises(ValueError):
            one.slot(0xD0000)
        one = WhichStagesTheChainIsMadeOf.a_chain(self, stages=(("CB", 0x100),))
        with self.assertRaises(ValueError):
            one.slot(0xD0000)


class WhatAnSmcIsRefusedFor(unittest.TestCase):
    """The original's classifier and the three fatal cases `smcnocheck` waives."""

    def test_a_retail_image_over_a_hacked_smc_is_refused(self):
        """No reset limit left, so not clean: the case this console's own dump is."""
        hacked = bytes(0x40) + bytes(0x40)
        one = a_build(self, kind="retail", files={"smc.bin": hacked + b"\x01"
                                                  + bytes(3)})
        with self.assertRaises(ValueError):
            one.smc()

    def test_smcnocheck_waives_it(self):
        hacked = bytes(0x80) + b"\x01" + bytes(3)
        one = a_build(self, kind="retail", files={"smc.bin": hacked}, smcnocheck=True)
        self.assertEqual(len(one.smc()), len(hacked))

    def test_a_jtag_image_over_a_clean_smc_is_refused(self):
        one = a_build(self, kind="jtag", board="falcon", files={"smc.bin": AN_SMC})
        with self.assertRaises(ValueError):
            one.smc()

    def test_a_glitch_image_over_a_clean_smc_only_complains(self):
        one = a_build(self, kind="glitch2", files={"smc.bin": AN_SMC}, patchsmc=False)
        with self.assertLogs("xebuild.build.build", level="WARNING"):
            one.smc()

    def test_an_smc_that_does_not_decrypt_is_refused(self):
        """Four non-zero bytes at the end say sealed, and opening it does not help."""
        one = a_build(self, files={"smc.bin": bytes(range(0x100))})
        with self.assertRaises(ValueError):
            one.smc()

    def test_a_blank_smc_is_refused_which_is_ours_and_not_the_original_s(self):
        one = a_build(self, files={"smc.bin": bytes(0x3000)})
        with self.assertRaises(ValueError):
            one.smc()


class AListOfFirmware:
    """A file list naming firmware files and no security files."""

    security = ()

    def __init__(self, *listed):
        self.firmware = tuple(Listed(name, crc) for name, crc in listed)


class AReleaseHoldingEveryFile:
    """Every file beside its list, holding `BODY`; nothing in a container or common/."""

    def listed_file(self, name):
        return BODY

    def container_file(self, name):
        return None

    def common_file(self, name):
        return None


BODY = b"body"
# The checksum a list states for `BODY`, so the file counts.
CRC = "%08x" % binascii.crc32(BODY)


class TheSmallerRulesOfABuild(unittest.TestCase):
    """What the fields of a build turn on, each one measured on the original."""

    def names(self, kind, board, *listed):
        one = a_build(self, kind=kind, board=board)
        one.release = AReleaseHoldingEveryFile()
        one._recipe = AListOfFirmware(*listed)
        return [name for name, _body in one.files(0x5A000000)]

    def test_a_jtag_image_names_its_patch_files_for_two_slots_whatever_it_lists(self):
        """`aac.xexp2` from a JTAG list with its own pair taken out -- measured; and
        any name ending in p that the list vouches for, 17489's `rrbkgnd.bmp` too."""
        listed = (("aac.xexp", CRC), ("rrbkgnd.bmp", CRC))
        self.assertEqual(self.names("jtag", "falcon", *listed),
                         ["aac.xexp2", "rrbkgnd.bmp2"])
        self.assertEqual(self.names("glitch2", "trinity", *listed),
                         ["aac.xexp1", "rrbkgnd.bmp1"])

    def test_a_name_ending_in_p_with_no_checksum_takes_no_number(self):
        """17489_RGL's `rglXam.rglp`, listed with none."""
        self.assertEqual(self.names("glitch2", "trinity", ("rglXam.rglp", "")),
                         ["rglXam.rglp"])

    def test_an_se_in_a_jtag_list_zeroes_the_lockdown_value_cfldv_or_not(self):
        """1838's; and 17559's list without its own pair keeps the console's."""
        stages = (("CB", 0x100), ("CD", 0x180), ("CE", 0x140), ("CF", 0x400),
                  ("CG", 0x14000), ("CB", 0x100), ("CD", 0x100), ("SE", 0x100))
        one = WhichStagesTheChainIsMadeOf.a_chain(self, kind="jtag", board="falcon",
                                                  stages=stages, cfldv=10)
        self.assertEqual(one.ldv, 0)
        one = WhichStagesTheChainIsMadeOf.a_chain(self, kind="jtag", board="falcon",
                                                  stages=stages[:7])
        self.assertEqual(one.ldv, 14)

    def test_which_stage_wears_the_console_by_role(self):
        """A split chain on its second B, a lone B on retail, devkit and a JTAG
        image's second chain, nothing on a glitch image."""
        glitch = a_build(self, kind="glitch", board="falcon")
        devkit = a_build(self, kind="devkit", board="falcon")
        self.assertEqual(glitch._wears_console(["CBA", "SB", "SD", "SE"]), 1)
        self.assertEqual(glitch._wears_console(["CB", "CD", "CE"]), -1)
        self.assertEqual(glitch._wears_console(["CB", "CD"], which=1), 0)
        self.assertEqual(devkit._wears_console(["SB", "SC", "SD", "SE"]), 0)

    def test_a_1bl_key_that_does_not_sum_is_refused(self):
        with self.assertRaises(ValueError):
            _ = a_build(self, one_bl_key="00112233445566778899AABBCCDDEEFF").one_bl_key
        good = "DD88AD0C9ED669E7B56794FB68563EFA"
        self.assertEqual(a_build(self, one_bl_key=good).one_bl_key.hex().upper(), good)

    def test_a_dump_of_no_length_a_flash_has_is_ignored_not_refused(self):
        """"is not a correct raw (with ecc) dump size (0x10c2000 bytes), ignoring"."""
        one = a_build(self, dump=False, files={"nanddump.bin": bytes(0x1000)})
        self.assertIsNone(one.dump)

    def test_a_foreign_crl_beside_the_build_goes_in_as_it_stands(self):
        from .test_security import OTHER, a_crl
        foreign = a_crl(OTHER)
        one = a_build(self, dump=False, files={"crl.bin": foreign},
                      cpu_key=bytes(range(0x10)).hex())
        self.assertEqual(one.security_file("crl.bin", 0x5A000000), foreign)

    def test_a_secdata_of_the_wrong_length_is_made_up_clean(self):
        key = bytes(range(0x10))
        one = a_build(self, dump=False, files={"secdata.bin": bytes(0x200)},
                      cpu_key=key.hex(), no_random=True)
        made = one.security_file("secdata.bin", 0x5A000000)
        self.assertEqual(len(made), 0x400)
        plain = rc4(hmacsha(key, made[:0x10]), made[0x10:])
        self.assertEqual(plain[:8], security.COMPILED_IN["secdata.bin"])

    def test_a_zero_cpu_key_zero_pairs_a_chain_with_a_cb_b(self):
        """"CPU key is all zeros, zeropairing CB_B": no pairing, no binding, LDV 0 --
        the dump's 14 and `cfldv` notwithstanding."""
        one = a_build(self, cpu_key="0" * 32, cfldv=5)
        one._chain_files = lambda which=0: [Listed("cba_1.bin", "0"),
                                            Listed("cbb_1.bin", "0")]
        self.assertTrue(one.zero_paired)
        self.assertEqual(one.pairing, bytes(3))
        self.assertEqual(one.ldv, 0)

    def test_a_lone_cb_keeps_its_pairing_under_a_zero_key(self):
        """A JTAG image's, measured: the LDV is 0 all the same."""
        one = a_build(self, kind="jtag", board="falcon", cpu_key="0" * 32)
        one._chain_files = lambda which=0: [Listed("cb_1.bin", "0")]
        self.assertTrue(one.zero_key)
        self.assertFalse(one.zero_paired)
        self.assertEqual(one.pairing, one.dump.pairing)
        self.assertEqual(one.ldv, 0)

    def test_with_no_dump_a_settings_block_has_to_be_given(self):
        """ "could not read smc_config.bin", "critical bootloader files are missing"."""
        with self.assertRaises(ValueError) as caught:
            a_build(self, dump=False)._settings()
        self.assertIn("smc_config.bin", str(caught.exception))

    def test_an_smc_config_bin_with_no_sound_block_stops_the_build(self):
        """Dump or not, measured: "unable to find SMC config data!"."""
        for dump in (True, False):
            with self.subTest(dump=dump), self.assertRaises(ValueError):
                a_build(self, dump=dump,
                        files={"smc_config.bin": bytes(0x400)})._config_block()

    def test_a_listed_sysupdate_xexp_is_left_out_in_any_case(self):
        """ "'sysupdate.xexp' is a reserved name!", `_strnicmp` over fourteen."""
        listed = (("SysUpdate.xexp1", CRC), ("aac.xexp", CRC))
        self.assertEqual(self.names("glitch2", "trinity", *listed), ["aac.xexp1"])


class HowMuchOfADumpIsRead(unittest.TestCase):
    """`image.dump.cut`: the original's loader rule for a dump longer than 48 MB."""

    SPARE = for_name("trinity")[0].flash.spare

    def a_nand_start(self) -> bytes:
        page = b"\xff\x4f" + bytes(PAGE - 2)
        return page + self.SPARE.with_ecc(page, bytes(self.SPARE.length))

    def test_nothing_up_to_48_mb_is_cut(self):
        raw = bytes(0x3000000)
        self.assertIs(dumps.cut(raw), raw)

    def test_an_emmc_dump_past_48_mb_is_cut_there(self):
        """Measured both ways: `FATX` at 0x3000000, or no code on the first page."""
        fatx = self.a_nand_start().ljust(0x3000000, b"\0") + b"FATX" + bytes(0x100)
        self.assertEqual(len(dumps.cut(fatx)), 0x3000000)
        self.assertEqual(len(dumps.cut(bytes(0x4000000))), 0x3000000)

    def test_a_big_block_part_read_whole_is_cut_to_64_mb(self):
        raw = self.a_nand_start().ljust(0x4200000 + 0x1000, b"\0")
        self.assertEqual(len(dumps.cut(raw)), 0x4200000)
        exact = raw[:0x4200000]
        self.assertIs(dumps.cut(exact), exact)


class WhichDumpsAreThrownAway(unittest.TestCase):
    """`image.dump.faulty`, over a made-up run of blocks of a 16 MB part.

    Each rule measured on the bench console's dump with the one fault put in: the
    original discarded it, and with the console's own files beside the build made the
    image this makes.
    """

    FLASH = for_name("trinity")[0].flash

    def a_header(self, fields=None) -> bytes:
        """A page 0 every check passes, with `fields` -- offset: (width, value) --
        written over it."""
        head = Header.blank()
        head.entrypoint, head.size, head.cf_at = 0x8000, 0x70000, 0x70000
        head.keyvault_at, head.keyvault_size = 0x4000, 0x4000
        head.patch_slots, head.keyvault_version = 2, 0x0712
        head.smc_at, head.smc_size = 0x1000, 0x3000
        page = bytearray(head.image)
        for at, (width, value) in (fields or {}).items():
            page[at:at + width] = value.to_bytes(width, "big")
        return bytes(page)

    def a_dump(self, blocks=40, bad=(), failing=(), header=None):
        spare, per = self.FLASH.spare, self.FLASH.spare.pages_a_block
        out = bytearray()
        for block in range(blocks):
            for page in range(per):
                data = bytearray((header or self.a_header()) if block == page == 0
                                 else bytes([block & 0xFF]) * PAGE)
                fields = bytearray(spare.write(block))
                if block in bad:
                    fields[spare.mark_at] = 0
                fields = spare.with_ecc(bytes(data), bytes(fields))
                if block in failing and page == 1:
                    data[100] ^= 1
                out += data + fields
        return bytes(out)

    def faulty(self, raw, ecd=True):
        return dumps.faulty(raw, self.FLASH, ecd=ecd)

    def test_a_sound_dump_is_kept(self):
        self.assertEqual(self.faulty(self.a_dump()), "")

    def test_a_header_without_its_magic(self):
        raw = self.a_dump(header=self.a_header({0x00: (2, 0xFF4E)}))
        self.assertIn("magic", self.faulty(raw))

    def test_each_header_field_the_loader_checks(self):
        """0x416D1D, one field at a time, all measured; the file here is 0xA5000."""
        past = 0x100000
        for fields, said in (({0x08: (4, past)}, "Entry"),
                             ({0x0C: (4, past)}, "Size is"),
                             ({0x60: (4, 0x8004)}, "KeyVaultSize"),
                             ({0x64: (4, 0x10)}, "SysUpdateAddr"),
                             ({0x64: (4, past)}, "SysUpdateAddr"),
                             ({0x6C: (4, past)}, "KeyVaultAddr"),
                             ({0x70: (4, past)}, "FileSystemAddr"),
                             ({0x78: (4, 0x2000)}, "SmcBootSize"),
                             ({0x7C: (4, past)}, "SmcBootAddr")):
            with self.subTest(said):
                raw = self.a_dump(header=self.a_header(fields))
                self.assertIn(said, self.faulty(raw))

    def test_three_header_fields_are_only_complained_about(self):
        """A keyvault of 0x8000, a slot count of 3, a settings address, and an SMC of
        0x3800 all pass, the middle two with a warning."""
        for fields in ({0x60: (4, 0x8000)}, {0x68: (2, 3)}, {0x74: (4, 0x1234)},
                       {0x78: (4, 0x3800)}):
            with self.subTest(fields):
                raw = self.a_dump(header=self.a_header(fields))
                self.assertEqual(self.faulty(raw), "")

    def test_an_emmc_image_the_original_built_for_xell(self):
        """ "is a ZEROPAIR/XELL image, discarding" -- on an eMMC dump only."""
        emmc = for_name("corona4g")[0].flash
        head = bytearray(self.a_header())
        head[0x10:0x1E] = b"zeropair image"
        raw = bytes(head).ljust(0x100000, b"\0")
        self.assertIn("ZEROPAIR", dumps.faulty(raw, emmc))
        self.assertEqual(dumps.faulty(self.a_header().ljust(0x100000, b"\0"), emmc), "")

    def test_block_0_marked_bad(self):
        self.assertIn("block 0", self.faulty(self.a_dump(bad=(0,))))

    def test_more_than_32_to_remap_whether_marked_or_failing_their_code(self):
        """32 is kept, 33 is not -- measured, `noremap` or not, which is why it is not
        asked here."""
        self.assertEqual(self.faulty(self.a_dump(bad=range(1, 33))), "")
        self.assertIn("33", self.faulty(self.a_dump(bad=range(1, 34))))
        self.assertIn("33", self.faulty(self.a_dump(failing=range(1, 34))))

    def test_noecdremap_takes_the_failing_ones_out_of_the_count(self):
        self.assertEqual(self.faulty(self.a_dump(failing=range(1, 34)), ecd=False), "")
