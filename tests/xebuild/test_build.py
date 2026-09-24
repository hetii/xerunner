"""Laying an image, and first the directory a console's own things come from.

A directory is cheap to make up, so all of this runs on one built here rather than on a
real one: written, read back, and checked. Where scratch goes is `tests/__init__.py`'s
business.
"""

import os
import shutil
import struct
import tempfile
import unittest

from xebuild.boards import for_name
from xebuild.build import Build, Filesystem, Material, layout, security
from xebuild.chain import Fields, sealing
from xebuild.chain.stage import Stage
from xebuild.config import BuildConfig
from xebuild.crypto import smc as cipher
from xebuild.crypto.rc4 import rc4
from xebuild.image import Directory, Header, Image, Keyvault
from xebuild.image.directory import CHAIN_END
from xebuild.imagetypes import for_name as type_for
from xebuild.release import Patches
from xebuild.release.recipe import Listed

from .test_chain import a_stage


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

    KEY = "7E5068DBB3FD03F04E367028D475EEC2"

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
    the console's own values come from, with its CG right behind it."""

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
        self.smc = cipher.sealed(smc, seed)
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
        self.assertEqual(one.smc(), cipher.sealed(plain, one.dump.smc[:4]))

    def test_patchsmc_lifts_the_reset_limit_and_moves_nothing_else(self):
        one = a_build(self, patchsmc=True)
        was, now = cipher.opened(one.dump.smc), cipher.opened(one.smc())
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
        return one, sealing.under(Stage(run, 0), sealing.ONE_BL_KEY), run

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
        first = sealing.under(Stage(one.slot(0xE4000, 0), 0), sealing.ONE_BL_KEY)
        last = sealing.under(Stage(one.slot(0xE8000, 1), 0), sealing.ONE_BL_KEY)
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
