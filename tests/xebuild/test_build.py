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
from xebuild.build import Build, Filesystem, Material, layout
from xebuild.config import BuildConfig
from xebuild.crypto import smc as cipher
from xebuild.image import Directory, Header, Image
from xebuild.image.directory import CHAIN_END
from xebuild.imagetypes import for_name as type_for
from xebuild.release import Patches


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

    def test_the_tail_is_a_file_only_where_it_falls_inside_the_filesystem(self):
        """Thirty one files against thirty, on two images of the same build."""
        self.assertTrue(layout.tail_is_a_file(0xD0000, base=0))
        self.assertFalse(layout.tail_is_a_file(0x2B80000, base=0x2B80000))

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


class ADumpThatOnlyAnswersWhatIsAsked:
    """Stands in for a console's dump, which is seventeen megabytes of ECC to make up.

    What the regions ask a dump is two things, and a test that built a whole flash to
    hand them over would spend a second and a half on codes nobody looks at. The bytes
    themselves are held against a real dump in `tests/xebuild/e2e/`.
    """

    def __init__(self, smc=AN_SMC, seed=b"\xfb\xd7\x5a\x10"):
        self.smc = cipher.sealed(smc, seed)
        self.sealed_keyvault = bytes(range(0x100)) * 0x40


class AReleaseWithOnePatchFile:
    """Stands in for a release, and records which patch file was asked for."""

    def __init__(self, sets):
        self.raw = sets
        self.asked = []

    def patches(self, image_type, board, ext=""):
        named = board if isinstance(board, str) else board.section
        self.asked.append((image_type.name, named))
        return Patches(self.raw)


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
        plain = bytes(0x100)
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

    def test_a_file_in_the_per_build_directory_wins(self):
        one = a_build(self, files={"kv.bin": b"a keyvault" * 100})
        self.assertEqual(one.keyvault(), b"a keyvault" * 100)

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

    def test_a_manufacturing_image_is_refused_rather_than_guessed_at(self):
        """Its slot begins with twelve fuse lines and two of them are not measured."""
        one = a_build(self, kind="glitch2m")
        with self.assertRaises(ValueError):
            one.patch_slot()


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

    def test_an_option_that_reaches_those_bytes_is_refused(self):
        """Handing back the default would be an image starting on the wrong button."""
        with self.assertRaises(ValueError):
            self.a_page(xellbutton="power")
        with self.assertRaises(ValueError):
            self.a_page(nodvd=True)

    def test_the_erase_block_is_the_console_s_own_and_not_every_board_states_it(self):
        self.assertEqual(self.a_page(board="trinity").block_size, 0x10000)
        self.assertEqual(self.a_page(board="falcon").block_size, 0)

    def test_the_copyright_year_is_the_board_s_and_jtag_has_its_own(self):
        self.assertIn(b"2004-2010", self.a_page(board="trinity").notice)
        self.assertIn(b"2004-2007", self.a_page(board="falcon").notice)
        self.assertIn(b"2004-2008",
                      self.a_page(kind="jtag", board="jasper").notice)
