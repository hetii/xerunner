"""What the roster has to hold true, and the numbers that came off real images.

A module of facts is easy to test badly: restating a constant proves nothing. So what is
pinned here is of two kinds. The rules -- one spelling means one console, a `bigffs`
spelling exists exactly where the flash has room for it -- would catch an entry added
wrongly. The numbers are the ones a build's output was measured against: image lengths,
where a filesystem starts, what a header states.

`AgainstTheBinary` is the strongest of them and needs the original. It is skipped unless
`XEBUILD_REFERENCE` names a copy of `xeBuild.exe`, so nothing here depends on material
this repository does not carry.
"""

import unittest

from xebuild import boards
from xebuild.boards import flash, spare

SIXTEEN = 16 * 1024 * 1024
SIXTY_FOUR = 64 * 1024 * 1024
FORTY_EIGHT = 48 * 1024 * 1024


class TheRoster(unittest.TestCase):

    def test_fourteen_consoles_answer_to_twenty_one_spellings(self):
        self.assertEqual(len(boards.ALL), 14)
        self.assertEqual(len(boards.names()), 21)

    def test_no_spelling_belongs_to_two_consoles(self):
        every = boards.names()
        self.assertEqual(len(set(every)), len(every))

    def test_every_console_says_what_it_is(self):
        for board in boards.ALL:
            with self.subTest(board=board.name):
                self.assertTrue(board.name)
                self.assertTrue(board.section)
                self.assertTrue(board.smc_clean)
                self.assertIsNotNone(board.flash)

    def test_a_section_is_a_prefix_of_the_console_s_own_name(self):
        for board in boards.ALL:
            with self.subTest(board=board.name):
                self.assertTrue(board.name.startswith(board.section))


class Lookup(unittest.TestCase):

    def test_every_spelling_resolves(self):
        for spelling in boards.names():
            with self.subTest(spelling=spelling):
                board, _ = boards.for_name(spelling)
                self.assertIn(spelling, board.spellings)

    def test_only_a_bigffs_spelling_asks_for_the_larger_filesystem(self):
        asked = {s for s in boards.names() if boards.for_name(s)[1]}
        self.assertEqual(
            asked,
            {"jasperbigffs", "trinitybigffs", "coronabigffs", "winchesterbigffs"},
        )

    def test_case_and_space_do_not_matter(self):
        board, big = boards.for_name("  TrinityBigFFS ")
        self.assertEqual(board.name, "trinitybb")
        self.assertTrue(big)

    def test_a_name_that_is_not_a_console_is_refused(self):
        with self.assertRaises(ValueError):
            boards.for_name("banana")

    def test_the_aliases_reach_the_console_they_belong_to(self):
        for spelling, expected in (
            ("jasperbc", "jasper"),
            ("jasper256", "jasperbb"),
            ("jasper512", "jasperbb"),
        ):
            with self.subTest(spelling=spelling):
                self.assertEqual(boards.for_name(spelling)[0].name, expected)


class TheLargerFilesystem(unittest.TestCase):
    """It is a build's choice, so it moves the filesystem and nothing else."""

    def test_a_spelling_exists_exactly_where_the_flash_has_room(self):
        for board in boards.ALL:
            with self.subTest(board=board.name):
                room = board.flash.bigffs_base is not None
                self.assertEqual(bool(board.bigffs), room)
                if room:
                    self.assertEqual(board.bigffs, board.section + "bigffs")

    def test_it_moves_the_filesystem_and_leaves_the_image_alone(self):
        for spelling in ("jasperbigffs", "trinitybigffs", "coronabigffs",
                         "winchesterbigffs"):
            with self.subTest(spelling=spelling):
                board, big = boards.for_name(spelling)
                self.assertEqual(board.offset_of(0, big), 0xB80000)
                self.assertEqual(board.offset_of(0), 0x2B80000)
                self.assertEqual(board.length, SIXTY_FOUR)


class Geometry(unittest.TestCase):
    """Measured against images the original built."""

    def test_an_image_is_one_of_three_lengths(self):
        for board in boards.ALL:
            with self.subTest(board=board.name):
                self.assertIn(board.length, (SIXTEEN, SIXTY_FOUR, FORTY_EIGHT))

    def test_a_spare_adds_sixteen_bytes_to_every_page_of_five_hundred_and_twelve(self):
        for board in boards.ALL:
            with self.subTest(board=board.name):
                if board.spare is None:
                    self.assertEqual(board.raw_length, board.length)
                else:
                    self.assertEqual(board.raw_length, board.length // 512 * 528)

    def test_the_three_lengths_on_disk(self):
        self.assertEqual(boards.for_name("trinity")[0].raw_length, 17301504)
        self.assertEqual(boards.for_name("trinitybb")[0].raw_length, 69206016)
        self.assertEqual(boards.for_name("corona4g")[0].raw_length, 50331648)

    def test_only_a_sixty_four_megabyte_image_reserves_room_below_its_filesystem(self):
        for board in boards.ALL:
            with self.subTest(board=board.name):
                expected = 0x2B80000 if board.length == SIXTY_FOUR else 0
                self.assertEqual(board.offset_of(0), expected)

    def test_what_a_header_states_as_its_block_size(self):
        stated = {b.name: b.stated_block_size() for b in boards.ALL}
        self.assertEqual(
            stated,
            {
                "xenon": 0, "zephyr": 0, "falcon": 0, "jaspersb": 0,
                "jasper": 0x10000, "jasperbb": 0x20000,
                "trinity": 0x10000, "trinitybb": 0x10000,
                "corona": 0x10000, "coronabb": 0x10000, "corona4g": 0x10000,
                "winchester": 0x10000, "winchesterbb": 0x10000,
                "winchester4g": 0x10000,
            },
        )

    def test_only_the_two_oldest_boards_leave_the_keyvault_length_unstated(self):
        silent = {b.name for b in boards.ALL if not b.states_keyvault_size}
        self.assertEqual(silent, {"xenon", "zephyr"})

    def test_a_fat_chain_belongs_to_the_four_oldest_families(self):
        fat = {b.section for b in boards.ALL if b.fat}
        self.assertEqual(fat, {"xenon", "zephyr", "falcon", "jasper"})

    def test_an_emmc_console_is_the_one_with_no_spare_area(self):
        flat = {b.name for b in boards.ALL if b.spare is None}
        self.assertEqual(flat, {"corona4g", "winchester4g"})
        for name in flat:
            self.assertTrue(boards.for_name(name)[0].flash.anchors)


class TheFlatShape(unittest.TestCase):
    """The one shape no console carries: what `devkit` and `testkit` images take."""

    def test_it_belongs_to_no_console(self):
        self.assertNotIn(flash.FlatBigNand, {type(b.flash) for b in boards.ALL})

    def test_it_is_sixty_four_megabytes_counting_from_zero(self):
        shape = flash.FlatBigNand(spare.SmallBlock())
        self.assertEqual(shape.length, SIXTY_FOUR)
        self.assertEqual(shape.offset_of(0), 0)
        self.assertEqual(shape.smc_config, 0x3DFC000)

    def test_it_states_the_16_mb_step_and_keeps_no_pool(self):
        """Measured on devkit images for xenon, falcon and jasper."""
        shape = flash.FlatBigNand(spare.SmallBlock())
        self.assertEqual((shape.block_size, shape.states_block_size), (0x10000, True))
        self.assertEqual(shape.round_to, 0x4000)
        self.assertFalse(shape.pool)


class TheSpareLayouts(unittest.TestCase):

    def test_there_are_three_and_they_differ(self):
        used = {type(b.spare) for b in boards.ALL if b.spare is not None}
        self.assertEqual(len(used), 3)
        self.assertEqual({one().meta for one in used}, {0, 1, 2})

    def test_what_is_written_is_what_is_read_back(self):
        for layout in (spare.SmallBlock(), spare.BigBlockController(),
                       spare.BigBlockChip()):
            with self.subTest(meta=layout.meta):
                written = layout.write(0x15C, sequence=7, kind=0x31)
                self.assertEqual(len(written), 16)
                self.assertEqual(layout.block_number(written), 0x15C)
                self.assertEqual(layout.sequence(written), 7)
                self.assertEqual(layout.kind(written), 0x31)
                self.assertTrue(layout.is_good(written))

    def test_a_block_marked_bad_is_not_good(self):
        layout = spare.BigBlockChip()
        written = bytearray(layout.write(1))
        written[layout.mark_at] = 0x00
        self.assertFalse(layout.is_good(bytes(written)))

    def test_a_version_of_more_than_a_byte_is_read_whole(self):
        """Real spare bytes off two consoles, against what the original prints.

        `mobileB.dat` on one reads 626 and another's `fsroot` reads 349. The top eight
        bits are four bytes away from the bottom eight, so reading only the low byte
        gives 114 and 93 -- and picking the higher of two copies by that would take the
        older one.
        """
        layout = spare.BigBlockController()
        for real, wanted in (
            ("723b010200ff00000814000071175a84", 626),
            ("5dd2010100ff000000000000307c0039", 349),
        ):
            with self.subTest(version=wanted):
                self.assertEqual(layout.sequence(bytes.fromhex(real)), wanted)

    def test_what_is_written_as_a_wide_version_reads_back_whole(self):
        layout = spare.BigBlockController()
        written = layout.write(0x1D2, sequence=626, kind=0x31)
        self.assertEqual(layout.sequence(written), 626)
        self.assertEqual(layout.block_number(written), 0x1D2)
        self.assertEqual(layout.kind(written), 0x31)

    def test_the_other_two_layouts_keep_theirs_in_one_byte(self):
        for layout, at in ((spare.SmallBlock(), 2), (spare.BigBlockChip(), 5)):
            with self.subTest(meta=layout.meta):
                self.assertIsNone(layout.sequence_high_at)
                fields = bytearray(16)
                fields[at] = 0x7B
                self.assertEqual(layout.sequence(bytes(fields)), 0x7B)

    def test_a_version_too_large_for_the_layout_is_refused(self):
        """Not cut down: half a number nobody asked for reads back as an older copy."""
        for layout in (spare.SmallBlock(), spare.BigBlockChip()):
            with self.subTest(meta=layout.meta), self.assertRaises(ValueError):
                layout.write(1, sequence=256)
        with self.assertRaises(ValueError):
            spare.BigBlockController().write(1, sequence=0x10000)

    def test_only_a_big_block_chip_holds_two_hundred_and_fifty_six_pages(self):
        self.assertEqual(spare.SmallBlock().pages_a_block, 32)
        self.assertEqual(spare.BigBlockController().pages_a_block, 32)
        self.assertEqual(spare.BigBlockChip().pages_a_block, 256)


class TheCodeOverAPage(unittest.TestCase):
    """What the controller keeps for every page, and what depends on it being right."""

    def test_a_page_carries_the_code_its_own_bytes_ask_for(self):
        for layout in (spare.SmallBlock(), spare.BigBlockController(),
                       spare.BigBlockChip()):
            with self.subTest(meta=layout.meta):
                data = bytes(range(256)) * 2
                fields = layout.write(0x15C, sequence=7, kind=0x31)
                whole = layout.with_ecc(data, fields)
                self.assertTrue(layout.ecc_ok(data + whole))

    def test_one_byte_of_data_changing_makes_the_code_wrong(self):
        layout = spare.BigBlockController()
        data = bytes(range(256)) * 2
        whole = layout.with_ecc(data, layout.write(1))
        self.assertTrue(layout.ecc_ok(data + whole))
        moved = bytearray(data)
        moved[100] ^= 0x01
        self.assertFalse(layout.ecc_ok(bytes(moved) + whole))

    def test_writing_the_code_leaves_every_other_field_alone(self):
        layout = spare.BigBlockChip()
        data = b"\xa5" * 512
        fields = layout.write(0x2E0, sequence=9, kind=0x2A)
        whole = layout.with_ecc(data, fields)
        self.assertEqual(whole[:layout.kind_at], fields[:layout.kind_at])
        self.assertEqual(layout.block_number(whole), 0x2E0)
        self.assertEqual(layout.sequence(whole), 9)
        self.assertEqual(layout.kind(whole), 0x2A)

    def test_a_short_page_has_no_code_to_check(self):
        self.assertFalse(spare.SmallBlock().ecc_ok(b"\x00" * 100))


class WhatTheOriginalPrints(unittest.TestCase):

    def test_two_consoles_it_cannot_name(self):
        blank = {b.name for b in boards.ALL if not b.text}
        self.assertEqual(blank, {"coronabb", "winchesterbb"})
        for name in blank:
            board, _ = boards.for_name(name)
            self.assertEqual(board.named, "whoops, console type was not caught!")

    def test_everyone_else_is_named(self):
        for board in boards.ALL:
            if board.text:
                with self.subTest(board=board.name):
                    self.assertEqual(board.named, board.text)

    def test_the_copyright_year_a_jtag_image_carries(self):
        years = {b.section: (b.notice_year(), b.notice_year("jtag"))
                 for b in boards.ALL}
        self.assertEqual(
            years,
            {
                "xenon": (2005, 2005), "zephyr": (2005, 2005),
                "falcon": (2007, 2007), "jasper": (2009, 2008),
                "trinity": (2010, 2007), "corona": (2010, 2007),
                "winchester": (2010, 2007),
            },
        )

    def test_zephyr_has_a_stock_image_of_its_own_and_borrows_the_rest(self):
        zephyr, _ = boards.for_name("zephyr")
        self.assertEqual(zephyr.smc("clean"), "ZEPHYR_CLEAN.bin")
        self.assertEqual(zephyr.smc("cr4"), "FALCON_CR4.bin")
        self.assertEqual(zephyr.smc("smc+"), "FALCON_SMC+.bin")

    def test_the_boards_with_no_glitch_image(self):
        for name, missing in (("xenon", ("cr4",)),
                              ("winchester", ("cr4", "smc+"))):
            board, _ = boards.for_name(name)
            for kind in missing:
                with self.subTest(board=name, kind=kind):
                    self.assertEqual(board.smc(kind), "")


if __name__ == "__main__":
    unittest.main()
