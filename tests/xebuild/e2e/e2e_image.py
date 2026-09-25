"""What a console's own dump says, against what the original prints for it.

Needs real material and says which. See `tests/xebuild/e2e/__init__.py`.
"""

import os
import unittest

from xebuild.boards import for_name
from xebuild.image import Anchor, Dump, Image, Keyvault, anchor as anchors, order


class AgainstAConsoleSOwnDump(unittest.TestCase):
    """The numbers the original prints for a real dump.

    Skipped unless `XEBUILD_DUMP` names one. `XEBUILD_DUMP_BLOBS` says what to expect,
    as `name:version:offset` separated by spaces, so a different dump can be checked
    without touching this file; without it the two consoles measured here are tried by
    the count of files their tables name.
    """

    def setUp(self):
        where = os.environ.get("XEBUILD_DUMP", "")
        if not os.path.isfile(where):
            raise unittest.SkipTest("XEBUILD_DUMP does not name a dump")
        board, _ = for_name("trinity")
        with open(where, "rb") as handle:
            self.image = Image(handle.read(), board.flash)

    def test_its_header_is_a_header(self):
        self.assertTrue(self.image.header.ok)
        self.assertEqual(self.image.header.entrypoint, 0x8000)

    def test_the_blobs_the_original_reports(self):
        wanted = os.environ.get("XEBUILD_DUMP_BLOBS", "")
        if not wanted:
            raise unittest.SkipTest("XEBUILD_DUMP_BLOBS does not say what to expect")
        for one in wanted.split():
            name, version, offset = one.split(":")
            with self.subTest(blob=name):
                found = self.image.blobs[name]
                self.assertEqual(found["version"], int(version, 0))
                self.assertEqual(found["offset"], int(offset, 0))

    def test_every_file_its_table_names_reads_back_at_its_stated_length(self):
        table = self.image.directory
        self.assertGreater(len(table.entries), 0)
        for entry in table.entries:
            if entry.released:
                continue
            with self.subTest(name=entry.name):
                self.assertEqual(len(self.image.read(entry.name)), entry.size)


class AConsoleSOwnKeyvault(unittest.TestCase):
    """Skipped unless `XEBUILD_DUMP` and `XEBUILD_CPUKEY` name a dump and its key."""

    def setUp(self):
        where = os.environ.get("XEBUILD_DUMP", "")
        key = os.environ.get("XEBUILD_CPUKEY", "")
        if not os.path.isfile(where) or len(key.strip()) != 32:
            raise unittest.SkipTest("XEBUILD_DUMP and XEBUILD_CPUKEY are not both set")
        board, _ = for_name("trinity")
        with open(where, "rb") as handle:
            self.image = Image(handle.read(), board.flash)
        self.key = bytes.fromhex(key.strip())

    def test_it_opens_to_a_serial_and_seals_back_to_the_same_bytes(self):
        sealed = self.image.flat[0x4000:0x8000]
        found = Keyvault.opened(sealed, self.key)
        self.assertTrue(found.looks_opened, "the key does not open this keyvault")
        self.assertEqual(found.sealed(self.key), sealed)

    def test_the_serial_is_the_one_in_the_dump_s_own_name(self):
        wanted = os.environ.get("XEBUILD_SERIAL", "")
        if not wanted:
            raise unittest.SkipTest("XEBUILD_SERIAL does not say which console")
        found = Keyvault.opened(self.image.flat[0x4000:0x8000], self.key)
        self.assertEqual(found.serial, wanted)


class AConsoleSOwnMaterial(unittest.TestCase):
    """What a build is entitled to take from a dump. Skipped without `XEBUILD_DUMP`."""

    @classmethod
    def setUpClass(cls):
        where = os.environ.get("XEBUILD_DUMP", "")
        if not where or not os.path.isfile(where):
            raise unittest.SkipTest("XEBUILD_DUMP does not name a dump")
        board, bigffs = for_name(os.environ.get("XEBUILD_DUMP_BOARD", "trinity"))
        with open(where, "rb") as handle:
            cls.dump = Dump(handle.read(), board, bigffs)

    def test_the_sealed_smc_is_where_the_header_says_and_as_long_as_it_says(self):
        head = self.dump.header
        self.assertEqual(len(self.dump.smc), head.smc_size)
        self.assertEqual(self.dump.smc, self.dump.image.flat[0x1000:0x4000])

    def test_the_settings_block_is_sound(self):
        """A console in use has one: "found at offset 0xf7c000" on both measured."""
        self.assertEqual(len(self.dump.smc_config), 0x400)
        self.assertTrue(self.dump.smc_config_ok)

    def test_the_statistics_block_is_one_round_to_below_the_settings_block(self):
        flash = self.dump.flash
        at = flash.smc_config - flash.round_to
        self.assertEqual(len(self.dump.statistics), 0x1000)
        self.assertEqual(self.dump.statistics, self.dump.image.flat[at : at + 0x1000])

    def test_the_three_blocks_at_the_top_are_a_round_to_apart(self):
        """Measured on four shapes: the step is `round_to`, not 0x4000.

        On 16 MB those are the same number, which is what made it look like a constant;
        on both 64 MB shapes the step is 0x20000.
        """
        flash = self.dump.flash
        step = flash.round_to
        self.assertEqual(len(self.dump.smc_config), 0x400)
        self.assertEqual(len(self.dump.statistics), 0x1000)
        self.assertEqual(len(self.dump.manufacturing), 0x1000)
        at = flash.smc_config - 2 * step
        flat = self.dump.image.flat
        self.assertEqual(self.dump.manufacturing, flat[at : at + 0x1000])

    def test_a_console_need_not_keep_a_manufacturing_block(self):
        """`XEBUILD_MANUFACTURING` says which this console is, as `yes` or `no`.

        One of the two measured keeps one with its own serial in it and the other has
        that block erased, and the original reports it for exactly the first. Without
        the variable only the two answers being consistent is asserted.
        """
        written = self.dump.manufacturing_written
        self.assertEqual(written, set(self.dump.manufacturing) != {0xFF})
        wanted = os.environ.get("XEBUILD_MANUFACTURING", "").strip().lower()
        if wanted in ("yes", "no"):
            self.assertEqual(written, wanted == "yes")

    def test_the_security_files_are_files(self):
        """Every one the dump holds has a directory entry, and its size matches it."""
        entries = {one.name: one.size for one in self.dump.image.directory.entries}
        found = self.dump.security
        self.assertTrue(found, "a console in use carries at least one")
        for name, body in found.items():
            self.assertEqual(len(body), entries[name])

    def test_a_dump_whose_settings_block_is_spoilt_is_not_sound(self):
        """One byte inside the summed span, put back through the spare, and refused.

        The original agrees, on this dump: the same change gives "seeking smc config in
        dump...not found!".
        """
        flash = self.dump.flash
        raw = self.dump.image.raw
        flat = bytearray(self.dump.image.flat)
        flat[flash.smc_config + 0x10] ^= 0xFF
        spoilt = flash.unflatten(bytes(flat), order._spares(raw, flash))
        self.assertFalse(Dump(spoilt, self.dump.board).smc_config_ok)


class AnEmmcImageTheOriginalBuilt(unittest.TestCase):
    """Skipped unless `XEBUILD_EMMC` names one."""

    @classmethod
    def setUpClass(cls):
        where = os.environ.get("XEBUILD_EMMC", "")
        if not where or not os.path.isfile(where):
            raise unittest.SkipTest("XEBUILD_EMMC does not name an image")
        with open(where, "rb") as handle:
            cls.raw = handle.read()

    def test_both_anchors_parse_and_agree_about_everything_but_their_number(self):
        first = Anchor.parse(self.raw[anchors.AT[0] : anchors.AT[0] + anchors.LENGTH])
        second = Anchor.parse(self.raw[anchors.AT[1] : anchors.AT[1] + anchors.LENGTH])
        self.assertEqual((first.number, second.number), (1, 2))
        self.assertEqual(first.table, second.table)
        self.assertEqual(first.blobs, second.blobs)

    def test_laying_what_it_says_back_gives_the_same_bytes(self):
        """Into an image of our own, since one read from a file refuses to be written.

        Which makes this the stronger statement of the two: a 48 MB image assembled here
        from nothing but this file's own content comes out byte for byte as the original
        built it, anchors and all.
        """
        flash = for_name("corona4g")[0].flash
        one = Anchor.chosen(self.raw)
        image = Image.blank(flash)
        image.put(0, Image(self.raw, flash).flat)
        anchors.lay(image, one.table, one.blobs)
        self.assertEqual(image.raw, self.raw)

    def test_its_filesystem_reads(self):
        image = Image(self.raw, for_name("corona4g")[0].flash)
        entries = image.directory.entries
        self.assertTrue(entries)
        for entry in entries:
            self.assertEqual(len(image.read(entry.name)), entry.size)


class ThePackingAgainstAnImageTheOriginalBuilt(unittest.TestCase):
    """The whole of laying a filesystem, checked by rebuilding one image's table.

    Needs `XEBUILD_REFERENCE_IMAGE`, and `XEBUILD_REFERENCE_BOARD` when the console is
    not a trinity. Nothing about the packing is asserted here: the files come out of the
    reference, go back through `Filesystem` in the order it lists them, and the table
    that comes out either is the one the original wrote or it is not.
    """

    @classmethod
    def setUpClass(cls):
        where = os.environ.get("XEBUILD_REFERENCE_IMAGE", "")
        if not where or not os.path.isfile(where):
            raise unittest.SkipTest("XEBUILD_REFERENCE_IMAGE does not name an image")
        board, bigffs = for_name(os.environ.get("XEBUILD_REFERENCE_BOARD", "trinity"))
        cls.board, cls.bigffs = board, bigffs
        with open(where, "rb") as handle:
            cls.image = Image(handle.read(), board.flash, bigffs)

    def test_the_table_it_wrote_is_the_table_this_writes(self):
        from xebuild.build import Filesystem
        image, board = self.image, self.board
        theirs = image.directory
        base = board.flash.base_of(self.bigffs)
        at = image.blobs["fsroot"]["offset"] // 0x4000 - base
        ours = Filesystem(board.flash, first=theirs.entries[0].sector,
                          bigffs=self.bigffs, table_at=at)
        for entry in theirs.entries:
            ours.add(entry.name, image.read(entry.name), entry.stamp)
        self.assertEqual(ours.table(), image.blob("fsroot"))

    def test_the_table_sits_past_the_files_and_the_settings_blobs(self):
        """Four of them between the last file and the table on every image measured."""
        image, board = self.image, self.board
        table = image.directory
        last = max(max(table.blocks_of(one)) for one in table.entries)
        base = board.flash.base_of(self.bigffs)
        at = image.blobs["fsroot"]["offset"] // 0x4000 - base
        blobs = [k for k in image.blobs if k != "fsroot"]
        self.assertEqual(at, last + 1 + len(blobs))
