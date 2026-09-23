"""What an image says about itself, and what is in it.

Two kinds of test again. The made-up ones build a tiny flash from nothing -- four
blocks, one file, one table -- and drive the whole of reading an image over it, which is
fast and proves the mechanism. The measured ones need a console's own dump and check the
numbers the original prints for it: where each settings blob is, which version it is,
and how many files its table names. They are skipped unless `XEBUILD_DUMP` says where a
dump is.

The tiny flash is a class of its own rather than a real one, because a real 16 MB image
is thirty-two thousand pages and every one of them wants its code computed.
"""

import os
import struct
import unittest

from xebuild.boards import for_name
from xebuild.boards.flash import SmallNand
from xebuild.image import Anchor, Directory, Dump, Header, Image, Keyvault, order
from xebuild.image import anchor as anchors
from xebuild.image import dump as dumps

PAGE = 512


class TinyFlash(SmallNand):
    """Four blocks of a 16 MB console's flash, which is enough to hold a filesystem."""

    blocks = 4


def a_header(entrypoint: int = 0x8000) -> bytes:
    """The first page of an image, with the fields this reads and nothing else."""
    out = bytearray(PAGE)
    struct.pack_into(">HH", out, 0x00, 0xFF4F, 1888)
    struct.pack_into(">II", out, 0x08, entrypoint, 0x70000)
    struct.pack_into(">I", out, 0x60, 0x4000)  # keyvault size
    struct.pack_into(">I", out, 0x6C, 0x4000)  # keyvault at
    struct.pack_into(">I", out, 0x70, 0x10000)  # block size
    struct.pack_into(">I", out, 0x74, 0)  # smc config: unsaid
    struct.pack_into(">II", out, 0x78, 0x3000, 0x1000)  # smc size, smc at
    return bytes(out)


def a_table(files, blocks: int, following=None) -> bytes:
    """One filesystem table: even pages the block map, odd pages the entries."""
    following = following or {}
    words = bytearray(0x2000)
    for block, nxt in following.items():
        struct.pack_into(">H", words, block * 2, nxt)
    for block in range(blocks):
        if block not in following:
            struct.pack_into(">H", words, block * 2, 0x1FFF)
    rows = bytearray(0x2000)
    for index, (name, sector, size, stamp) in enumerate(files):
        row = bytearray(0x20)
        row[: len(name)] = name.encode("latin-1")
        struct.pack_into(">H", row, 0x16, sector)
        struct.pack_into(">II", row, 0x18, size, stamp)
        rows[index * 0x20 : (index + 1) * 0x20] = row
    out = bytearray()
    for page in range(16):
        out += words[page * PAGE : (page + 1) * PAGE]
        out += rows[page * PAGE : (page + 1) * PAGE]
    return bytes(out)


def an_image(version: int = 7) -> Image:
    """A whole tiny image: a header, one file, and a table naming it."""
    flash = TinyFlash()
    body = b"hello, console" * 64
    flat = bytearray(flash.length)
    flat[:PAGE] = a_header()
    flat[0x4000 : 0x4000 + len(body)] = body
    flat[0x8000 : 0xC000] = a_table(
        [("hello.bin", 1, len(body), 0x584B9226)], flash.blocks
    )
    spares = []
    for page in range(flash.length // PAGE):
        block = page // flash.spare.pages_a_block
        kind = 0x30 if block == 2 else 0
        spares.append(flash.spare.written(block, sequence=version, kind=kind))
    return Image(flash.unflatten(bytes(flat), spares), flash)


class WhatAnImageSaysAboutItself(unittest.TestCase):
    def test_the_fields_that_were_checked_against_the_original(self):
        header = Header(a_header())
        self.assertTrue(header.ok)
        self.assertEqual(header.magic, 0xFF4F)
        self.assertEqual(header.version, 1888)
        self.assertEqual(header.entrypoint, 0x8000)
        self.assertEqual(header.keyvault_at, 0x4000)
        self.assertEqual(header.keyvault_size, 0x4000)
        self.assertEqual(header.block_size, 0x10000)
        self.assertEqual(header.smc_at, 0x1000)
        self.assertEqual(header.smc_size, 0x3000)
        self.assertEqual(header.smc_config_at, 0)

    def test_anything_without_the_magic_is_not_an_image(self):
        self.assertFalse(Header(b"\x00" * PAGE).ok)
        self.assertFalse(Header(b"").ok)
        self.assertFalse(Header(b"\xff\x4f" + b"\x00" * 4).ok)

    def test_it_reads_the_bytes_where_they_are_rather_than_a_copy(self):
        """So a header read from an image being assembled answers with what is there."""
        body = bytearray(a_header())
        header = Header(body)
        struct.pack_into(">I", body, 0x08, 0xC000)
        self.assertEqual(header.entrypoint, 0xC000)


class TheFileTable(unittest.TestCase):
    def test_the_two_tables_are_interleaved_a_page_at_a_time(self):
        block = a_table([("one.bin", 1, 0x100, 0)], 4, following={1: 0x1FFF})
        table = Directory(block, 4)
        self.assertEqual(len(table.entries), 1)
        self.assertEqual(table.entries[0].name, "one.bin")
        self.assertEqual(len(table.map), 0x1000)

    def test_an_entry_says_where_how_long_and_when(self):
        block = a_table([("hud.xex", 0x237, 0x1D000, 0x584B9227)], 0x400)
        entry = Directory(block, 0x400).entries[0]
        self.assertEqual(entry.name, "hud.xex")
        self.assertEqual((entry.sector, entry.size), (0x237, 0x1D000))
        self.assertEqual(entry.stamp, 0x584B9227)
        self.assertFalse(entry.released)

    def test_a_chain_follows_the_map_and_stops_outside_the_flash(self):
        block = a_table([("two.bin", 1, 0x8000, 0)], 4, following={1: 2, 2: 0x1FFF})
        table = Directory(block, 4)
        self.assertEqual(table.chain(1), (1, 2))
        self.assertEqual(table.blocks_of(table.entries[0]), (1, 2))

    def test_a_chain_cut_to_what_the_entry_states(self):
        block = a_table([("one.bin", 1, 0x4000, 0)], 4, following={1: 2, 2: 0x1FFF})
        table = Directory(block, 4)
        self.assertEqual(table.chain(1), (1, 2))
        self.assertEqual(table.blocks_of(table.entries[0]), (1,))

    def test_a_map_that_points_back_does_not_loop_for_ever(self):
        block = a_table([("bad.bin", 1, 0x40000, 0)], 4, following={1: 2, 2: 1})
        self.assertEqual(Directory(block, 4).chain(1), (1, 2))

    def test_a_chain_stops_at_every_marker_there_is(self):
        """The four the original writes, and the one only a console writes.

        Read off an image the original built from nothing: RESERVED over the bootloader
        region and past the last usable block, FREE for an unused one, CHAIN_END for a
        file's last, and TABLE exactly once on the block the table sits in. 0x5FFE it
        never writes; both consoles here carry it.
        """
        # RESERVED, TABLE, FREE, CHAIN_END, as the original writes them
        for marker in (0x1FFB, 0x1FFD, 0x1FFE, 0x1FFF):
            with self.subTest(marker=hex(marker)):
                block = a_table([("two.bin", 1, 0x8000, 0)], 4,
                                following={1: 2, 2: marker})
                self.assertEqual(Directory(block, 4).chain(1), (1, 2))

    def test_a_console_s_flags_are_not_part_of_the_block(self):
        """Measured, and it decides whether an older copy of a table reads at all.

        A console sets bits above the thirteen that name the block. One table's version
        166 carries two hundred and thirty-five such words, and reading them whole gives
        the wrong length for thirteen of its twenty-six files where masking gives the
        right length for all of them. The values seen: 0x83BF, which is block 0x3BF with
        bit 15 set; 0x9FFF, which is CHAIN_END with the same bit; and 0x5FFE, which is
        FREE with bit 14.
        """
        block = a_table([("two.bin", 1, 0x8000, 0)], 4,
                        following={1: 0x8000 | 2, 2: 0x9FFF})
        self.assertEqual(Directory(block, 4).chain(1), (1, 2))
        block = a_table([("one.bin", 1, 0x4000, 0)], 4, following={1: 0x5FFE})
        self.assertEqual(Directory(block, 4).chain(1), (1,))

    def test_a_name_beginning_with_five_is_one_the_filesystem_let_go(self):
        block = a_table([("\x05ystemupdate.xex", 0x3BE, 0x43000, 0)], 0x400)
        entry = Directory(block, 0x400).entries[0]
        self.assertTrue(entry.released)
        self.assertEqual(entry.name, "\x05ystemupdate.xex")

    def test_an_entry_pointing_outside_the_flash_is_no_entry(self):
        block = a_table([("far.bin", 0x800, 0x100, 0)], 4)
        self.assertEqual(Directory(block, 4).entries, ())


class WhatIsInAnImage(unittest.TestCase):
    def test_the_table_is_found_by_scanning_for_its_kind(self):
        image = an_image(version=7)
        found = image.blobs["fsroot"]
        self.assertEqual(found["version"], 7)
        self.assertEqual(found["offset"], 0x8000)
        self.assertEqual(found["length"], 0x4000)

    def test_a_blob_comes_back_whole(self):
        image = an_image()
        self.assertEqual(len(image.blob("fsroot")), 0x4000)

    def test_the_file_the_table_names_reads_back(self):
        image = an_image()
        body = image.read("hello.bin")
        self.assertEqual(body, b"hello, console" * 64)

    def test_a_file_that_is_not_there(self):
        with self.assertRaises(ValueError):
            an_image().read("nothing.bin")

    def test_a_wide_version_survives_the_scan(self):
        """The reason a version is read as two bytes: 626 is a real one."""
        self.assertEqual(an_image(version=626).blobs["fsroot"]["version"], 626)

    def test_a_block_is_read_from_where_it_is_and_not_from_where_it_says(self):
        """The boundary of this class, and it is deliberate.

        The block number in a page's spare is not consulted when a file is read: the
        table names block 1 and block 1 is what is read. A dump whose blocks sit
        elsewhere is put in order first, by something else -- the original does the same
        thing in the same order, saying "copying nanddump data from block 0x%x to block
        0x%x for file extraction integrity" before it extracts anything.
        """
        flash = TinyFlash()
        body = b"where it is" * 8
        flat = bytearray(flash.length)
        flat[:PAGE] = a_header()
        flat[0x4000 : 0x4000 + len(body)] = body
        flat[0x8000 : 0xC000] = a_table(
            [("one.bin", 1, len(body), 0)], flash.blocks
        )
        spares = []
        for page in range(flash.length // PAGE):
            block = page // flash.spare.pages_a_block
            # every block claims to be somewhere else, as one dump measured does
            claimed = (block * 4) % flash.blocks
            kind = 0x30 if block == 2 else 0
            spares.append(flash.spare.written(claimed, sequence=1, kind=kind))
        image = Image(flash.unflatten(bytes(flat), spares), flash)
        self.assertEqual(image.read("one.bin"), body)

    def test_an_emmc_image_with_no_sound_anchor_names_no_filesystem(self):
        """It has no spare to scan, so an anchor is the only thing that could say."""
        board, _ = for_name("corona4g")
        image = Image(b"\x00" * 0x8000, board.flash)
        with self.assertRaises(ValueError):
            image.blobs  # noqa: B018


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


if __name__ == "__main__":
    unittest.main()


class AConsoleSOwnSecrets(unittest.TestCase):
    """The keyvault, which opens with one console's key and no other."""

    KEY = bytes.fromhex("00112233445566778899aabbccddeeff")

    def a_keyvault(self, serial="123456789012", made="10-21-10",
                   dvd=b"\xab" * 16, hashed=True):
        plain = bytearray(0x4000)
        plain[0xB0:0xBC] = serial.encode("latin-1")
        plain[0x100:0x110] = dvd
        plain[0x9E4:0x9EC] = made.encode("latin-1")
        if hashed:
            plain[0x1DF8:0x1E08] = b"\x5a" * 16
        return Keyvault(bytes(plain))

    def test_what_it_says_about_the_console(self):
        made = self.a_keyvault()
        self.assertEqual(made.serial, "123456789012")
        self.assertEqual(made.made_on, "10-21-10")
        self.assertEqual(made.dvd_key, b"\xab" * 16)
        self.assertTrue(made.looks_opened)

    def test_sealing_and_opening_come_back_to_the_same_bytes(self):
        one = self.a_keyvault()
        sealed = one.sealed(self.KEY)
        self.assertEqual(len(sealed), 0x4000)
        self.assertNotEqual(sealed[0x100:0x110], b"\xab" * 16)
        again = Keyvault.opened(sealed, self.KEY)
        self.assertEqual(again.plain[0x10:], one.plain[0x10:])
        self.assertEqual(again.serial, "123456789012")

    def test_the_nonce_is_derived_so_sealing_twice_gives_the_same_bytes(self):
        """Measured on two consoles: the nonce is HMAC(cpu key, plaintext + 07 12).

        It matters because it means a rebuilt image carries the console's own keyvault
        bytes exactly, with nothing taken from the dump to make it so.
        """
        one = self.a_keyvault()
        self.assertEqual(one.sealed(self.KEY), one.sealed(self.KEY))
        other = bytes(byte ^ 1 for byte in self.KEY)
        self.assertNotEqual(one.sealed(self.KEY)[:0x10], one.sealed(other)[:0x10])

    def test_the_wrong_key_opens_it_to_nothing_that_reads_as_a_serial(self):
        sealed = self.a_keyvault().sealed(self.KEY)
        wrong = Keyvault.opened(sealed, bytes(byte ^ 1 for byte in self.KEY))
        self.assertFalse(wrong.looks_opened)

    def test_the_two_kinds_the_original_names(self):
        self.assertTrue(self.a_keyvault(hashed=True).hashed)
        self.assertFalse(self.a_keyvault(hashed=False).hashed)

    def test_all_ones_is_no_hash_either(self):
        """Its own test: type 2 the moment a word is neither zero nor all ones."""
        plain = bytearray(0x4000)
        plain[0x1DF8:0x1E08] = b"\xff" * 16
        self.assertFalse(Keyvault(bytes(plain)).hashed)


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


class PuttingBlocksBackWhereTheyBelong(unittest.TestCase):
    """Every rule here was measured by handing the original a dump made for the purpose.

    A tiny flash again, but one with a pool: eight blocks of which five may be used, so
    blocks 6 and 7 are where a replacement may live.
    """

    class PooledFlash(SmallNand):
        blocks = 8
        last_block = 5

    def a_dump(self):
        """Eight blocks, each holding its own number and claiming it in its spare."""
        flash = self.PooledFlash()
        step, per = PAGE + flash.spare.length, flash.spare.pages_a_block
        out = bytearray()
        for block in range(flash.blocks):
            data = bytes([block]) * PAGE
            fields = flash.spare.written(block, sequence=1, kind=0)
            out += (data + flash.spare.with_ecc(data, fields)) * per
        return bytes(out), flash, step, per

    def mark_bad(self, raw, flash, block, step, per):
        out = bytearray(raw)
        for page in range(per):
            at = (block * per + page) * step
            fields = bytearray(out[at + PAGE : at + step])
            fields[flash.spare.mark_at] = 0x00
            data = out[at : at + PAGE]
            out[at + PAGE : at + step] = flash.spare.with_ecc(data, fields)
        return bytes(out)

    def stand_in(self, raw, flash, bad, pool, step, per):
        """Put the bad block's data in the pool, claiming the bad block's number."""
        out = bytearray(raw)
        for page in range(per):
            at = (pool * per + page) * step
            data = bytes([bad]) * PAGE
            fields = flash.spare.written(bad, sequence=1, kind=0)
            out[at : at + PAGE] = data
            out[at + PAGE : at + step] = flash.spare.with_ecc(data, fields)
        return bytes(out)

    def test_a_dump_whose_blocks_are_all_in_place_comes_back_unchanged(self):
        """Which is every dump off a console that has never replaced a block."""
        raw, flash, _, _ = self.a_dump()
        self.assertEqual(order.logical(raw, flash), raw)
        self.assertEqual(order.marked_bad(raw, flash), ())
        self.assertEqual(order.failing(raw, flash), ())
        self.assertEqual(order.replacements(raw, flash), {})

    def test_a_block_the_chip_wrote_off_is_found(self):
        raw, flash, step, per = self.a_dump()
        raw = self.mark_bad(raw, flash, 3, step, per)
        self.assertEqual(order.marked_bad(raw, flash), (3,))

    def test_its_contents_come_from_the_pool(self):
        """What the original does: "copying nanddump data from block X to block Y"."""
        raw, flash, step, per = self.a_dump()
        raw = self.mark_bad(raw, flash, 3, step, per)
        raw = self.stand_in(raw, flash, 3, 7, step, per)
        self.assertEqual(order.replacements(raw, flash), {3: 7})
        span = step * per
        out = order.logical(raw, flash)
        self.assertEqual(out[3 * span : 4 * span], raw[7 * span : 8 * span])

    def test_a_block_claiming_another_s_number_outside_the_pool_is_no_replacement(self):
        """The original turns one away: "bad LBA at block 0x387, block LBA ignored"."""
        raw, flash, step, per = self.a_dump()
        raw = self.mark_bad(raw, flash, 3, step, per)
        raw = self.stand_in(raw, flash, 3, 4, step, per)  # 4 is inside the usable area
        self.assertEqual(order.replacements(raw, flash), {})
        self.assertEqual(order.logical(raw, flash), raw)

    def test_a_page_whose_code_no_longer_fits_its_data_moves_the_block(self):
        """One flipped byte: "ECD error at block 0x2a, block will be remapped"."""
        raw, flash, step, per = self.a_dump()
        broken = bytearray(raw)
        broken[(3 * per + 1) * step + 100] ^= 0x01
        self.assertEqual(order.failing(bytes(broken), flash), (3,))

    def test_what_the_two_options_turn_off(self):
        raw, flash, step, per = self.a_dump()
        with_bad = self.stand_in(self.mark_bad(raw, flash, 3, step, per),
                                 flash, 3, 7, step, per)
        self.assertNotEqual(order.logical(with_bad, flash), with_bad)
        self.assertEqual(order.logical(with_bad, flash, remap=False), with_bad)
        broken = bytearray(raw)
        broken[(3 * per + 1) * step + 100] ^= 0x01
        self.assertEqual(order.logical(bytes(broken), flash, ecd=False), bytes(broken))

    def test_an_emmc_image_has_nothing_to_put_in_order(self):
        board, _ = for_name("corona4g")
        flat = b"\x5a" * 0x8000
        self.assertEqual(order.logical(flat, board.flash), flat)


def an_emmc_image(blobs=None, files=None) -> bytes:
    """A 48 MB eMMC image: a header, a file, a table, and both anchors naming them.

    Written whole rather than as a class of its own, the way the NAND tests do it,
    because an anchor sits at a fixed offset near the top of the flash and a smaller
    image has nowhere to put one.
    """
    board, _ = for_name("corona4g")
    flash = board.flash
    body = b"no spare here" * 32
    flat = bytearray(flash.length)
    flat[:PAGE] = a_header()
    flat[0x4000 : 0x4000 + len(body)] = body
    table_block = 0x380
    flat[table_block * 0x4000 : (table_block + 1) * 0x4000] = a_table(
        files if files is not None else [("plain.bin", 1, len(body), 0)], flash.blocks
    )
    return anchors.lay(bytes(flat), table_block, blobs or {})


class AnAnchorBlock(unittest.TestCase):
    """The structure an eMMC image says where everything went in."""

    def test_it_survives_being_written_and_read_again(self):
        one = Anchor(2, 0x390, {0x31: (0x38C, 0x800), 0x34: (0x38F, 0x200)})
        again = Anchor.parse(one.encoded)
        self.assertEqual(again.number, 2)
        self.assertEqual(again.table, 0x390)
        self.assertEqual(again.blobs, {0x31: (0x38C, 0x800), 0x34: (0x38F, 0x200)})

    def test_a_slot_is_a_kind_and_a_gap_stays_a_gap(self):
        """Measured: built with only MobileC and MobileE, slots 1 and 3 are filled."""
        one = Anchor(1, 0x38E, {0x32: (0x38C, 0x200), 0x34: (0x38D, 0x800)})
        block = one.encoded
        self.assertEqual(struct.unpack_from(">HH", block, 0x20), (0, 0))
        self.assertEqual(struct.unpack_from(">HH", block, 0x24), (0x38C, 0x200))
        self.assertEqual(struct.unpack_from(">HH", block, 0x28), (0, 0))
        self.assertEqual(struct.unpack_from(">HH", block, 0x2C), (0x38D, 0x800))

    def test_a_hash_that_does_not_match_is_refused(self):
        block = bytearray(Anchor(1, 0x390, {}).encoded)
        block[0x20] ^= 0xFF
        with self.assertRaises(ValueError):
            Anchor.parse(bytes(block))

    def test_the_number_decides_and_not_the_position(self):
        """Measured: with 2 in the first block the original selects the first."""
        image = bytearray(0x3000000)
        first, second = anchors.AT
        image[first : first + anchors.LENGTH] = Anchor(2, 0x111, {}).encoded
        image[second : second + anchors.LENGTH] = Anchor(1, 0x222, {}).encoded
        self.assertEqual(Anchor.chosen(bytes(image)).table, 0x111)
        image[first : first + anchors.LENGTH] = Anchor(1, 0x111, {}).encoded
        image[second : second + anchors.LENGTH] = Anchor(2, 0x222, {}).encoded
        self.assertEqual(Anchor.chosen(bytes(image)).table, 0x222)

    def test_a_number_that_is_neither_one_nor_two_is_not_policed(self):
        """Measured: an anchor numbered 9 is accepted, and it wins."""
        image = bytearray(0x3000000)
        first, second = anchors.AT
        image[first : first + anchors.LENGTH] = Anchor(9, 0x111, {}).encoded
        image[second : second + anchors.LENGTH] = Anchor(2, 0x222, {}).encoded
        self.assertEqual(Anchor.chosen(bytes(image)).number, 9)

    def test_one_sound_copy_is_enough(self):
        image = bytearray(an_emmc_image())
        image[anchors.AT[1]] ^= 0xFF
        self.assertEqual(Anchor.chosen(bytes(image)).number, 1)

    def test_neither_copy_sound_is_a_refusal(self):
        image = bytearray(an_emmc_image())
        for at in anchors.AT:
            image[at] ^= 0xFF
        with self.assertRaises(ValueError):
            Anchor.chosen(bytes(image))

    def test_laying_them_leaves_the_rest_of_the_block_alone(self):
        """An image the original built has zeros to 0x1000 and erased flash past it."""
        image = bytearray(b"\xff" * 0x3000000)
        laid = anchors.lay(bytes(image), 0x380, {})
        for at in anchors.AT:
            self.assertEqual(set(laid[at + anchors.LENGTH : at + 0x1000]), {0})
            self.assertEqual(set(laid[at + 0x1000 : at + 0x4000]), {0xFF})

    def test_an_anchor_that_would_not_fit_is_refused(self):
        with self.assertRaises(ValueError):
            anchors.lay(b"\x00" * 0x1000, 0x380, {})


class AnEmmcImageReadsThroughItsAnchor(unittest.TestCase):
    def test_the_table_comes_from_the_anchor_and_not_from_a_scan(self):
        image = Image(an_emmc_image(), for_name("corona4g")[0].flash)
        self.assertEqual(image.blobs["fsroot"]["offset"], 0x380 * 0x4000)
        self.assertEqual(image.blobs["fsroot"]["length"], 0x4000)
        self.assertEqual(image.read("plain.bin"), b"no spare here" * 32)

    def test_a_version_is_not_in_an_anchor_so_one_is_reported(self):
        """Measured: the original reports version 1 for every blob it reads this way."""
        image = Image(an_emmc_image(), for_name("corona4g")[0].flash)
        self.assertEqual(image.blobs["fsroot"]["version"], 1)

    def test_the_blobs_an_anchor_names_come_back_under_the_console_s_names(self):
        raw = an_emmc_image(blobs={0x31: (0x300, 0x800), 0x33: (0x301, 0x200)})
        image = Image(raw, for_name("corona4g")[0].flash)
        self.assertEqual(sorted(image.blobs), ["MobileB.dat", "MobileD.dat", "fsroot"])
        self.assertEqual(image.blobs["MobileB.dat"]["offset"], 0x300 * 0x4000)
        self.assertEqual(image.blobs["MobileD.dat"]["length"], 0x200)


class TheSettingsBlockSChecksum(unittest.TestCase):
    """The one thing the original checks before it will use a dump's settings block."""

    def test_a_block_is_sound_when_its_head_holds_the_complement_of_the_sum(self):
        block = bytearray(0x400)
        block[0x10:0x110] = bytes(range(0x100))
        head = dumps.checksum(block)
        block[:2] = head.to_bytes(2, "little")
        self.assertEqual(int.from_bytes(block[:2], "little"), dumps.checksum(block))

    def test_the_span_ends_at_0x10c(self):
        """Measured: 0x10B changes it, 0x10C does not, both checked on the original."""
        block = bytearray(0x400)
        block[0x10:] = bytes(0x3F0)
        was = dumps.checksum(block)
        inside = bytearray(block)
        inside[0x10B] ^= 0xFF
        self.assertNotEqual(dumps.checksum(inside), was)
        outside = bytearray(block)
        outside[0x10C] ^= 0xFF
        self.assertEqual(dumps.checksum(outside), was)

    def test_the_bytes_before_the_span_are_outside_it(self):
        """Which is why the zero pair and the 05 21 beside it can be overwritten."""
        block = bytearray(0x400)
        was = dumps.checksum(block)
        for at in (0x02, 0x08, 0x0E, 0x0F):
            other = bytearray(block)
            other[at] ^= 0xFF
            self.assertEqual(dumps.checksum(other), was)


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
        one = Anchor.chosen(self.raw)
        self.assertEqual(anchors.lay(self.raw, one.table, one.blobs), self.raw)

    def test_its_filesystem_reads(self):
        image = Image(self.raw, for_name("corona4g")[0].flash)
        entries = image.directory.entries
        self.assertTrue(entries)
        for entry in entries:
            self.assertEqual(len(image.read(entry.name)), entry.size)
