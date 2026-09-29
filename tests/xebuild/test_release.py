"""What a release says it is made of, and what is in it.

The made-up half writes file lists and patch files by hand and reads them back, and
builds a small signed package so the block arithmetic is exercised without a twelve
megabyte file. The measured half needs the real thing: `XEBUILD_RELEASE_DIR` naming a
release directory, and it checks every bootloader the release names against the checksum
the release states for it, which is a proof that needs no other tool.
"""

import os
import shutil
import struct
import hashlib
import binascii
import tempfile
import unittest

from xebuild.boards import for_name
from xebuild.imagetypes import for_name as type_for
from xebuild.release.recipe import Listed, canonical
from xebuild.release import Container, Patches, Recipe, Release

A_LIST = """\
[version]
17559

[trinitybl]
cba_9188.bin,5a76752d
cbb_9188.bin,febb1074;
cd_9452.bin,455fa02c
ce_1888.bin,ff9b60df
cf_17559.bin,0883e155
cg_17559.bin,10fbc84d

[trinitybl_WB]
cba_9188.bin,5a76752d
cbb_13182.bin,6899f9ab
cd_9452.bin,455fa02c
ce_1888.bin,ff9b60df
cf_17559.bin,0883e155
cg_17559.bin,10fbc84d

[falconbl]
cb_5770.bin,3279f0d5
none,00000000
cd_5770.bin,d04e8927

[security]
crl.bin,
dae.bin,

[flashfs]
dash.xex,d2089a4c
..\\launch.xex,
"""


class AFileList(unittest.TestCase):

    def setUp(self):
        self.recipe = Recipe(A_LIST)

    def test_the_version_and_the_sections(self):
        self.assertEqual(self.recipe.version, "17559")
        self.assertIn("trinitybl", self.recipe.sections)

    def test_the_section_is_named_after_the_console(self):
        board, _ = for_name("trinity")
        self.assertEqual(self.recipe.section_for(board), "trinitybl")
        self.assertEqual(len(self.recipe.stages(board)), 6)

    def test_an_extension_lengthens_the_name_rather_than_replacing_it(self):
        """Measured: `-c corona -r WB` reads `[coronabl_WB]`."""
        board, _ = for_name("trinity")
        self.assertEqual(self.recipe.section_for(board, "WB"), "trinitybl_WB")
        self.assertEqual(self.recipe.stages(board, "WB")[1].plain, "cbb_13182.bin")

    def test_a_section_that_is_not_there_is_refused_the_way_the_original_says_it(self):
        board, _ = for_name("winchester")
        with self.assertRaises(ValueError) as caught:
            self.recipe.stages(board)
        self.assertIn("[winchesterbl]", str(caught.exception))

    def test_a_semicolon_ends_a_line(self):
        """One line in two of the nine releases has one, and the original reads past."""
        board, _ = for_name("trinity")
        self.assertEqual(self.recipe.stages(board)[1].crc, 0xFEBB1074)

    def test_an_empty_slot_is_kept_rather_than_skipped(self):
        """A glitch chain has one CB, and the list still names six slots."""
        board, _ = for_name("falcon")
        stages = self.recipe.stages(board)
        self.assertEqual(len(stages), 3)
        self.assertTrue(stages[1].absent)
        self.assertFalse(stages[0].absent)

    def test_a_split_chain_is_read_from_the_section(self):
        trinity, _ = for_name("trinity")
        falcon, _ = for_name("falcon")
        self.assertTrue(self.recipe.dual_cb(trinity))
        self.assertFalse(self.recipe.dual_cb(falcon))

    def test_what_the_release_vouches_for_and_what_it_does_not(self):
        self.assertEqual(self.recipe.firmware[0].crc, 0xD2089A4C)
        self.assertIsNone(self.recipe.firmware[1].crc)
        self.assertTrue(self.recipe.firmware[1].outside)
        self.assertEqual([one.plain for one in self.recipe.security],
                         ["crl.bin", "dae.bin"])

    def test_a_checksum_that_is_not_one_is_refused(self):
        with self.assertRaises(ValueError):
            Recipe("[flashfs]\ndash.xex,not-a-number\n").firmware  # noqa: B018

    def test_nothing_is_read_as_a_stage_that_is_not_one(self):
        listed = Recipe("[flashfs]\ndash.xex,d2089a4c\n").firmware[0]
        self.assertEqual(listed.kind, "")


class AReleaseSFileList(unittest.TestCase):
    """`Release.recipe`, off a release directory made up in the test."""

    def test_one_with_no_version_label_is_refused(self):
        """Measured: "could not find label [version] in file list ini" (0x40952E)."""
        where = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, where)
        kind = type_for("glitch2")
        with open(os.path.join(where, kind.file_list("")), "w") as handle:
            handle.write("[trinitybl]\ncba_9188.bin,5a76752d\n")
        with self.assertRaisesRegex(ValueError, r"label \[version\]"):
            Release(where).recipe(kind)
        with open(os.path.join(where, kind.file_list("")), "w") as handle:
            handle.write("[version]\n17559\n\n[trinitybl]\ncba_9188.bin,5a76752d\n")
        self.assertEqual(Release(where).recipe(kind).version, "17559")


class WhatAListSaysBeyondItsFiles(unittest.TestCase):
    """Measured on made-up lists against the original."""

    def test_a_raw_patch_offset_is_decimal_unless_it_starts_0x(self):
        found = Recipe("[rawpatch]\na.bin,100000\nb.bin,0x100000\nc.bin,0X10\n")
        self.assertEqual(found.raw_patches,
                         (("a.bin", 100000), ("b.bin", 0x100000), ("c.bin", 0x10)))

    def test_a_raw_patch_with_no_offset_or_none_that_reads_is_refused(self):
        for line in ("a.bin", "a.bin,", "a.bin,f0000"):
            with self.subTest(line=line), self.assertRaises(ValueError):
                Recipe("[rawpatch]\n%s\n" % line).raw_patches  # noqa: B018

    def test_a_firmware_name_past_21_characters_is_refused(self):
        self.assertEqual(len(Recipe("[flashfs]\n%s.xex,0\n" % ("b" * 17)).firmware), 1)
        with self.assertRaisesRegex(ValueError, "greater than 21 chars"):
            Recipe("[flashfs]\n%s.xex,0\n" % ("c" * 18)).firmware  # noqa: B018


class TheFormAChecksumCovers(unittest.TestCase):
    """The release's own readme states this, and it is quoted at the site."""

    def a_stage(self, tag: str, length: int, stated: int = 0) -> bytes:
        out = bytearray(length)
        out[0:2] = tag.encode("latin-1")
        struct.pack_into(">I", out, 0x0C, stated or length)
        out[0x10:0x90] = bytes(range(1, 0x81))
        return bytes(out)

    def test_it_is_cut_to_the_size_the_stage_states(self):
        """Files are padded on disk and the padding is not part of the code."""
        body = self.a_stage("CD", 0x200, stated=0x100)
        self.assertEqual(len(canonical(body, "CD")), 0x100)

    def test_a_cb_blanks_its_nonce_and_the_pairing_beside_it(self):
        body = self.a_stage("CB", 0x100)
        self.assertEqual(canonical(body, "CBA")[0x10:0x40], bytes(0x30))
        self.assertNotEqual(canonical(body, "CBA")[0x40:0x44], bytes(4))

    def test_the_others_blank_the_nonce_alone(self):
        body = self.a_stage("CD", 0x100)
        for kind in ("CD", "CE", "CG", "SC", "SD", "SE"):
            with self.subTest(kind=kind):
                self.assertEqual(canonical(body, kind)[0x10:0x20], bytes(0x10))
                self.assertNotEqual(canonical(body, kind)[0x20:0x24], bytes(4))

    def test_a_cf_blanks_a_great_deal_more(self):
        body = self.a_stage("CF", 0x400)
        self.assertEqual(canonical(body, "CF")[0x20:0x230], bytes(0x210))

    def test_an_sb_is_left_alone_beyond_the_truncation(self):
        """Measured: every SB any release names answers as it stands."""
        body = self.a_stage("SB", 0x100)
        self.assertEqual(canonical(body, "SB")[0x10:0x20], body[0x10:0x20])

    def test_a_kind_it_does_not_know_is_only_cut(self):
        body = self.a_stage("ZZ", 0x200, stated=0x80)
        self.assertEqual(canonical(body, ""), body[:0x80])


class TheChecksABootloaderPasses(unittest.TestCase):
    """`Release._checked`: its stated length, its magic and its checksum, each
    refused as the original refuses it (0x429B30)."""

    def listed(self, name: str, body: bytes, crc: int | None = None) -> Listed:
        kind = Listed(name, "0").kind
        found = binascii.crc32(canonical(body, kind)) & 0xFFFFFFFF
        return Listed(name, "%08x" % (found if crc is None else crc))

    def test_a_stage_the_list_vouches_for_goes_through_as_it_came(self):
        body = TheFormAChecksumCovers().a_stage("CD", 0x100)
        self.assertEqual(Release._checked(self.listed("cd_1.bin", body), body), body)

    def test_a_changed_byte_is_refused_by_its_checksum(self):
        body = TheFormAChecksumCovers().a_stage("CD", 0x100)
        listed = self.listed("cd_1.bin", body)
        with self.assertRaisesRegex(ValueError, "BL crc check failed"):
            Release._checked(listed, body[:0x80] + b"\xff" + body[0x81:])

    def test_ffffffff_spares_only_an_sc_sd_or_se(self):
        body = TheFormAChecksumCovers().a_stage("SD", 0x100)
        self.assertEqual(Release._checked(self.listed("sd_1.bin", body, 0xFFFFFFFF),
                                          body), body)
        body = TheFormAChecksumCovers().a_stage("CD", 0x100)
        with self.assertRaisesRegex(ValueError, "BL crc check failed"):
            Release._checked(self.listed("cd_1.bin", body, 0xFFFFFFFF), body)

    def test_a_stated_length_past_the_file_is_refused(self):
        body = TheFormAChecksumCovers().a_stage("CD", 0x100, stated=0x110)
        with self.assertRaisesRegex(ValueError, "BL size"):
            Release._checked(self.listed("cd_1.bin", body), body)

    def test_a_magic_of_another_kind_is_refused(self):
        body = TheFormAChecksumCovers().a_stage("CE", 0x100)
        with self.assertRaisesRegex(ValueError, "BL magic check CE for CD"):
            Release._checked(self.listed("cd_1.bin", body), body)


class APatchFile(unittest.TestCase):

    def made(self, *sets) -> bytes:
        out = bytearray()
        for group in sets:
            for at, words in group:
                out += struct.pack(">II", at, len(words))
                out += struct.pack(">%dI" % len(words), *words)
            out += b"\xff\xff\xff\xff"
        return bytes(out)

    def test_the_records_and_the_sets(self):
        raw = self.made([(0x4DF4, (0x60000000,)), (0x4F50, (1, 2, 3))],
                        [(0x5660, (0x38600000,))])
        patches = Patches(raw)
        self.assertEqual(len(patches.sets), 2)
        self.assertEqual(len(patches.records), 3)
        self.assertEqual(patches.records[1].words, (1, 2, 3))
        self.assertEqual(patches.records[1].length, 12)

    def test_a_file_may_simply_stop_instead_of_saying_so(self):
        """The per-option files do: `nofcrt.bin` ends at its last record."""
        raw = struct.pack(">III", 0x1000, 1, 0xAABBCCDD)
        self.assertEqual(len(Patches(raw).records), 1)

    def test_a_record_running_past_the_end_is_refused(self):
        with self.assertRaises(ValueError):
            Patches(struct.pack(">II", 0x1000, 8) + bytes(4))

    def test_laying_one_over_a_body(self):
        raw = self.made([(0x10, (0xDEADBEEF,))])
        out = Patches(raw).over(bytes(0x20))
        self.assertEqual(out[0x10:0x14], bytes.fromhex("deadbeef"))
        self.assertEqual(out[:0x10], bytes(0x10))

    def test_one_that_does_not_fit_is_refused_rather_than_trimmed(self):
        raw = self.made([(0x100, (1,))])
        with self.assertRaises(ValueError):
            Patches(raw).over(bytes(0x20))

    def test_counting_from_somewhere_other_than_zero(self):
        raw = self.made([(0x8010, (0xDEADBEEF,))])
        out = Patches(raw).over(bytes(0x20), base=0x8000)
        self.assertEqual(out[0x10:0x14], bytes.fromhex("deadbeef"))

    def test_one_set_is_laid_and_the_others_are_left_alone(self):
        """A release's own file holds three, and they go to three different places:
        the first patches CB_B, the second CD, the third is not laid over anything."""
        raw = self.made([(0x00, (0x11111111,))], [(0x04, (0x22222222,))])
        out = Patches(raw).over(bytes(0x20), which=1)
        self.assertEqual(out[:8], bytes(4) + bytes.fromhex("22222222"))

    def test_a_set_comes_back_as_it_stands_with_its_sentinel(self):
        """An image's patch slot holds one verbatim, so it is handed over uncut."""
        raw = self.made([(0x00, (0x11111111,))], [(0x04, (0x22222222,))])
        patches = Patches(raw)
        self.assertEqual(patches.set_raw(1),
                         struct.pack(">III", 0x04, 1, 0x22222222) + b"\xff" * 4)

    def test_the_sets_put_back_together_are_the_file(self):
        """Nothing between them and nothing dropped, on a file of three."""
        raw = self.made([(0x00, (1,))], [(0x04, (2,))], [(0x08, (3, 4))])
        patches = Patches(raw)
        self.assertEqual(b"".join(patches.set_raw(one) for one in range(3)), raw)


class ASignedPackage(unittest.TestCase):
    """A small one, built here, so the block arithmetic is exercised."""

    BLOCK = 0x1000

    def a_package(self, files, wide=False) -> bytes:
        """`files` is a list of (name, bytes).

        Laid out block by block, because that is the thing being tested: the reader
        walks a file one block at a time and steps over the tables, so a writer that
        lays a whole file in one run leaves no room for them and the last blocks of a
        long file go missing. Which is what the first draft of this did.
        """
        rows, blocks, first = bytearray(), [], 1
        for name, body in files:
            padded = body.ljust(
                (len(body) + self.BLOCK - 1) // self.BLOCK * self.BLOCK, b"\x00"
            )
            count = len(padded) // self.BLOCK
            row = bytearray(0x40)
            row[: len(name)] = name.encode("latin-1")
            row[0x28] = 0x40 | len(name)
            row[0x29:0x2C] = count.to_bytes(3, "little")
            row[0x2F:0x32] = first.to_bytes(3, "little")
            struct.pack_into(">I", row, 0x34, len(body))
            rows += row
            blocks += [padded[n * self.BLOCK : (n + 1) * self.BLOCK]
                       for n in range(count)]
            first += count
        data = [bytes(rows).ljust(self.BLOCK, b"\x00"), *blocks]
        step = 2 if wide else 1

        def before(block):
            return ((block // 0xAA + 1) * step) if block >= 0xAA else 0

        out = bytearray(0xC000 + (len(data) + before(len(data)) + 2) * self.BLOCK)
        out[:4] = b"PIRS"
        out[0x411:0x411 + 0x18] = "A Package".encode("utf-16-be")
        out[0x379] = 0x24
        out[0x37B] = 1  # what a descriptor says, which is not what decides it
        struct.pack_into("<H", out, 0x37C, 1)
        out[0x37E:0x381] = (0).to_bytes(3, "little")
        for index, block in enumerate(data):
            at = 0xC000 + (index + before(index)) * self.BLOCK
            out[at : at + len(block)] = block
            # Each group of 0xAA blocks has its own table, laid just before the group.
            group = (index // 0xAA) * 0xAA
            table = 0xC000 + (group + before(group)) * self.BLOCK - step * self.BLOCK
            hash_at = table + (index % 0xAA) * 0x18
            out[hash_at : hash_at + 0x14] = hashlib.sha1(block).digest()
        return bytes(out)

    def test_it_lists_what_it_holds(self):
        raw = self.a_package([("$flash_dash.xex", b"hello" * 100)])
        package = Container(raw)
        self.assertEqual(package.name, "A Package")
        self.assertIn("$flash_dash.xex", package.held)
        self.assertEqual(package.firmware("dash.xex"), b"hello" * 100)

    def test_the_table_size_is_asked_of_the_package_and_not_of_its_descriptor(self):
        """Its descriptor says two blocks either way; only the hashes say which."""
        narrow = Container(self.a_package([("a", b"x" * 10)], wide=False))
        wide = Container(self.a_package([("a", b"x" * 10)], wide=True))
        self.assertFalse(narrow.wide)
        self.assertTrue(wide.wide)

    def test_a_block_past_the_first_table_is_still_found(self):
        """Which is the whole point of the arithmetic: 0xAA blocks in, it shifts."""
        body = bytes(range(256)) * (0xB0 * 0x10)
        raw = self.a_package([("big", body)])
        self.assertEqual(Container(raw).read("big"), body)

    def test_something_that_is_not_a_package(self):
        with self.assertRaises(ValueError):
            Container(b"NOPE" + bytes(0x10000))

    def test_a_file_it_does_not_hold(self):
        with self.assertRaises(ValueError):
            Container(self.a_package([("a", b"x")])).read("b")
