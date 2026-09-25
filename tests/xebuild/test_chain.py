"""The bootloader chain, made up and measured.

The made-up half builds a tiny chain in memory -- a few stage headers laid one after
another -- and drives walking, the slots and the keying over it. The measured half needs
a console's own dump and checks the numbers the original prints for it: the stages and
their offsets, the pairing and the lockdown value, and the field in CB_B that ties the
chain to the SMC beside it. Skipped unless `XEBUILD_DUMP` says where a dump is.
"""

import struct
import unittest

from xebuild.boards import for_name
from xebuild.chain import Chain, Fields, fuses, sealing, update
from xebuild.chain.stage import Stage
from xebuild.crypto.formats import decrypt_bootloader
from xebuild.crypto.keys import hmacsha
from xebuild.crypto.rc4 import rc4


def opened_under_the_1bl_key(stage):
    """A CF-sealed stage opened, header and all: the key HMAC(1BL key, its nonce)."""
    return stage.head + decrypt_bootloader(stage.body,
                                           hmacsha(sealing.ONE_BL_KEY, stage.nonce))


def a_stage(tag: str, length: int, build: int = 0x1000, flags: int = 0,
            nonce: bytes = b"") -> bytes:
    """One stage: its header, its nonce where its kind keeps it, then filler."""
    out = bytearray(length)
    out[0:2] = tag.encode("latin-1")
    struct.pack_into(">HHH", out, 0x02, build, 0, flags)
    struct.pack_into(">II", out, 0x08, 0x3C0, length)
    at = 0x20 if tag == "CF" else 0x10
    out[at : at + 0x10] = (nonce or bytes(range(0x10)))
    return bytes(out)


class AStageSHeader(unittest.TestCase):

    def test_the_fields_measured_on_two_consoles(self):
        one = Stage(a_stage("CB", 0x100, build=0x23E4, flags=0x0800), 0)
        self.assertEqual(one.tag, "CB")
        self.assertEqual(one.build, 0x23E4)
        self.assertEqual(one.word_at_04, 0)
        self.assertEqual(one.flags, 0x0800)
        self.assertEqual(one.entrypoint, 0x3C0)
        self.assertEqual(one.length, 0x100)
        self.assertTrue(one.dual)
        self.assertFalse(one.manufacturing)

    def test_the_flag_that_names_the_manufacturing_regime(self):
        """0x0800 against 0x0801 is the whole difference between two shipped CB_As."""
        self.assertFalse(Stage(a_stage("CB", 0x100, flags=0x0800), 0).manufacturing)
        self.assertTrue(Stage(a_stage("CB", 0x100, flags=0x0801), 0).manufacturing)

    def test_a_cf_keeps_its_nonce_and_body_somewhere_else(self):
        """Measured: 0x20 and 0x30, where every other kind has 0x10 and 0x20."""
        nonce = bytes(range(0x20, 0x30))
        self.assertEqual(Stage(a_stage("CF", 0x400, nonce=nonce), 0).nonce, nonce)
        self.assertEqual(Stage(a_stage("CF", 0x400), 0).shape, (0x20, 0x30))
        self.assertEqual(Stage(a_stage("CD", 0x400), 0).shape, (0x10, 0x20))

    def test_the_glitch_bootloader_an_exploit_inserts(self):
        self.assertTrue(Stage(a_stage("CB", 0x400, build=15432), 0).payload)
        self.assertFalse(Stage(a_stage("CB", 0x400, build=0x23E4), 0).payload)

    def test_what_is_not_a_stage(self):
        self.assertFalse(Stage(b"\x00" * 0x40, 0).looks_like_a_stage)
        self.assertFalse(Stage(b"CB", 0).looks_like_a_stage)
        # a length of zero would walk on the spot for ever
        self.assertFalse(Stage(a_stage("CB", 0x100)[:0x20] + bytes(0x20), 0)
                         .looks_like_a_stage)


class WritingWhatAStageCarries(unittest.TestCase):
    """The write sides, beside the read sides they have to agree with.

    There is no separate sealing function and there should not be: RC4 is symmetric, so
    the same pass that opens a stage closes it. Measured on a real console: all four of
    its stages, opened and run through again under the same key, come back as the bytes
    the flash holds.
    """

    def test_a_nonce_is_written_where_its_kind_keeps_it(self):
        given = bytes(range(0x30, 0x40))
        for tag, at in (("CD", 0x10), ("CF", 0x20)):
            with self.subTest(tag=tag):
                one = Stage(bytearray(a_stage(tag, 0x400)), 0)
                one.nonce = given
                self.assertEqual(one.nonce, given)
                self.assertEqual(one.image[at : at + 0x10], given)

    def test_a_nonce_that_is_not_sixteen_bytes_is_refused(self):
        one = Stage(bytearray(a_stage("CD", 0x400)), 0)
        for given in (b"", bytes(15), bytes(17)):
            with self.subTest(given=len(given)), self.assertRaises(ValueError):
                one.nonce = given

    def test_a_stage_over_bytes_that_cannot_be_written_says_so(self):
        with self.assertRaises(ValueError) as caught:
            Stage(a_stage("CD", 0x400), 0).nonce = bytes(0x10)
        self.assertIn("bytearray", str(caught.exception))

    def test_the_fields_a_stage_carries_for_one_console(self):
        cpu, key, x = bytes(range(0x10)), bytes(0x10), bytes(range(0x10, 0x20))
        out = Fields.write(bytes.fromhex("780227"), cpu, key, x)
        self.assertEqual(len(out), 0x20)
        one = Fields(out)
        self.assertEqual(one.pairing, bytes.fromhex("780227"))
        self.assertEqual(one.ldv, 0)
        self.assertTrue(one.agrees(cpu, key, x))

    def test_the_lockdown_byte_is_left_at_zero_because_a_cb_b_leaves_it(self):
        """Measured on a console's own CB_B and on two reference images: the pairing is
        written and the byte after it is not, while the same console's CF states 14."""
        nothing = bytes(0x10)
        out = Fields.write(bytes.fromhex("780227"), nothing, nothing, nothing)
        self.assertEqual(out[0x03], 0)
        self.assertEqual(out[0x04:0x10], bytes(12))

    def test_no_key_leaves_the_binding_zero_as_the_manufacturing_regime_does(self):
        out = Fields.write(bytes.fromhex("780227"))
        self.assertEqual(out[0x10:0x20], bytes(0x10))
        self.assertEqual(out[0x00:0x03], bytes.fromhex("780227"))

    def test_a_pairing_that_is_not_three_bytes_is_refused(self):
        for given in (b"", bytes(2), bytes(4)):
            with self.subTest(given=len(given)), self.assertRaises(ValueError):
                Fields.write(given)


class TheSealing(unittest.TestCase):

    def test_the_public_key_and_the_sum_the_original_states(self):
        self.assertEqual(sealing.key_sum(sealing.ONE_BL_KEY), 0x983)

    def test_a_split_cb_binds_on_its_second_half(self):
        stages = [Stage(a_stage(tag, 0x100), 0) for tag in ("CB", "CB", "CD")]
        self.assertEqual(sealing.binding_at(stages), 1)

    def test_a_single_cb_chain_binds_nowhere(self):
        """A JTAG chain, measured: every stage keys from its nonce alone."""
        stages = [Stage(a_stage(tag, 0x100), 0) for tag in ("CB", "CD", "CE")]
        self.assertEqual(sealing.binding_at(stages), -1)
        keys = sealing.keys(stages)
        self.assertTrue(all(one is not None for one in keys))

    def test_without_a_cpu_key_nothing_past_the_binding_opens(self):
        stages = [Stage(a_stage(tag, 0x100), 0) for tag in ("CB", "CB", "CD", "CE")]
        keys = sealing.keys(stages)
        self.assertIsNotNone(keys[0])
        self.assertEqual(keys[1:], (None, None, None))

    def test_the_manufacturing_regime_puts_zeros_where_the_key_goes(self):
        plain = [Stage(a_stage("CB", 0x100, flags=0x0800), 0)]
        mfg = [Stage(a_stage("CB", 0x100, flags=0x0801), 0)]
        second = Stage(a_stage("CB", 0x100), 0)
        cpu = bytes(range(0x10))
        self.assertEqual(sealing.message_for(second, cpu, mfg[0]),
                         second.nonce + bytes(0x10))
        self.assertEqual(sealing.message_for(second, cpu, plain[0]),
                         second.nonce + cpu)

    def test_the_later_regime_folds_in_the_first_head_with_its_flags_blanked(self):
        first = Stage(a_stage("CB", 0x100, flags=0x1000), 0)
        second = Stage(a_stage("CB", 0x100), 0)
        cpu = bytes(range(0x10))
        message = sealing.message_for(second, cpu, first)
        self.assertEqual(len(message), 0x10 + len(cpu) + 0x10)
        self.assertEqual(message[-0x10 + 0x06 : -0x10 + 0x08], bytes(2))

    def test_a_second_pass_is_asked_for_and_never_assumed(self):
        """One image type on one chain shape takes it -- retail, with no CB_B -- and
        nothing in a chain states the image type, so it is the caller's to name.

        Deciding it from the board instead made every chain on a fat board unreadable
        from CD down, so the first half of this is the regression that mattered: with
        nothing said, no stage is keyed twice.
        """
        stages = [Stage(a_stage(tag, 0x100), 0) for tag in ("CB", "CD", "CE")]
        cpu = bytes(range(0x10))
        ordinary = sealing.keys(stages, cpu)
        asked = sealing.keys(stages, cpu, second_pass_at=1)
        self.assertEqual(ordinary[0], asked[0])
        self.assertEqual(asked[1], hmacsha(cpu, ordinary[1]))
        self.assertNotEqual(ordinary[1], asked[1])

    def test_the_pass_carries_forward_to_the_stage_behind_it(self):
        """The key that comes out is the secret the next stage derives from."""
        stages = [Stage(a_stage(tag, 0x100), 0) for tag in ("CB", "CD", "CE")]
        cpu = bytes(range(0x10))
        asked = sealing.keys(stages, cpu, second_pass_at=1)
        self.assertEqual(asked[2], hmacsha(asked[1], stages[2].nonce))

    def test_a_second_pass_without_a_console_key_is_refused(self):
        stages = [Stage(a_stage(tag, 0x100), 0) for tag in ("CB", "CD")]
        with self.assertRaises(ValueError):
            sealing.keys(stages, b"", second_pass_at=1)

    def test_code_reads_as_open_and_sealed_bytes_do_not(self):
        """Entropy, with the numbers this bench measured either side of it."""
        self.assertTrue(sealing.looks_open("CB", bytes(0x2000)))
        self.assertFalse(sealing.looks_open("CB", rc4(b"key", bytes(0x2000))))

    def test_a_ce_is_judged_on_its_header_and_not_on_entropy(self):
        """Its plaintext is a compressed kernel, so entropy calls a right key wrong."""
        opened = bytearray(0x40)
        struct.pack_into(">II", opened, 8, 0x120000, 0)
        self.assertTrue(sealing.looks_open("CE", bytes(opened)))
        struct.pack_into(">II", opened, 8, 0xDF59448, 0x9B39D69D)
        self.assertFalse(sealing.looks_open("CE", bytes(opened)))


class AMadeUpChain(unittest.TestCase):
    """A flash with a few stage headers in it, and nothing else."""

    class Sham:
        """The least an image can be for a chain to walk it."""

        class Head:
            def __init__(self, entrypoint, size):
                self.entrypoint, self.size = entrypoint, size

        def __init__(self, flat, entrypoint, size):
            self.flat = flat
            self.header = self.Head(entrypoint, size)

    def an_image(self, kinds, slots=1, lockdowns=()):
        """A flash with a chain and some slots.

        `lockdowns` gives each slot the lockdown value it should state, which means
        sealing its body the way a console's is: the pairing is set to the slot's number
        repeated, so a test can see which slot an answer came from.
        """
        board, _ = for_name("trinity")
        flat = bytearray(0x200000)
        at = 0x8000
        for tag, length, build, *nonce in kinds:
            flat[at : at + length] = a_stage(tag, length, build=build,
                                             nonce=nonce[0] if nonce else b"")
            at += length
        slots_at = 0x100000
        for index in range(slots):
            where = slots_at + index * board.flash.block_size
            one = bytearray(a_stage("CF", 0x400, build=0x4400 + index))
            if index < len(lockdowns):
                plain = bytearray(one)
                plain[0x21C:0x21F] = bytes([index + 1]) * 3
                plain[0x21F] = lockdowns[index]
                key = hmacsha(sealing.ONE_BL_KEY, bytes(plain[0x20:0x30]))
                one = bytes(plain[:0x30]) + rc4(key, bytes(plain[0x30:]))
            flat[where : where + 0x400] = one
        return Chain(self.Sham(bytes(flat), 0x8000, slots_at), board)

    def test_it_walks_by_the_lengths_the_stages_state(self):
        chain = self.an_image([("CB", 0x1000, 0x23E4), ("CB", 0x2000, 0x23E4),
                               ("CD", 0x1000, 0x24EC)])
        self.assertEqual([one.tag for one in chain.stages], ["CB", "CB", "CD"])
        self.assertEqual([one.at for one in chain.stages], [0x8000, 0x9000, 0xB000])

    def test_an_inserted_bootloader_is_dropped_but_reported(self):
        chain = self.an_image([("CB", 0x1000, 0x23E4), ("CB", 0x400, 15432),
                               ("CB", 0x2000, 0x23E4), ("CD", 0x1000, 0x24EC)])
        self.assertEqual(len(chain.walked), 4)
        self.assertEqual([one.tag for one in chain.stages], ["CB", "CB", "CD"])
        self.assertTrue(chain.converted)
        self.assertEqual(chain.stages[1].build, 0x23E4)

    def test_the_slots_begin_where_the_header_says_and_step_a_flash_block(self):
        chain = self.an_image([("CB", 0x1000, 0x23E4)], slots=2)
        self.assertEqual([one.at for one in chain.slots], [0x100000, 0x110000])

    def test_the_slot_that_counts_is_the_one_stating_the_largest_lockdown(self):
        """Measured five ways on a console with two, by resealing its own slots.

        13/12 and 12/13 both give 13, which is what rules position out; 3/7 gives 7 and
        9/0 gives 9, and the pairing comes from whichever slot won.
        """
        for first, second, wins in ((13, 12, 0), (12, 13, 1), (3, 7, 1), (9, 0, 0)):
            with self.subTest(slots=(first, second)):
                chain = self.an_image([("CB", 0x1000, 0x23E4)], slots=2,
                                      lockdowns=(first, second))
                where = (0x100000, 0x110000)[wins]
                self.assertEqual(chain.slot.at, where)
                self.assertEqual(chain.console.ldv, max(first, second))
                self.assertEqual(chain.console.pairing, bytes([wins + 1]) * 3)

    def test_a_chain_that_binds_nowhere_says_so_rather_than_handing_back_a_cd(self):
        """A single-CB chain has no binding stage, and the second stage is the CD."""
        chain = self.an_image([("CB", 0x1000, 0x23E4), ("CD", 0x1000, 0x24EC),
                               ("CE", 0x1000, 0x760)])
        self.assertEqual(chain.stages[1].tag, "CD")
        self.assertIsNone(chain.bound(bytes(0x10)))

    def test_a_chain_that_does_bind_hands_back_the_second_cb(self):
        chain = self.an_image([("CB", 0x1000, 0x23E4), ("CB", 0x1000, 0x23E4),
                               ("CD", 0x1000, 0x24EC)])
        self.assertIsNotNone(chain.bound(bytes(0x10)))

    def test_asking_for_it_without_the_console_s_key_is_refused(self):
        chain = self.an_image([("CB", 0x1000, 0x23E4), ("CB", 0x1000, 0x23E4)])
        with self.assertRaises(ValueError):
            chain.bound(b"")

    def test_the_walk_reads_each_buffer_s_nonce_and_the_console_s_slot(self):
        """0x417651: CB_A, CB_B, CD, CE in that order, then the slot's CF and CG."""
        n = [bytes([k]) * 0x10 for k in range(1, 5)]
        chain = self.an_image([("CB", 0x1000, 0x23E4, n[0]),
                               ("CB", 0x1000, 0x23E4, n[1]),
                               ("CD", 0x1000, 0x24EC, n[2]),
                               ("CE", 0x1000, 0x760, n[3])], lockdowns=(5,))
        read, finished = chain.nonce_walk()
        self.assertTrue(finished)
        self.assertEqual([read[k] for k in ("CB_A", "CB_B", "CD", "CE")], n)
        self.assertEqual(read["CF"], bytes(range(0x10)))
        self.assertIn("CG", read)

    def test_a_single_cb_goes_straight_on_to_its_cd_and_finishes(self):
        chain = self.an_image([("CB", 0x1000, 0x23E4), ("CD", 0x1000, 0x24EC),
                               ("CE", 0x1000, 0x760)], lockdowns=(5,))
        read, finished = chain.nonce_walk()
        self.assertTrue(finished)
        self.assertNotIn("CB_B", read)

    def test_an_rgh3_chain_stops_the_walk_with_the_payload_read_as_cb_b(self):
        """Its third CB stands where the CD is due: nothing past it, nothing drawn
        from the slot, and a build then draws every nonce."""
        payload = b"\x77" * 0x10
        chain = self.an_image([("CB", 0x1000, 0x23E4), ("CB", 0x400, 15432, payload),
                               ("CB", 0x1000, 0x23E4), ("CD", 0x1000, 0x24EC),
                               ("CE", 0x1000, 0x760)], lockdowns=(5,))
        read, finished = chain.nonce_walk()
        self.assertFalse(finished)
        self.assertEqual(read["CB_B"], payload)
        self.assertEqual(set(read), {"CB_A", "CB_B"})

    def test_a_chain_with_no_ce_does_not_finish(self):
        chain = self.an_image([("CB", 0x1000, 0x23E4), ("CB", 0x1000, 0x23E4),
                               ("CD", 0x1000, 0x24EC)], lockdowns=(5,))
        self.assertFalse(chain.nonce_walk()[1])

    def test_an_image_with_no_slot_refuses_rather_than_guessing(self):
        chain = self.an_image([("CB", 0x1000, 0x23E4)], slots=0)
        with self.assertRaises(ValueError):
            chain.slot  # noqa: B018


class WritingAnUpdatePair(unittest.TestCase):
    """`chain.update`: the CF and CG a build lays behind the chain."""

    KEY = bytes(range(0x10))

    def test_the_cf_counts_the_tail_s_blocks_one_up_from_the_other(self):
        cf = bytearray(a_stage("CF", 0x400))
        update.with_tail(cf, 0x34, 2)
        self.assertEqual(cf[0x30:0x36], bytes.fromhex("000200340035"))
        self.assertEqual(cf[0x36:0x68], bytes(0x32))
        update.with_tail(cf, 0x34, 0)
        self.assertEqual(cf[0x30:0x68], bytes(0x38))

    def test_a_tail_too_long_for_the_list_is_refused(self):
        cf = bytearray(a_stage("CF", 0x400))
        update.with_tail(cf, 0x34, 27)
        with self.assertRaises(ValueError):
            update.with_tail(cf, 0x34, 28)

    def test_the_console_s_block_reads_back_and_the_binding_is_the_cpu_key_s(self):
        cf = bytearray(a_stage("CF", 0x400))
        update.with_console(cf, 1, b"\x78\x02\x27", 14, self.KEY)
        self.assertEqual(cf[0x21B], 1)
        self.assertEqual(Fields.in_cf(bytes(cf)).pairing, b"\x78\x02\x27")
        self.assertEqual(Fields.in_cf(bytes(cf)).ldv, 14)
        message = bytearray(cf[:0x220])
        message[0x20:0x30] = hmacsha(sealing.ONE_BL_KEY, bytes(cf[0x20:0x30]))
        self.assertEqual(bytes(cf[0x220:0x230]), hmacsha(self.KEY, bytes(message)))
        other = bytearray(a_stage("CF", 0x400))
        update.with_console(other, 1, b"\x78\x02\x27", 14, bytes(0x10))
        self.assertNotEqual(other[0x220:0x230], cf[0x220:0x230])

    def test_the_pair_opens_under_the_1bl_key_and_the_key_the_cf_carries(self):
        cf = bytearray(a_stage("CF", 0x400))
        cf[0x330:0x340] = b"\x5a" * 0x10
        cg_nonce = b"\x3c" * 0x10
        cg = a_stage("CG", 0x206, nonce=cg_nonce)
        run = update.sealed(cf, cg, cg_nonce, 0x10)
        self.assertEqual(len(run), 0x400 + 0x210)
        self.assertEqual(opened_under_the_1bl_key(Stage(run, 0))[:0x400],
                         bytes(cf))
        sealed_cg = Stage(run, 0x400)
        key = hmacsha(b"\x5a" * 0x10, cg_nonce)
        self.assertEqual(rc4(key, run[0x420:]), cg[0x20:] + bytes(10))
        self.assertEqual(sealed_cg.nonce, cg_nonce)


class TheFusesALoaderHandsOver(unittest.TestCase):
    """`chain.fuses`: twelve lines, as the template at 0x44A700 fills them."""

    KEY = bytes(range(0x10))

    def test_every_line_of_a_retail_slim_console_s(self):
        out = fuses.virtual(0x03000003, self.KEY, 17)
        lines = [out[at:at + 8] for at in range(0, 0x60, 8)]
        self.assertEqual(len(lines), 12)
        self.assertEqual(lines[0], bytes.fromhex("c0ffffffffffffff"))
        self.assertEqual(lines[1], bytes.fromhex("0f0f0f0f0f0ff0f0"))
        self.assertEqual(lines[2], bytes.fromhex("ff00000000000000"))
        self.assertEqual(lines[3:7], [self.KEY[:8]] * 2 + [self.KEY[8:]] * 2)
        self.assertEqual(lines[7], b"\xff" * 8)
        self.assertEqual(lines[8], bytes.fromhex("f000000000000000"))
        self.assertEqual(lines[9:], [bytes(8)] * 3)

    def test_a_devkit_s_type_and_no_lockdown(self):
        out = fuses.virtual(0, self.KEY, 0)
        self.assertEqual(out[8:16], bytes.fromhex("0f0f0f0f0f0f0f0f"))
        self.assertEqual(out[0x38:0x48], bytes(0x10))

    def test_the_word_comes_off_the_cb_and_an_unknown_type_is_refused(self):
        cb = bytearray(0x400)
        cb[0x3B0:0x3B4] = bytes.fromhex("02001234")
        self.assertEqual(fuses.cb_word(cb), 0x02001234)
        with self.assertRaises(ValueError):
            fuses.virtual(0x07000000, self.KEY, 0)
