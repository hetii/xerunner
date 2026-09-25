"""A console's own bootloader chain, and the field tying it to its SMC.

Needs real material and says which. See `tests/xebuild/e2e/__init__.py`.
"""

import os
import unittest

from xebuild.crypto import smc
from xebuild.crypto.rc4 import rc4
from xebuild.boards import for_name
from xebuild.image import Dump, Image
from xebuild.crypto.keys import hmacsha
from xebuild.chain import Chain, Fields, sealing


class AConsoleSOwnChain(unittest.TestCase):
    """The numbers the original prints for a real dump. Needs `XEBUILD_DUMP`."""

    @classmethod
    def setUpClass(cls):
        where = os.environ.get("XEBUILD_DUMP", "")
        key = os.environ.get("XEBUILD_CPUKEY", "")
        if not where or not os.path.isfile(where) or not key:
            raise unittest.SkipTest("XEBUILD_DUMP and XEBUILD_CPUKEY are not both set")
        board, bigffs = for_name(os.environ.get("XEBUILD_DUMP_BOARD", "trinity"))
        with open(where, "rb") as handle:
            cls.dump = Dump(handle.read(), board, bigffs)
        cls.cpu_key = bytes.fromhex(key)
        cls.chain = cls.dump.chain

    def test_the_chain_starts_where_the_header_says(self):
        self.assertEqual(self.chain.stages[0].at, self.dump.header.entrypoint)
        self.assertEqual(self.chain.stages[0].tag, "CB")

    def test_the_first_slot_sits_where_the_header_says_the_chain_ends(self):
        """Measured on seven images: that field is where the slots begin, and a CF is
        what is there. The original says the same number as "patch slot offset"."""
        self.assertEqual(self.chain.slots[0].at, self.dump.header.size)
        self.assertEqual(self.chain.slots[0].tag, "CF")

    def test_the_pairing_and_the_lockdown_value_come_out_of_the_cf(self):
        """`XEBUILD_PAIRING` and `XEBUILD_LDV` say what the original printed."""
        found = self.chain.console
        self.assertEqual(len(found.pairing), 3)
        wanted = os.environ.get("XEBUILD_PAIRING", "")
        if wanted:
            self.assertEqual(found.pairing.hex(), wanted.strip().lower())
        ldv = os.environ.get("XEBUILD_LDV", "")
        if ldv:
            self.assertEqual(found.ldv, int(ldv, 0))

    def test_a_cf_needs_no_console_secret(self):
        """It is sealed under the key every console carries, which is why extract
        mode can read a pairing out of a dump it holds no key for."""
        slot = self.chain.slot
        plain = slot.head + rc4(hmacsha(sealing.ONE_BL_KEY, slot.nonce), slot.body)
        self.assertEqual(Fields.in_cf(plain).pairing, self.chain.console.pairing)

    def test_the_field_in_cb_b_ties_the_chain_to_the_smc_beside_it(self):
        """This is what proves `crypto.smc.fingerprint`, so it is the test that matters.

        Skipped on a chain an exploit has converted: such a console keeps its CB_B in
        the clear and does not need the field to be right, because the check is patched
        out rather than recomputed.
        """
        if self.chain.converted:
            raise unittest.SkipTest("this chain is converted, so the field is not kept")
        fields = self.chain.bound(self.cpu_key)
        key = self.chain.keys(self.cpu_key)[sealing.binding_at(self.chain.stages)]
        self.assertTrue(
            fields.agrees(self.cpu_key, key, smc.fingerprint(self.dump.smc))
        )

    def test_the_pairing_in_cb_b_is_the_one_the_cf_states(self):
        if self.chain.converted:
            raise unittest.SkipTest("this chain is converted")
        self.assertEqual(self.chain.bound(self.cpu_key).pairing,
                         self.chain.console.pairing)

    def test_every_stage_but_the_kernel_opens_to_something_that_reads_as_code(self):
        """And the kernel is the exception on purpose: it is compressed, so its
        plaintext is as dense as ciphertext. It is judged on its header instead."""
        for stage, key in zip(self.chain.stages, self.chain.keys(self.cpu_key),
                              strict=True):
            if key is None:
                continue
            with self.subTest(tag=stage.tag, at=stage.at):
                self.assertTrue(sealing.looks_open(stage.tag,
                                                   self.chain.plain(stage, key)))


class AgainstAnImageTheOriginalBuilt(unittest.TestCase):
    """What the original wrote into CB_B, against what this would write.

    Needs `XEBUILD_REFERENCE_IMAGE` naming an image the original built from the dump
    `XEBUILD_DUMP` names, with `XEBUILD_CPUKEY` for that console. Where the original
    cannot read a dump's keyvault alone, it builds one of these once it is handed the
    keyvault this code extracts.
    """

    @classmethod
    def setUpClass(cls):
        where = os.environ.get("XEBUILD_REFERENCE_IMAGE", "")
        dump = os.environ.get("XEBUILD_DUMP", "")
        key = os.environ.get("XEBUILD_CPUKEY", "")
        if not (where and dump and key) or not os.path.isfile(where):
            raise unittest.SkipTest("reference image, dump and cpu key not all named")
        board, bigffs = for_name(os.environ.get("XEBUILD_DUMP_BOARD", "trinity"))
        cls.board = board
        cls.cpu_key = bytes.fromhex(key)
        with open(dump, "rb") as handle:
            cls.dump = Dump(handle.read(), board, bigffs)
        with open(where, "rb") as handle:
            cls.image = Image(handle.read(), board.flash)

    def test_the_fields_it_wrote_are_the_fields_this_writes(self):
        chain = Chain(self.image, self.board)
        stages, keys = chain.stages, chain.keys(self.cpu_key)
        at = sealing.binding_at(stages)
        theirs = chain.plain(stages[at], keys[at])[:0x20]
        head = self.image.header
        sealed = self.image.flat[head.smc_at : head.smc_at + head.smc_size]
        ours = Fields.write(self.dump.pairing, self.cpu_key, keys[at],
                            smc.fingerprint(sealed))
        self.assertEqual(ours, theirs)

    def test_every_stage_of_it_reseals_to_the_bytes_it_holds(self):
        """RC4 is symmetric, so this is the whole of writing a stage, and it is
        checked against an image rather than asserted."""
        chain = Chain(self.image, self.board)
        for stage, key in zip(chain.stages, chain.keys(self.cpu_key), strict=True):
            if key is None:
                continue
            with self.subTest(tag=stage.tag, at=stage.at):
                sealed = self.image.flat[stage.at : stage.at + stage.length]
                again = stage.head + rc4(key, chain.plain(stage, key))
                self.assertEqual(again, sealed)
