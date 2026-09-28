"""Update mode's `collect`: what it asks of the console's SMC and settings block.

Read out of the original (0x403B2F, 0x40426B) rather than measured -- no console here
hands over a broken one -- so what is held here is the rule as read.
"""

import os
import shutil
import tempfile
import unittest

from types import SimpleNamespace
from xebuild.network import ConsoleInfo
from xebuild.update.update import collect
from xebuild.image.settings import checksum
from xebuild.crypto.formats import encrypt_smc


def a_block() -> bytes:
    block = bytearray(0x400)
    block[0x10:0x110] = bytes(range(0x100))
    block[:2] = checksum(block).to_bytes(2, "little")
    return bytes(block)


class AConsole:
    """Answers `collect` with a head, an SMC and a settings file, and nothing else."""

    def __init__(self, smc, settings, served=None):
        head = bytearray(0x1000)
        head[0x78:0x7C] = len(smc).to_bytes(4, "big")
        head[0x7C:0x80] = (0x4000 - len(smc)).to_bytes(4, "big")
        self.gtbl = bytes(head[:0x4000 - len(smc)].ljust(0x4000 - len(smc), b"\0")
                          + smc).ljust(0xB0000, b"\0")
        self.settings = settings
        self.served = served or {}
        self.asked = []

    def file(self, name):
        self.asked.append(name)
        if name == "usv:\\Static.settings":
            return self.settings
        return self.served.get(name)

    def bad_blocks(self):
        return []

    def mount(self, *_):
        pass

    def unmount(self, *_):
        pass

    def bootloaders(self):
        return self.gtbl


class WhatUpdateAsksOfTheConsole(unittest.TestCase):

    RECIPE = SimpleNamespace(firmware=[])

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.base)

    def collect(self, smc, settings, offers=0, served=None, append=()):
        info = bytearray(0x4A0)
        info[0x0B] = offers
        console = AConsole(smc, settings, served)
        self.console = console
        return collect(console, ConsoleInfo(bytes(info)), self.RECIPE, self.base,
                       append=append)

    def test_a_sound_smc_and_block_go_through_and_the_block_is_cut_to_0x400(self):
        smc = encrypt_smc(bytes(0x3000), bytes(4))
        found = self.collect(smc, a_block() + b"\xff" * 0x100)
        self.assertEqual(found.settings, a_block())

    def test_an_smc_that_does_not_open_stops_it(self):
        with self.assertRaisesRegex(ValueError, "could not decrypt smc.bin"):
            self.collect(b"\xff" * 0x3000, a_block())

    def test_an_smc_shorter_than_0x3000_stops_it(self):
        with self.assertRaisesRegex(ValueError, "could not retrieve smc.bin"):
            self.collect(encrypt_smc(bytes(0x2000), bytes(4)), a_block())

    def test_a_settings_block_that_is_short_missing_or_unsound_stops_it(self):
        smc = encrypt_smc(bytes(0x3000), bytes(4))
        spoilt = bytearray(a_block())
        spoilt[0x20] ^= 1
        for settings in (a_block()[:0x3FF], None, bytes(spoilt),
                         b"\xff" * 0x200 + a_block()):
            size = None if settings is None else len(settings)
            with self.subTest(settings=size), \
                    self.assertRaisesRegex(ValueError, "smc_config from console"):
                self.collect(smc, settings)



class TheAddonsAConsoleHandsOver(unittest.TestCase):
    """Update mode asks for them where the original does and names them by the
    index of the release the console runs; the rules, measured on the original
    against a stand-in console."""

    NOFCRT = bytes.fromhex("000611a000000001" "0002e24000000003")
    NOHDD = bytes.fromhex("0015dd3000000001")

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.base)
        where = os.path.join(self.base, "0", "bin")
        os.makedirs(where)
        table = (2).to_bytes(4, "big")
        for name, records in (("nofcrt", self.NOFCRT), ("nohdd", self.NOHDD)):
            table += (len(records) // 8).to_bytes(4, "big") + records
            table += name.encode().ljust(16, b"\x00")
        with open(os.path.join(where, "addon.idx"), "wb") as handle:
            handle.write(table)

    def collect(self, offers, served, append=()):
        info = bytearray(0x4A0)
        info[0x0B] = offers
        self.console = AConsole(encrypt_smc(bytes(0x3000), bytes(4)), a_block(),
                                served)
        return collect(self.console, ConsoleInfo(bytes(info)),
                       SimpleNamespace(firmware=[]), self.base, append=append)

    def test_nothing_is_asked_for_where_the_console_offers_nothing(self):
        found = self.collect(0, {"addons": self.NOFCRT, "blmod": b"x" * 4})
        self.assertNotIn("addons", self.console.asked)
        self.assertNotIn("blmod", self.console.asked)
        self.assertEqual(found.addons, ())

    def test_blmod_then_addons_before_the_settings_block(self):
        found = self.collect(6, {"addons": self.NOHDD + self.NOFCRT, "blmod": b"x" * 4})
        asked = self.console.asked
        at = asked.index("blmod")
        self.assertEqual(asked[at:at + 3], ["blmod", "addons", "usv:\\Static.settings"])
        self.assertEqual(found.addons, ("nofcrt", "nohdd"))

    def test_an_entry_is_carried_only_whole(self):
        self.assertEqual(self.collect(4, {"addons": self.NOFCRT[:8]}).addons, ())

    def test_a_length_that_is_no_multiple_of_four_is_skipped(self):
        self.assertEqual(self.collect(4, {"addons": self.NOFCRT + b"\x01"}).addons, ())

    def test_addons_named_on_the_command_line_leave_the_console_s_unasked(self):
        found = self.collect(4, {"addons": self.NOFCRT}, append=("nolan",))
        self.assertNotIn("addons", self.console.asked)
        self.assertEqual(found.addons, ())


if __name__ == "__main__":
    unittest.main()
