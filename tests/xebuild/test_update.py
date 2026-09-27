"""Update mode's `collect`: what it asks of the console's SMC and settings block.

Read out of the original (0x403B2F, 0x40426B) rather than measured -- no console here
hands over a broken one -- so what is held here is the rule as read.
"""

import shutil
import tempfile
import unittest

from types import SimpleNamespace
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

    def __init__(self, smc, settings):
        head = bytearray(0x1000)
        head[0x78:0x7C] = len(smc).to_bytes(4, "big")
        head[0x7C:0x80] = (0x4000 - len(smc)).to_bytes(4, "big")
        self.gtbl = bytes(head[:0x4000 - len(smc)].ljust(0x4000 - len(smc), b"\0")
                          + smc).ljust(0xB0000, b"\0")
        self.settings = settings

    def file(self, name):
        return self.settings if name == "usv:\\Static.settings" else None

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

    def collect(self, smc, settings):
        return collect(AConsole(smc, settings), None, self.RECIPE, self.base)

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


if __name__ == "__main__":
    unittest.main()
