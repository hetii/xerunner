"""Client mode's `-bp` over a made-up console: where the bytes land, what else moves.

The original's own recording of `-bp` is not held against this: it patches the first
blocks of the flash whatever offset it is given, and this does not -- see
`client._binary_patch`.
"""

import os
import shutil
import tempfile
import unittest

from xebuild.boards import ALL
from xebuild.network import ConsoleInfo
from xebuild.cli.command import parse_client
from xebuild.client.client import _binary_patch

SPARE = next(one.flash.spare for one in ALL if one.flash.spare is not None)


def info(flash_length, block_length):
    """A console's answer to GTIN with only its two lengths set."""
    body = bytearray(0x4A0)
    body[0x14:0x18] = flash_length.to_bytes(4, "big")
    body[0x18:0x1C] = block_length.to_bytes(4, "big")
    return ConsoleInfo(bytes(body))


class AFlash:
    """Raw blocks in memory, read and written as the update server does."""

    def __init__(self, blocks, block):
        self.block = block
        self.raw = bytearray(os.urandom(blocks * block))
        self.asked = []

    def read_blocks(self, first, count):
        self.asked.append(("read", first, count))
        return bytes(self.raw[first * self.block:(first + count) * self.block])

    def write_blocks(self, first, body, count):
        self.asked.append(("write", first, count))
        self.raw[first * self.block:(first + count) * self.block] = body


class ABinaryPatch(unittest.TestCase):

    def setUp(self):
        self.where = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.where)

    def patch(self, flash, console, offset, body):
        path = os.path.join(self.where, "patch.bin")
        with open(path, "wb") as handle:
            handle.write(body)
        _binary_patch(flash, console, path, offset)

    def logical(self, raw):
        """The data areas alone, as a logical offset counts them."""
        return b"".join(raw[at:at + 0x200] for at in range(0, len(raw), 0x210))

    def test_the_bytes_land_at_the_logical_offset_in_the_block_it_names(self):
        flash = AFlash(0x400, 0x4200)
        before = bytes(flash.raw)
        body = bytes(range(0x30))
        self.patch(flash, info(0x1080000, 0x4200), 0x400000 + 0x1F0, body)
        self.assertEqual(flash.asked, [("read", 0x100, 1), ("write", 0x100, 1)])
        self.assertEqual(self.logical(flash.raw)[0x4001F0:0x400220], body)
        # Everything else in the data is as it was; the two pages touched carry a code
        # that is right again, and no other spare moved.
        was, now = self.logical(before), self.logical(flash.raw)
        self.assertEqual(was[:0x4001F0] + was[0x400220:],
                         now[:0x4001F0] + now[0x400220:])
        for page in range(len(flash.raw) // 0x210):
            raw = bytes(flash.raw[page * 0x210:(page + 1) * 0x210])
            if page in (0x100 * 32, 0x100 * 32 + 1):
                self.assertTrue(SPARE.ecc_ok(raw), page)
            else:
                self.assertEqual(raw, before[page * 0x210:(page + 1) * 0x210], page)

    def test_a_patch_across_a_block_boundary_takes_both_blocks(self):
        flash = AFlash(0x10, 0x4200)
        body = b"\xaa" * 0x20
        self.patch(flash, info(0x1080000, 0x4200), 0x7FF0, body)
        self.assertEqual(flash.asked, [("read", 1, 2), ("write", 1, 2)])
        self.assertEqual(self.logical(flash.raw)[0x7FF0:0x8010], body)

    def test_a_patch_reaching_the_end_of_the_flash_is_refused(self):
        flash = AFlash(0x10, 0x4200)
        with self.assertRaisesRegex(ValueError, "exceed NAND system area"):
            self.patch(flash, info(0x1080000, 0x4200), 0xFFFFF0, b"\x00" * 0x10)
        self.assertEqual(flash.asked, [])

    def test_on_emmc_the_bytes_go_in_as_they_are(self):
        flash = AFlash(4, 0x4000)
        body = bytes(range(0x40))
        self.patch(flash, info(0x3000000, 0x4000), 0x4000 + 0x1F0, body)
        self.assertEqual(flash.asked, [("read", 1, 1), ("write", 1, 1)])
        self.assertEqual(bytes(flash.raw[0x41F0:0x4230]), body)


class ShutdownAndReboot(unittest.TestCase):
    """A reboot supersedes a shutdown whichever comes first -- measured, both orders
    ending in REEB. The original words it by which it saw first; argparse does not
    keep the order, so one sentence says it for both."""

    def test_either_order_reboots(self):
        said = "shutdown superseded by reboot"
        for argv in (["-s", "-reboot"], ["-reboot", "-s"]):
            with self.subTest(argv=argv):
                with self.assertLogs("xebuild", "INFO") as logged:
                    settings = parse_client(argv)
                self.assertTrue(settings.get("reboot"))
                self.assertFalse(settings.get("shutdown"))
                self.assertTrue(any(said in line for line in logged.output))


if __name__ == "__main__":
    unittest.main()
