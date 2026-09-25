"""What a console says about itself when asked: the answer to `GTIN`.

0x4A0 bytes or more, laid out as the original's parser at 0x41F4DF reads them -- eight
big-endian words, then the keys and fuses, then three RSA public keys -- and measured
on a real console's answer, whose every field the original's report agrees with:

    0x00  the server's version in the upper bytes, its peek version in the lowest
    0x04  the running kernel, major.minor.build.qfe in 4.4.16.(4 of 8) bits
    0x0C  the bootstrap flags: the board in the low nibble, the hack in the top bits
    0x10  the hardware flags: the board in the top nibble, an HDD at 0x20
    0x14  the NAND image's length, 0x18 its block length with spare
    0x1C  the CF's console block: pairing in the upper three bytes, lockdown below
    0x20  CPU key, 0x30 DVD key, 0x40 twelve fuse lines, 0xA0 twelve virtual ones
    0x100 1BL key, 0x110 1BL, 0x220 PIRS and 0x330 MASTER public keys, 0x110 each
"""

from ..crypto.keys import hammingweight, uideccencode

# Board names by the original's table at 0x44A6E0, which its index 0 calls Unknown.
BOARDS = ("Unknown", "Xenon", "Zephyr", "Falcon", "Jasper", "Trinity", "Corona",
          "Winchester")

# Each public key and the sum of its bytes the original calls good (0x406CFC).
PUBLIC_KEYS = (("1BL", "1BL_pub.bin", 0x110, 0x79C7),
               ("PIRS", "PIRS_pub.bin", 0x220, 0x80D0),
               ("MASTER", "MAST_pub.bin", 0x330, 0x843C))


def _board(index: int) -> str:
    return BOARDS[index] if 0 <= index < len(BOARDS) else BOARDS[0]


def cpu_key_weight(key: bytes) -> int:
    """How many of the key's 106 key bits are set -- 53 in any real one; its 22 check
    bits are not counted."""
    return hammingweight(key[:13]) + hammingweight(bytes([key[13] & 0x03]))


class ConsoleInfo:
    """One console's answer to `GTIN`."""

    def __init__(self, body: bytes):
        if len(body) < 0x4A0:
            raise ValueError("a console's info is at least 0x4a0 bytes, and this is "
                             "%#x" % len(body))
        self.body = bytes(body)

    def word(self, at: int) -> int:
        return int.from_bytes(self.body[at:at + 4], "big")

    @property
    def server_version(self) -> tuple:
        """`(version, peek version)`: "updsvr version 3 (peek version 2)"."""
        return self.word(0) >> 8, self.word(0) & 0xFF

    @property
    def kernel(self) -> str:
        """"2.0.17559.0" -- the qfe is the low nibble, as the original prints it."""
        word = self.word(4)
        return "%d.%d.%d.%d" % (word >> 28, (word >> 24) & 0xF, (word >> 8) & 0xFFFF,
                                word & 0xF)

    @property
    def bootstrap(self) -> int:
        return self.word(0x0C)

    @property
    def hardware(self) -> int:
        return self.word(0x10)

    @property
    def bootstrap_type(self) -> str:
        return _board((self.bootstrap & 0xF) + 1)

    @property
    def hardware_type(self) -> str:
        return _board((self.hardware >> 28) + 1)

    @property
    def fat(self) -> bool:
        """Xenon to Jasper -- where a wired controller's ports are named differently."""
        return (self.bootstrap & 0xF) + 1 <= 4

    @property
    def hdd(self) -> bool:
        return bool(self.hardware & 0x20)

    @property
    def flash_length(self) -> int:
        return self.word(0x14)

    @property
    def block_length(self) -> int:
        return self.word(0x18)

    @property
    def pairing(self) -> int:
        return self.word(0x1C) >> 8

    @property
    def ldv(self) -> int:
        return self.word(0x1C) & 0xFF

    @property
    def cpu_key(self) -> bytes:
        return self.body[0x20:0x30]

    @property
    def dvd_key(self) -> bytes:
        return self.body[0x30:0x40]

    @property
    def fuses(self) -> tuple:
        return tuple(self.body[at:at + 8] for at in range(0x40, 0xA0, 8))

    @property
    def virtual_fuses(self) -> tuple:
        return tuple(self.body[at:at + 8] for at in range(0xA0, 0x100, 8))

    @property
    def one_bl_key(self) -> bytes:
        return self.body[0x100:0x110]

    def public_key(self, at: int) -> bytes:
        return self.body[at:at + 0x110]

    @property
    def image_type(self) -> tuple:
        """`(board, hack)` as the original names them (0x4308D0): the board with a
        suffix for the larger parts, and the hack from the top four bootstrap bits,
        JTAG before Glitch2 before Glitch before Glitch2M; a Xenon's Glitch is
        "Glitch-FAT". Measured over a made-up answer for each.

        A 64 MB Jasper or Trinity is `bb` -- "Jasperbb", measured -- and `bigffs` where
        the kernel word's low byte is 8 or the word at 0x08 has 8 set (0x4309C8), which
        no answer measured had. A 48 MB Corona is "Corona4g".
        """
        index = (self.bootstrap & 0xF) + 1
        board = _board(index)
        if index in (4, 5) and self.flash_length == 0x4200000:
            big = (self.word(4) & 0xFF) == 8 or self.word(8) & 8
            board += "bigffs" if big else "bb"
        elif index == 6 and self.flash_length == 0x3000000:
            board += "4g"
        flags = self.bootstrap
        if flags & 0x80000000:
            hack = "JTAG"
        elif flags & 0x20000000:
            hack = "Glitch2"
        elif flags & 0x40000000:
            hack = "Glitch" + ("-FAT" if flags & 0xF == 0 else "")
        elif flags & 0x10000000:
            hack = "Glitch2M"
        else:
            hack = ""
        return board, hack

    def key_checks(self) -> dict:
        """Each key and public key and whether the original would call it good."""
        cpu = self.cpu_key
        weight = cpu_key_weight(cpu)
        # A key of the wrong weight is called wrong in both, measured: "weight:0x36
        # error; ecd: error".
        out = {"cpu weight": weight,
               "cpu ecd": weight == 53 and uideccencode(cpu) == cpu,
               "1bl": sum(self.one_bl_key) == 0x983}
        for name, _file, at, wanted in PUBLIC_KEYS:
            out[name] = sum(self.public_key(at)) == wanted
        return out
