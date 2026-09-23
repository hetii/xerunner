"""The system management controller: knowing one before writing it.

This is the part of an image where a mistake is not undone by the means that made it.
The SMC runs before anything else and is what brings a console up far enough to be
flashed again, so a build identifies one rather than carrying it across on trust.

Everything here reads a **plaintext** SMC. `crypto.smc` is what opens the sealed bytes
a flash holds, and nothing in this file ciphers anything.

**What identifies one is a checksum from byte four.** The first four bytes are the
seed the cipher carries, which is why they are skipped -- the same SMC sealed twice
has two different heads and one checksum. The original prints the number: "SMC
checksum: f9c96639".

**Which motherboard it is for is the top half of one byte.** All seven are here,
measured by giving the original each image the release ships and reading what it
printed. **Seven is nameless**: `WINCHESTER_CLEAN.bin` comes back as "known clean SMC
found, type: Unknown v7.1(1.03)", so the original has no name for that board, and this
says the same rather than improving on it.

**Being known and being stock are the same question here, and six images answer it.**
Measured over all nineteen the release ships: the six CLEAN ones for Corona, Falcon,
Jasper, Trinity, Winchester and Zephyr are "known clean SMC found"; everything else,
including every CR4 and SMC+ and all three JTAG images, is "unknown SMC found".
**Xenon's stock image is not in it** -- `XENON_CLEAN.bin` is reported unknown, which
is a gap in the original's own table and not a property of the image.

The table the original carries has entries for images this bench does not hold, so
ours is a subset of it. Absent from it therefore means "nothing here vouches for
this", not "this is not stock", and the difference matters because the safe answer is
the pessimistic one.

**A glitched SMC is one with no reset limit left to patch.** The limit is the counter
that stops a console booting after too many failed attempts, which a glitch trips by
design, and it is found by a signature rather than at an offset. Measured across all
nineteen images, the equivalence is exact: the signature is present in all six stock
images and all three JTAG ones, absent from all six CR4 and SMC+ ones, and "glitch
hack found in SMC binary!" is printed for exactly the second set.

Nothing here decides what a build does about any of it. Whether an image type demands
a stock SMC, and whether a complaint stops the build or is only printed, is a rule
about builds; it is not measured here and is not guessed at either.
"""

from __future__ import annotations

import binascii
import re

# The top half of the byte at 0x100, as the original names it. Seven has no name.
MOTHERBOARDS = {
    1: "Xenon",
    2: "Zephyr",
    3: "Falcon",
    4: "Jasper",
    5: "Trinity",
    6: "Corona",
    7: "Unknown",
}

# Every image the original calls known and clean, by its checksum. Six of the
# nineteen the release ships, each measured by handing it over and reading back.
CLEAN = {
    0xBA42AB9F: "Corona, stock",
    0x1D0C613E: "Falcon, stock",
    0x5B3AED00: "Jasper, stock",
    0xF9C96639: "Trinity, stock",
    0x3A0059DB: "Winchester, stock",
    0x9AD5B7EE: "Zephyr, stock",
}

# The reset limit, found by what it looks like rather than by where it sits. Two
# bytes of the six are zeroed to lift it.
LIMIT = re.compile(rb"\x05.\xe5.\xb4\x05", re.DOTALL)


class Smc:
    """One SMC image, in the clear."""

    def __init__(self, plain: bytes):
        self.plain = bytes(plain)

    @property
    def checksum(self) -> int:
        """What identifies this image, over everything past the cipher's seed."""
        return binascii.crc32(self.plain[4:]) & 0xFFFFFFFF

    @property
    def motherboard(self) -> str:
        """Which board it is for, or nothing when the byte is not one of the seven."""
        return MOTHERBOARDS.get(self.plain[0x100] >> 4, "")

    @property
    def version(self) -> str:
        """The version as the original spells it: `v5.1(3.01)`."""
        return "v%d.%d(%d.%02d)" % (self.plain[0x100] >> 4, self.plain[0x100] & 0x0F,
                                    self.plain[0x101], self.plain[0x102])

    @property
    def named(self) -> str:
        """What the original prints after "type: "."""
        return "%s %s" % (self.motherboard or "Unknown", self.version)

    @property
    def clean(self) -> bool:
        """Whether this is one of the stock images the original vouches for."""
        return self.checksum in CLEAN

    @property
    def reset_limit(self) -> int:
        """Where the reset limit is, or -1 when this image has none left."""
        found = LIMIT.search(self.plain)
        return found.start() if found else -1

    @property
    def glitched(self) -> bool:
        """Whether a glitch hack has already been put in this image.

        Which is the same question as having no reset limit, measured over all nineteen
        images the release ships with no exception either way.
        """
        return self.reset_limit < 0

    def patched(self) -> bytes:
        """This image with the reset limit lifted, or as it stands when it has none.

        Two bytes at the signature go to zero and nothing else moves.
        """
        at = self.reset_limit
        if at < 0:
            return self.plain
        return self.plain[:at] + bytes(2) + self.plain[at + 2 :]

    def __repr__(self) -> str:
        return "Smc(%s, %08x, %s)" % (
            self.named, self.checksum, "clean" if self.clean else "not vouched for"
        )
