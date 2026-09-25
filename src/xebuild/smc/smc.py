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

**Whether an SMC is clean for an image type is the original's classifier**, and it is
here because it asks only the SMC -- `clean_for`. What a build does with the answer --
whether a complaint stops it or is only printed -- is a rule about builds, and lives
with them.
"""

from __future__ import annotations

import binascii
import re

from ..crypto.formats import decrypt_smc

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

# What a hacked SMC carries, searched over the whole image: two runs the original builds
# on the stack at 0x40BD8F and 0x40BD9E before its classifier looks for them.
HACK_MARKS = (bytes.fromhex("78bab6"), bytes.fromhex("d000001b"))

# The two routines `with_patch` replaces, and what goes in their place.
PATCHES = {
    "smcnoeject": (bytes.fromhex("a290b322"), bytes.fromhex("c3220000")),
    "smcnoblink": (bytes.fromhex("a2cf92e0a2ce22"), bytes.fromhex("d3220000000000")),
}


class Smc:
    """One SMC image, in the clear."""

    def __init__(self, plain: bytes):
        self.plain = bytes(plain)

    @classmethod
    def handed_in(cls, given: bytes) -> Smc | None:
        """An `smc.bin` as handed over, opened if it was handed over sealed, or None
        where it would not open.

        The original's own test, read out of it at 0x41BABC: four zero bytes at the end
        mean the image is in the clear, since every plaintext SMC is padded that way;
        otherwise it says "SMC binary appears to be encrypted, attempting to decrypt..."
        and asks the same question of what comes out. Still no zeros means it did not
        decrypt -- which a build may waive, so the refusal is the caller's.
        """
        if given[-4:] == bytes(4):
            return cls(given)
        plain = decrypt_smc(given)
        return cls(plain) if plain[-4:] == bytes(4) else None

    @property
    def blank(self) -> bool:
        """Whether this is nothing but 0x00 or 0xFF: no SMC at all.

        Every test the original makes passes such a buffer; refusing it is ours.
        """
        return set(self.plain) <= {0x00} or set(self.plain) <= {0xFF}

    def clean_for(self, number: int) -> bool:
        """The original's classifier at 0x40BD80, read out by x360mcp, for an image
        type by its number.

        Clean when the checksum is one of the stock images; otherwise by type: never
        for devgl (4, 5); for a glitch (3) while the reset limit is still there; for
        JTAG (2) while neither hack mark is; for retail and the kits only when both
        hold.
        """
        if self.clean:
            return True
        if number in (4, 5):
            return False
        if number == 3:
            return self.reset_limit >= 0
        if number == 2:
            return not self.marked
        return self.reset_limit >= 0 and not self.marked

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

    @property
    def marked(self) -> bool:
        """Whether either of the two marks a hacked SMC carries is anywhere in it."""
        return any(mark in self.plain for mark in HACK_MARKS)

    def with_patch(self, name: str) -> bytes:
        """This image with `smcnoeject` or `smcnoblink` applied, or as it stands.

        The core is an 8051, and each patch replaces a short routine found by what it
        looks like -- the offset differs between versions and the sequence does not:

            smcnoeject   A2 90 B3 22          MOV C,90h.0 / CPL C / RET
                     ->  C3 22 00 00          CLR C / RET: the button never reads
                     pressed
            smcnoblink   A2 CF 92 E0 A2 CE 22 ...
                     ->  D3 22 00 00 00 00 00 SETB C / RET: the ring blinks once

        Measured by x360mcp on the nineteen images the original ships: the eject routine
        is in every one exactly once, and the blink routine in sixteen -- not in the
        three Corona images nor Winchester, where the original warns "could not patch
        SMC to disable ROL center blinking" and carries on, which is what this does too.
        A signature found twice is refused: patching one would be a guess at which.
        """
        wanted, replacement = PATCHES[name]
        first = self.plain.find(wanted)
        if first < 0:
            return self.plain
        if self.plain.find(wanted, first + 1) >= 0:
            raise ValueError("the %s signature is in this SMC twice" % name)
        return (self.plain[:first] + replacement
                + self.plain[first + len(replacement):])

    def __repr__(self) -> str:
        return "Smc(%s, %08x, %s)" % (
            self.named, self.checksum, "clean" if self.clean else "not vouched for"
        )
