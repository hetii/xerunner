"""The SMC's settings block: fan curves, temperatures, MAC address, regions.

0x400 bytes a flash keeps at the place its shape names -- `Flash.smc_config` -- and a
console hands over as `smc_config.bin`. The fields below are the ones a build writes,
each found by x360mcp building twice, once with the option and once without, and
reading the difference; J-Runner's own field table agrees on every one it has.

    0x11  CPU fan, 0x12  GPU fan         0x80 | percent; 0x7F is on auto
    0x29..0x2B  CPU, GPU, EDRAM target temperature, Centigrade
    0x2C..0x2E  CPU, GPU, EDRAM overheat temperature
    0x220  MAC address, six bytes
    0x228  video region, thirty-two bits big-endian
    0x22C  game region, sixteen bits big-endian
    0x234  DVD region, thirty-two bits big-endian

The widths are the original's own, read out of its settings-block routine at 0x4291F0
and measured over a block with every field marked: a video or DVD region is written as
four bytes, not as the two or one its usual values fit in.

The head says the block's checksum -- `checksum` -- which covers 0x10 to 0x10C only, so
the fields past 0x220 never move it.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# The settings block, and the region of it the head's word is computed over.
CONFIG_LENGTH = 0x400
SUMMED = (0x10, 0x10C)

# Where each one-byte field is, by the name of the option that sets it.
TEMPERATURES = {"cputemp": 0x29, "gputemp": 0x2A, "edramtemp": 0x2B,
                "overcputemp": 0x2C, "overgputemp": 0x2D, "overedramtemp": 0x2E}


def checksum(block: bytes) -> int:
    """The word a settings block's head has to carry for the original to accept it.

    One's complement of the sum of its bytes from 0x10 to 0x10C, and the head holds it
    little-endian -- the SMC is a little-endian device in a big-endian console.

    Measured rather than assumed, and the span is exact. Three real blocks agree. A
    byte changed at 0x10B makes the original say "not found!"; the same change at 0x10C,
    at the MAC address in 0x220, or at the block's very last byte leaves it accepted.
    Nothing else is checked: change a byte inside the span, recompute this, and the
    block is accepted again. The bytes from 0x02 to 0x10 are outside it, which is why
    the zero pair and the `05 21` beside it can be overwritten with no complaint.
    """
    return (~sum(bytes(block)[SUMMED[0] : SUMMED[1]])) & 0xFFFF


class SmcConfig:
    """One settings block, and whatever follows it in the region it came in."""

    def __init__(self, block: bytes):
        self.original = bytes(block)
        self.block = bytearray(block)

    @classmethod
    def found_in(cls, region: bytes) -> SmcConfig | None:
        """The first block in `region` whose head sums, one 0x400 step at a time.

        J-Runner hands over the whole 0x10000 a console keeps its copies in, and the
        original searches it -- "valid SMC config data found at offset 0xc000" in
        `Donor Files/smc_config/Trinity.bin`.
        """
        for at in range(0, len(region) - CONFIG_LENGTH + 1, CONFIG_LENGTH):
            found = cls(region[at:at + CONFIG_LENGTH])
            if found.sound:
                return found
        return None

    @property
    def sound(self) -> bool:
        """Whether the head says what the block sums to: the original's whole test."""
        head = self.block[:CONFIG_LENGTH]
        return (len(head) == CONFIG_LENGTH
                and int.from_bytes(head[:2], "little") == checksum(head))

    def set_fan(self, which: str, percent: int | None) -> None:
        """`cpu` or `gpu` at a fixed percent, 0 for auto, None to leave it."""
        if percent is None:
            return
        # 0x7F for auto whatever the byte said. The original writes it for `gpufan=0`
        # without marking the block changed, so its head keeps the old checksum and the
        # block no longer passes its own test -- measured, one byte differs and not the
        # head. `sealed` recomputes the head over any change, a deliberate divergence.
        at = {"cpu": 0x11, "gpu": 0x12}[which]
        self.block[at] = 0x80 | percent if percent else 0x7F

    def set_temperature(self, name: str, degrees: int) -> None:
        """One of `TEMPERATURES`, in Centigrade; zero is not written."""
        if degrees:
            self.block[TEMPERATURES[name]] = degrees

    def set_mac(self, mac: bytes) -> None:
        self.block[0x220:0x226] = mac

    def set_regions(self, av: int | None = None, game: int = 0,
                    dvd: int | None = None) -> None:
        """Video and DVD region as thirty-two bits, each only where given; game region
        as sixteen, only where not zero."""
        if av is not None:
            self.block[0x228:0x22C] = av.to_bytes(4, "big")
        if game:
            self.block[0x22C:0x22E] = game.to_bytes(2, "big")
        if dvd is not None:
            self.block[0x234:0x238] = dvd.to_bytes(4, "big")

    def sealed(self) -> bytes:
        """The block as it goes back: its head recomputed where anything changed, and
        left as it was where nothing did.

        A DVD region of zero is put to 1 first, whoever set it -- the block itself or
        `dvdregion=0` -- as the original does: "SMC config has dvd region as 0, xbox
        will not play DVD videos like this... forcing it to 1 (NTSC/USA)". It tests
        the four bytes as one word, at 0x4293A7; measured on a real block with its
        0x237 zeroed, and with `dvdregion=0` over a field whose four bytes were all
        set.
        """
        if not any(self.block[0x234:0x238]):
            logger.warning("SMC config has dvd region as 0, xbox will not play DVD "
                           "videos like this... forcing it to 1 (NTSC/USA)")
            self.block[0x234:0x238] = (1).to_bytes(4, "big")
        out = bytearray(self.block)
        if bytes(out) != self.original:
            out[0:2] = checksum(out).to_bytes(2, "little")
        return bytes(out)
