"""The SMC's settings block: fan curves, temperatures, MAC address, regions.

0x400 bytes a flash keeps at the place its shape names -- `Flash.smc_config` -- and a
console hands over as `smc_config.bin`. The fields below are the ones a build writes,
each found by x360mcp building twice, once with the option and once without, and
reading the difference; J-Runner's own field table agrees on every one it has.

    0x11  CPU fan, 0x12  GPU fan         0x80 | percent; zero is on auto
    0x29..0x2B  CPU, GPU, EDRAM target temperature, Centigrade
    0x2C..0x2E  CPU, GPU, EDRAM overheat temperature
    0x220  MAC address, six bytes
    0x22A  video region, 0x22C  game region, both sixteen bits big-endian
    0x237  DVD region, one byte

The head says the block's checksum -- `checksum` -- which covers 0x10 to 0x10C only, so
the fields past 0x220 never move it.
"""

from __future__ import annotations

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

    def set_fan(self, which: str, percent: int) -> None:
        """`cpu` or `gpu` at a fixed percent; zero is not written, and stays auto."""
        if percent:
            self.block[{"cpu": 0x11, "gpu": 0x12}[which]] = 0x80 | percent

    def set_temperature(self, name: str, degrees: int) -> None:
        """One of `TEMPERATURES`, in Centigrade; zero is not written."""
        if degrees:
            self.block[TEMPERATURES[name]] = degrees

    def set_mac(self, mac: bytes) -> None:
        self.block[0x220:0x226] = mac

    def set_regions(self, av: int = 0, game: int = 0, dvd: int = 0) -> None:
        """Video and game region as sixteen bits big-endian, DVD region as one byte;
        each only where given."""
        if av:
            self.block[0x22A:0x22C] = av.to_bytes(2, "big")
        if game:
            self.block[0x22C:0x22E] = game.to_bytes(2, "big")
        if dvd:
            self.block[0x237] = dvd & 0xFF

    def sealed(self) -> bytes:
        """The block as it goes back: its head recomputed where anything changed, and
        left as it was where nothing did."""
        out = bytearray(self.block)
        if bytes(out) != self.original:
            out[0:2] = checksum(out).to_bytes(2, "little")
        return bytes(out)
