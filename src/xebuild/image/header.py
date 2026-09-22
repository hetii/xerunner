"""The first page of a flash image, as named fields rather than offsets in the code.

Ten of them are read here, and each was checked against something the original says out
loud about the same image. Its extract mode prints where the keyvault and the SMC are
and how long each is; its build mode prints the header's version and refuses an image
whose magic is not 0xFF4F; and the entry point is the offset it reports the chain at.

The fields this does not name are the ones nothing has verified yet. The word at 0x04,
the flags at 0x06 and 0x48, the patch slot count at 0x68 and the keyvault version at
0x6A are all in the layout and none has been checked against anything the original
prints, so they are left out until something needs them and can prove them.
"""

from __future__ import annotations

import struct


class Header:
    """What an image says about itself, read off its first page.

    A view rather than a copy: the bytes stay where they are, so a header read from an
    image being assembled answers with whatever is there now.
    """

    def __init__(self, image: bytes):
        self.image = image

    def _word(self, at: int) -> int:
        return struct.unpack_from(">H", self.image, at)[0]

    def _long(self, at: int) -> int:
        return struct.unpack_from(">I", self.image, at)[0]

    @property
    def magic(self) -> int:
        """0xFF4F on anything the console will load. The original refuses the rest."""
        return self._word(0x00)

    @property
    def ok(self) -> bool:
        """Whether this looks like a flash image at all."""
        return len(self.image) > 0x80 and self.magic == 0xFF4F

    @property
    def version(self) -> int:
        """The build version the header states -- the original's own words for it."""
        return self._word(0x02)

    @property
    def entrypoint(self) -> int:
        """Where the bootloader chain starts. 0x8000 on every image measured."""
        return self._long(0x08)

    @property
    def size(self) -> int:
        """What the header says the chain occupies."""
        return self._long(0x0C)

    @property
    def keyvault_size(self) -> int:
        """Measured: the original says "decrypting KeyVault ... of size 0x4000"."""
        return self._long(0x60)

    @property
    def keyvault_at(self) -> int:
        """Measured: the original says "decrypting KeyVault at address 0x4000"."""
        return self._long(0x6C)

    @property
    def block_size(self) -> int:
        """The flash's erase block, stated only where the controller is a big block one.

        Zero on the four boards whose header leaves it unsaid, and the original's own
        log draws the same line: "NAND dump is from a small block machine / NAND dump
        uses big block controller".
        """
        return self._long(0x70)

    @property
    def smc_config_at(self) -> int:
        """Where the settings block went, or zero when the header does not say.

        Zero on the dump measured, and the original then goes looking for it --
        "seeking smc config in dump...found at offset 0xf7c000".
        """
        return self._long(0x74)

    @property
    def smc_size(self) -> int:
        """Measured: the original says "decrypting SMC ... of size 0x3000"."""
        return self._long(0x78)

    @property
    def smc_at(self) -> int:
        """Measured: the original says "decrypting SMC at address 0x1000"."""
        return self._long(0x7C)

    def __repr__(self) -> str:
        if not self.ok:
            return "Header(no magic)"
        return "Header(v%d, chain at %#x, keyvault at %#x, smc at %#x)" % (
            self.version, self.entrypoint, self.keyvault_at, self.smc_at
        )
