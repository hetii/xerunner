"""The first page of a flash image, as named fields rather than offsets in the code.

Ten of them are read here, and each was checked against something the original says out
loud about the same image. Its extract mode prints where the keyvault and the SMC are
and how long each is; its build mode prints the header's version and refuses an image
whose magic is not 0xFF4F; and the entry point is the offset it reports the chain at.

The rest are here too, and each says what it stands on. Where x360mcp names a field,
that name is used and a comment says it is a name rather than a finding; where nothing
names one, the offset is the name, so the one thing known about it is not lost. None of
them is read by anything that decides anything, and none is in `__repr__`: they are here
to be looked at and measured, not to be built on.
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

    # --- not verified here, and each says what it stands on ----------------------
    @property
    def word_at_04(self) -> int:
        """Zero on both consoles measured, and nothing names it, so the offset is."""
        return self._word(0x04)

    @property
    def word_at_06(self) -> int:
        """Zero on both consoles measured, and nothing names it."""
        return self._word(0x06)

    # x360mcp calls this the word before the boot flags. That is a name, not a finding.
    @property
    def before_flags(self) -> int:
        """One on the retail dump measured and zero on the glitched one.

        x360mcp records the same split -- images the original builds carry one, and an
        RGH3 dump carries zero with the boot flag bytes beside it cleared as well. Two
        consoles is not enough to call that a rule.
        """
        return self._long(0x48)

    # x360mcp calls this the number of patch slots. That is a name, not a finding.
    @property
    def patch_slots(self) -> int:
        """Two on both consoles measured."""
        return self._word(0x68)

    # x360mcp calls this the keyvault's version. That is a name, not a finding.
    @property
    def keyvault_version(self) -> int:
        """0x0712 on both consoles measured.

        Worth one more sentence, because it may not be a coincidence: 07 12 is also the
        two bytes a keyvault's nonce is derived over, which `keyvault.py` carries as a
        constant. If the salt is really this field, a keyvault of another version would
        seal differently -- and both consoles here are 0x0712, so nothing tells them
        apart.
        """
        return self._word(0x6A)

    def __repr__(self) -> str:
        if not self.ok:
            return "Header(no magic)"
        return "Header(v%d, chain at %#x, keyvault at %#x, smc at %#x)" % (
            self.version, self.entrypoint, self.keyvault_at, self.smc_at
        )
