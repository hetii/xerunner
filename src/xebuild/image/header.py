"""The first page of a flash image, as named fields rather than offsets in the code.

Ten of them are read here, and each was checked against something the original says out
loud about the same image. Its extract mode prints where the keyvault and the SMC are
and how long each is; its build mode prints the header's version and refuses an image
whose magic is not 0xFF4F; and the entry point is the offset it reports the chain at.

Every field can be written as well as read, and a write goes straight into the image:
a header is a view, so setting one is how a build fills the page it is assembling.
`blank` makes a fresh page to start from where there is no image yet.

The rest are here too, and each says what it stands on. Where x360mcp names a field,
that name is used and a comment says it is a name rather than a finding; where nothing
names one, the offset is the name, so the one thing known about it is not lost. None of
them is read by anything that decides anything, and none is in `__repr__`: they are here
to be looked at and measured, not to be built on.
"""

from __future__ import annotations

import struct

PAGE = 512
MAGIC = 0xFF4F


class Header:
    """What an image says about itself, read off its first page.

    A view rather than a copy: the bytes stay where they are, so a header read from an
    image being assembled answers with whatever is there now.
    """

    def __init__(self, image: bytes):
        self.image = image

    @classmethod
    def blank(cls) -> Header:
        """A fresh page with the magic set and nothing else, ready to be filled."""
        out = bytearray(PAGE)
        struct.pack_into(">H", out, 0x00, MAGIC)
        return cls(out)

    def _word(self, at: int) -> int:
        return struct.unpack_from(">H", self.image, at)[0]

    def _long(self, at: int) -> int:
        return struct.unpack_from(">I", self.image, at)[0]

    def _put(self, form: str, at: int, value) -> None:
        """One field, into the bytes this header is a view on.

        `struct` refuses a value the field cannot hold, so a number nobody asked for is
        never quietly cut down to fit. What it will not do is explain an image that
        cannot be written at all, so that one is said here.
        """
        try:
            struct.pack_into(form, self.image, at, value)
        except TypeError:
            raise ValueError(
                "this header is a view on bytes that cannot be written; "
                "give it a bytearray, or start from Header.blank()"
            ) from None

    @property
    def magic(self) -> int:
        """0xFF4F on anything the console will load. The original refuses the rest."""
        return self._word(0x00)

    @magic.setter
    def magic(self, value: int) -> None:
        self._put(">H", 0x00, value)

    @property
    def ok(self) -> bool:
        """Whether this looks like a flash image at all."""
        return len(self.image) > 0x80 and self.magic == MAGIC

    @property
    def version(self) -> int:
        """The build version the header states -- the original's own words for it."""
        return self._word(0x02)

    @version.setter
    def version(self, value: int) -> None:
        self._put(">H", 0x02, value)

    @property
    def entrypoint(self) -> int:
        """Where the bootloader chain starts. 0x8000 on every image measured."""
        return self._long(0x08)

    @entrypoint.setter
    def entrypoint(self, value: int) -> None:
        self._put(">I", 0x08, value)

    @property
    def size(self) -> int:
        """What the header says the chain occupies."""
        return self._long(0x0C)

    @size.setter
    def size(self, value: int) -> None:
        self._put(">I", 0x0c, value)

    @property
    def keyvault_size(self) -> int:
        """Measured: the original says "decrypting KeyVault ... of size 0x4000"."""
        return self._long(0x60)

    @keyvault_size.setter
    def keyvault_size(self, value: int) -> None:
        self._put(">I", 0x60, value)

    @property
    def keyvault_at(self) -> int:
        """Measured: the original says "decrypting KeyVault at address 0x4000"."""
        return self._long(0x6C)

    @keyvault_at.setter
    def keyvault_at(self, value: int) -> None:
        self._put(">I", 0x6c, value)

    @property
    def block_size(self) -> int:
        """The flash's erase block, stated only where the controller is a big block one.

        Zero on the four boards whose header leaves it unsaid, and the original's own
        log draws the same line: "NAND dump is from a small block machine / NAND dump
        uses big block controller".
        """
        return self._long(0x70)

    @block_size.setter
    def block_size(self, value: int) -> None:
        self._put(">I", 0x70, value)

    @property
    def smc_config_at(self) -> int:
        """Where the settings block went, or zero when the header does not say.

        Zero on the dump measured, and the original then goes looking for it --
        "seeking smc config in dump...found at offset 0xf7c000".
        """
        return self._long(0x74)

    @smc_config_at.setter
    def smc_config_at(self, value: int) -> None:
        self._put(">I", 0x74, value)

    @property
    def smc_size(self) -> int:
        """Measured: the original says "decrypting SMC ... of size 0x3000"."""
        return self._long(0x78)

    @smc_size.setter
    def smc_size(self, value: int) -> None:
        self._put(">I", 0x78, value)

    @property
    def smc_at(self) -> int:
        """Measured: the original says "decrypting SMC at address 0x1000"."""
        return self._long(0x7C)

    @smc_at.setter
    def smc_at(self, value: int) -> None:
        self._put(">I", 0x7c, value)

    # --- not verified here, and each says what it stands on ----------------------
    @property
    def word_at_04(self) -> int:
        """Zero on both consoles measured, and nothing names it, so the offset is."""
        return self._word(0x04)

    @word_at_04.setter
    def word_at_04(self, value: int) -> None:
        self._put(">H", 0x04, value)

    @property
    def word_at_06(self) -> int:
        """Zero on both consoles measured, and nothing names it."""
        return self._word(0x06)

    @word_at_06.setter
    def word_at_06(self, value: int) -> None:
        self._put(">H", 0x06, value)

    # x360mcp calls this the word before the boot flags. That is a name, not a finding.
    @property
    def before_flags(self) -> int:
        """One on the retail dump measured and zero on the glitched one.

        x360mcp records the same split -- images the original builds carry one, and an
        RGH3 dump carries zero with the boot flag bytes beside it cleared as well. Two
        consoles is not enough to call that a rule.
        """
        return self._long(0x48)

    @before_flags.setter
    def before_flags(self, value: int) -> None:
        self._put(">I", 0x48, value)

    # x360mcp calls this the number of patch slots. That is a name, not a finding.
    @property
    def patch_slots(self) -> int:
        """Two on both consoles measured."""
        return self._word(0x68)

    @patch_slots.setter
    def patch_slots(self, value: int) -> None:
        self._put(">H", 0x68, value)

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

    @keyvault_version.setter
    def keyvault_version(self, value: int) -> None:
        self._put(">H", 0x6a, value)

    def __repr__(self) -> str:
        if not self.ok:
            return "Header(no magic)"
        return "Header(v%d, chain at %#x, keyvault at %#x, smc at %#x)" % (
            self.version, self.entrypoint, self.keyvault_at, self.smc_at
        )
