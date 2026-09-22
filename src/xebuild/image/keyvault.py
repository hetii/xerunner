"""A console's own secrets, and the one thing in a flash image that is only its own.

The keyvault is the block at 0x4000 that makes an image belong to one machine. It is
sealed with RC4 under a key derived from the console's CPU key, so it opens with that
key and with no other -- which is what makes it the identity of a dump: the same
bootloaders and the same dashboard say nothing about which console an image came off,
and this says everything.

It sits at 0x4000 and is 0x4000 long, which the header states as well.

What is read here is what could be proved. Opening it is proved by what comes out: each
of the two consoles measured has its own twelve-digit serial in the clear at 0xB0, and
one of them keeps its DVD key in a file beside the dump, which is the same sixteen bytes
this finds at 0x100. The manufacturing date reads as a date on both. The fields x360mcp
names that nothing here can check -- the region word, the OSIG, the console id, the FCRT
policy -- are left out until something needs them and can prove them.

Sealing it again is deterministic, which took measuring and is worth the sentence: the
nonce is **not drawn**, it is `HMAC(cpu key, plaintext + 07 12)`, confirmed to the byte
on both consoles. So a rebuilt image's keyvault is the console's own bytes exactly, and
nothing about it has to be carried from the dump.
"""

from __future__ import annotations

from ..crypto import keys, rc4

NONCE = 0x10


class Keyvault:
    """One keyvault in the clear. Opening and sealing cross the image's edge."""

    def __init__(self, plain: bytes):
        self.plain = bytes(plain)

    @classmethod
    def opened(cls, sealed: bytes, cpu_key: bytes) -> Keyvault:
        """The keyvault a console's block holds, under that console's own CPU key.

        Any key opens it to something; only its own opens it to a serial that reads as
        one, which is what `looks_opened` is for.
        """
        sealed = bytes(sealed)
        body = rc4.rc4(keys.derive(cpu_key, sealed[:NONCE]), sealed[NONCE:])
        return cls(sealed[:NONCE] + body)

    def sealed(self, cpu_key: bytes) -> bytes:
        """Back to the bytes an image carries, nonce and all.

        The nonce is derived rather than drawn, so this is the console's own bytes again
        and not merely a valid keyvault.
        """
        body = self.plain[NONCE:]
        # 0x07 0x12 is what the derivation takes beyond the plaintext itself.
        nonce = keys.derive(cpu_key, body + b"\x07\x12")
        return nonce + rc4.rc4(keys.derive(cpu_key, nonce), body)

    @property
    def serial(self) -> str:
        """The console's serial, twelve digits."""
        return self.plain[0xB0:0xBC].decode("latin-1")

    @property
    def dvd_key(self) -> bytes:
        """The drive's key, sixteen bytes."""
        return self.plain[0x100:0x110]

    @property
    def made_on(self) -> str:
        """When the console was made, as it writes it: month, day, year."""
        return self.plain[0x9E4:0x9EC].decode("latin-1")

    @property
    def hashed(self) -> bool:
        """Whether this is what the original calls a type 2 keyvault rather than type 1.

        Its own test is the eight words at 0x1DF8: type 2 the moment one of them is
        neither zero nor all ones, and type 1 otherwise. The hash is what a master key
        would check, and that key is not here, so nothing checks it.
        """
        words = [self.plain[0x1DF8 + at : 0x1DFC + at] for at in range(0, 0x20, 4)]
        return any(one not in (b"\x00" * 4, b"\xff" * 4) for one in words)

    @property
    def looks_opened(self) -> bool:
        """Whether the key this was opened with was the right one.

        A serial of twelve digits is the test, because a wrong key gives noise and noise
        is not digits.
        """
        return len(self.serial) == 12 and self.serial.isdigit()

    def __repr__(self) -> str:
        if not self.looks_opened:
            return "Keyvault(not opened)"
        return "Keyvault(%s, made %s, type %d)" % (
            self.serial, self.made_on, 2 if self.hashed else 1
        )
