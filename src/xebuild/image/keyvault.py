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
this finds at 0x100. The manufacturing date reads as a date on both.

Four fields whose names nothing here can check are here too, each with a comment saying
the name is a guess. None of them is read by anything that decides anything, and none
is in `__repr__`.

**What the original checks is exactly what is checked here, read out of its own
code.** The routine at 0x401630 is handed the sealed bytes and their length and does
four things: HMAC-SHA1 of the sixteen-byte head under the CPU key, RC4 of everything
past it under that, HMAC-SHA1 of what came out with `07 12` appended, and a comparison
of the result with the head it started from. Its caller at 0x413E34 prints "keyvault
decrypted OK" or "keyvault decrypt failed, discarding" on that one answer. So the
derivation below is not a reconstruction of the check; it is the check.

**On one console the original says that check failed, and the reason is not the
keyvault.** It never sees it. A print inserted into the binary just before the
comparison shows what the two sides actually are: on the console it accepts, both are
0x02B79A2F; on the console it refuses, the stored side is **0xFFFFFFFF** -- erased
flash. The bytes it compared were not a keyvault at all.

Why is in `order.py`, because it is about where blocks go rather than about keyvaults:
twenty-four blocks of that console announce four times their own position, the
keyvault's block is one of them, and the buffer the original reads this from is
assembled by the announced number, so that position stays erased. Reading by position,
as this does and as the console itself must, finds the keyvault where it is.

**Nothing is silently wrong in either direction, which is worth being exact about.**
Handed no `kv.bin`, the original refuses that dump outright -- "critical bootloader
files are missing, cannot proceed!" -- and produces no image. Handed a foreign one it
builds, but says twice that it does not match: "the hash does not match the CPU key"
and "could not verify pre-decrypted keyvault". What this reads instead is the
console's own: its serial, its date, a nonce equal to the derivation below, and a
byte-exact round trip.

Sealing it again is deterministic, which took measuring and is worth the sentence: the
nonce is **not drawn**, it is `HMAC(cpu key, plaintext + 07 12)`, confirmed to the byte
on both consoles. So a rebuilt image's keyvault is the console's own bytes exactly, and
nothing about it has to be carried from the dump.
"""

import logging

from ..crypto.formats import NONCE_LENGTH, decrypt_keyvault, encrypt_keyvault

logger = logging.getLogger(__name__)


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
        return cls(decrypt_keyvault(sealed, cpu_key))

    @classmethod
    def opened_if_own(cls, sealed: bytes, cpu_key: bytes) -> Keyvault | None:
        """The keyvault in these bytes if this key is the one they were sealed under.

        Its nonce is what its plaintext derives under the right key and nothing else,
        which is the original's own check -- "keyvault decrypt failed, discarding",
        measured with a CPU key one bit wrong.
        """
        vault = cls.opened(sealed, cpu_key)
        if vault.sealed(cpu_key)[:NONCE_LENGTH] != bytes(sealed)[:NONCE_LENGTH]:
            return None
        return vault

    @classmethod
    def handed_in(cls, given: bytes, cpu_key: bytes) -> Keyvault:
        """A `kv.bin` handed in beside a build, sealed or in the clear.

        Sealed under this key, it is opened; anything else is taken as plaintext, which
        is what J-Runner hands over for a dead NAND and what the original says of it:
        "kv.bin appears to be decrypted already, but the hash does not match the CPU
        key". Either way the first sixteen bytes are a nonce, stale in a clear copy.

        0x3FF0 bytes are a keyvault without that nonce, and the original puts sixteen
        zeros in front (0x41D490), measured. Any other length than that or 0x4000 is
        refused. The original says "kv.bin is not the correct size! Skipping
        verification and encryption!" and writes the file into the image as it stands,
        unsealed -- measured at 0x3F00 and 0x4100 -- which leaves the console a
        keyvault it cannot open; sealing it at its wrong length, as this did before,
        does no better, since the nonce then covers the wrong span.
        """
        if len(given) == 0x3FF0:
            given = bytes(NONCE_LENGTH) + bytes(given)
        if len(given) != 0x4000:
            raise ValueError("kv.bin is %#x bytes, not the correct size (0x4000, or "
                             "0x3FF0 without its nonce)" % len(given))
        own = cls.opened_if_own(given, cpu_key)
        if own is not None:
            return own
        logger.error("kv.bin appears to be decrypted already, but the hash does not "
                     "match the CPU key")
        return cls(given)

    @property
    def head(self) -> bytes:
        """The eight bytes a build puts in afresh at 0x10 -- see `with_head` -- and the
        head `extended.bin` takes as its own."""
        return self.plain[NONCE_LENGTH:NONCE_LENGTH + 8]

    def with_head(self, head: bytes) -> Keyvault:
        return Keyvault(self.plain[:NONCE_LENGTH] + bytes(head)[:8]
                        + self.plain[NONCE_LENGTH + 8:])

    def with_dvd_key(self, key: bytes) -> Keyvault:
        return Keyvault(self.plain[:0x100] + bytes(key) + self.plain[0x110:])

    def sealed(self, cpu_key: bytes) -> bytes:
        """Back to the bytes an image carries, nonce and all.

        The nonce is derived rather than drawn, so this is the console's own bytes again
        and not merely a valid keyvault.
        """
        return encrypt_keyvault(self.plain, cpu_key)

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

    # --- named, unverified here ------------------------------------------------------
    # The name is a guess at what it holds; nothing here confirms it.
    @property
    def fcrt_policy(self) -> bytes:
        """`00f00000` on one console measured and `03f00000` on the other."""
        return self.plain[0x1C:0x20]

    # The name is a guess at what it holds; nothing here confirms it.
    @property
    def region(self) -> bytes:
        """`02fe0000` on both consoles measured, so nothing here tells regions apart."""
        return self.plain[0xC8:0xCC]

    # The name is a guess at what it holds; nothing here confirms it.
    @property
    def console_id(self) -> bytes:
        """Five bytes, different on each console measured, which fits an identity."""
        return self.plain[0x9CA:0x9CF]

    # The name is a guess at what it holds; nothing here confirms it.
    @property
    def osig(self) -> bytes:
        """Forty bytes, and **the same on both consoles measured**.

        Which is the useful thing to record about it: whatever it is, it is not an
        identity. The first eight read `058000325b000000` on each.
        """
        return self.plain[0xC8A:0xC8A + 40]

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
