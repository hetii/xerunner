"""One link of the bootloader chain, as named fields rather than offsets in the code.

A console starts in a series of locked rooms: the key to each is inside the one
before it. The first piece of code is burned into the processor and is not in flash at
all; what it opens is the first stage here, and each stage opens the next. So nothing
above this can read a stage without having read the one before it.

Every kind of stage -- CB, CD, CE, CF, CG -- carries the same 0x20 byte header,
measured on two consoles' dumps and on seven images the original built:

    0x00   2  which kind this is, as two letters
    0x02   2  the build it belongs to
    0x04   2  zero on everything measured, and nothing names it
    0x06   2  flags
    0x08   4  where it starts running
    0x0C   4  how long it is, header included
    0x10  16  the nonce its key is derived over

**A CF is the exception, and not a small one.** Its nonce sits at 0x20 and its body
begins at 0x30, where every other kind has them at 0x10 and 0x20. Reading a CF the
ordinary way opens it to noise and says nothing about it: on a console whose own CF
carries pairing 0x780227 and a lockdown value of 0x0E, the ordinary offsets give
0x85AC4D and 0x78, both perfectly plausible.

Because the header is the same, a stage is one type here. What differs is not what a
stage *is* but what is done with it: which secret opens it, which `sealing` answers, and
whether it carries values belonging to one console, which `console` reads.
"""

from __future__ import annotations

import struct

LENGTH = 0x20


class Stage:
    """A view on one stage where it lies, not a copy of it."""

    def __init__(self, image: bytes, at: int):
        self.image = image
        self.at = at

    def _word(self, offset: int) -> int:
        return struct.unpack_from(">H", self.image, self.at + offset)[0]

    def _long(self, offset: int) -> int:
        return struct.unpack_from(">I", self.image, self.at + offset)[0]

    @property
    def tag(self) -> str:
        """Measured: the kind comes from these two bytes and not from a filename.

        Release 17489 is why that is worth saying. Its stages are not named the way
        every other release names them, and anything that read the kind off a recipe's
        filenames got that release wrong.
        """
        return self.image[self.at : self.at + 2].decode("latin-1")

    @property
    def build(self) -> int:
        return self._word(0x02)

    @property
    def word_at_04(self) -> int:
        """Zero on both consoles measured and nothing names it, so the offset does."""
        return self._word(0x04)

    @property
    def flags(self) -> int:
        return self._word(0x06)

    @property
    def entrypoint(self) -> int:
        return self._long(0x08)

    @property
    def length(self) -> int:
        """How long the whole stage is. The next one begins exactly this far on."""
        return self._long(0x0C)

    @property
    def shape(self) -> tuple:
        """Where this kind keeps its nonce, and where its body starts."""
        return (0x20, 0x30) if self.tag == "CF" else (0x10, LENGTH)

    @property
    def nonce(self) -> bytes:
        at, _body = self.shape
        return self.image[self.at + at : self.at + at + 0x10]

    @property
    def body(self) -> bytes:
        """Everything past the header, still sealed."""
        _nonce, at = self.shape
        return self.image[self.at + at : self.at + self.length]

    @property
    def head(self) -> bytes:
        """The header, whichever length this kind's is."""
        _nonce, at = self.shape
        return self.image[self.at : self.at + at]

    @property
    def looks_like_a_stage(self) -> bool:
        """Whether there is a stage here at all, which is how a walk knows to stop."""
        if self.at + LENGTH > len(self.image):
            return False
        # Two letters rather than a list of the kinds we happen to know: a list would
        # stop a walk dead at the first kind this file had not heard of, and stopping
        # early is indistinguishable from reaching the end.
        if not self.image[self.at : self.at + 2].isalpha():
            return False
        return 0 < self.length <= 0x800000 and self.at + self.length <= len(self.image)

    # --- what the flag word says. Only a first CB is asked these. ------------------
    @property
    def dual(self) -> bool:
        """Whether a second CB follows, printed as "dual CB flag detected!".

        A chain with a single CB binds itself to no console at all.
        """
        return bool(self.flags & 0x0800)

    @property
    def manufacturing(self) -> bool:
        """The bit that puts a chain in the manufacturing regime.

        Decoded from the original at 0x41C37F as `be16(cb_a + 6) & 1`, and it is the
        whole difference between `cba_9188.bin` (0x0800) and `cba_9188_mfg.bin`
        (0x0801).
        Two things follow from it and nothing else does: CB_B is sealed against sixteen
        zero bytes instead of the console's key, and CB_B's console field is left as
        sixteen zeros rather than being computed. See `sealing`.
        """
        return bool(self.flags & 0x0001)

    @property
    def late(self) -> bool:
        """A later regime, which folds this stage's own head into CB_B's message."""
        return bool(self.flags & 0x1000)

    @property
    def payload(self) -> bool:
        """Whether this is the glitch bootloader an exploit inserts.

        It is not part of the chain the console's keys run down, and a walk that keys
        through it gets everything after it wrong. Seen on this bench: an RGH3 console
        carries one of build 15432, 0x400 long, sitting between CB_A and CB_B.
        """
        return self.build == 15432

    def __repr__(self) -> str:
        return "Stage(%s at %#x, %#x bytes, build %#x)" % (
            self.tag, self.at, self.length, self.build
        )
