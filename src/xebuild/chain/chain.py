"""The chain of an image: its stages in order, and the slots behind them.

Walking it is arithmetic -- each stage says how long it is, so the next begins exactly
that far on -- and it stops at the first thing that is not a stage. Measured on two
consoles' dumps and seven images the original built, every one of which agrees with the
offsets the original prints as it lays them.

**CF and CG are not in the chain.** They sit behind it, in slots, and where the first
slot begins is stated in the image's own header: the field that looks like the chain's
length is where the slots begin. Confirmed on seven images -- 0xB0000 on a 16 MB glitch
image, 0xC0000 on both 64 MB shapes, 0x70000 on a retail and on a JTAG one -- and in
each case the two bytes there read `CF`. The original says the same number itself, as
"patch slot offset reset to: 0xb0000".

**A slot is not always one, and which one a console's values come from is not a
position.** It is the slot stating the largest lockdown value, and the pairing comes
from that same slot. Measured on a console carrying two, by resealing its slots with
values of this side's choosing and reading what the original then believed:

    13 / 12  ->  13          12 / 13  ->  13          3 / 7  ->  7, pairing from slot 1
     0 /  5  ->   5           9 /  0  ->   9, pairing from slot 0

The first two are the same values either way round, which is what rules out position. It
also explains what a JTAG image looks like: its first pair is the one the exploit boots
through and carries no console block at all, so its lockdown reads zero and the
release's own slot behind it wins -- "the last one" was right there for the wrong
reason. What two equal values do is not measured, and this takes the earlier slot.

Slots are a flash erase block apart, which is what `block_size` on a flash is for.

**A converted chain is a state, not damage.** An RGH3 console carries a glitch
bootloader inserted between CB_A and CB_B, and everything behind it has shifted. The
original will not read such a dump at all -- "**** Warning: error getting CB/CBA Nonce,
aborting!" -- so this names the condition rather than pretending to have walked it.
"""

import logging

from . import sealing
from .stage import Stage
from .console import Fields
from ..crypto.keys import hmacsha
from ..crypto.formats import decrypt_bootloader

logger = logging.getLogger(__name__)


class Chain:
    """The stages of one image, opened as far as the keys allow.

    `image` is anything that answers `flat` and `header` -- an `Image` or a `Dump`'s --
    and `board` says which console, which settles the fat regime and the slot stride.
    """

    def __init__(self, image, board):
        self.image = image
        self.board = board

    @property
    def flat(self) -> bytes:
        return self.image.flat

    @property
    def walked(self) -> tuple:
        """Every stage from the entry point on, the inserted payload included."""
        out, at = [], self.image.header.entrypoint
        while True:
            one = Stage(self.flat, at)
            if not one.looks_like_a_stage:
                break
            out.append(one)
            at += one.length
        return tuple(out)

    @property
    def stages(self) -> tuple:
        """The chain the console's keys run down, with any inserted payload dropped."""
        return tuple(one for one in self.walked if not one.payload)

    @property
    def converted(self) -> bool:
        """Whether an exploit has put its own bootloader into this chain."""
        return any(one.payload for one in self.walked)

    @property
    def slots(self) -> tuple:
        """The CF and CG pairs behind the chain, each slot a flash block further on."""
        out, at = [], self.image.header.size
        step = self.board.flash.block_size
        while step:
            one = Stage(self.flat, at)
            if not one.looks_like_a_stage or one.tag != "CF":
                break
            out.append(one)
            at += step
        return tuple(out)

    def _opened_slots(self) -> tuple:
        """Every slot with what it says, since which one counts is in the contents."""
        found = tuple(
            (one, Fields.in_cf(one.head + decrypt_bootloader(
                one.body, hmacsha(sealing.ONE_BL_KEY, one.nonce))))
            for one in self.slots
        )
        if not found:
            raise ValueError("this image keeps no CF slot behind its chain")
        return found

    @property
    def slot(self) -> Stage:
        """The slot this console's values come from: the one stating the largest LDV."""
        return max(self._opened_slots(), key=lambda pair: pair[1].ldv)[0]

    def nonce_walk(self) -> tuple:
        """What the original's survey reads off a dump's chain: nonces by the buffer
        they fill -- CB_A, CB_B, CD, CE, CF, CG -- and whether it finished.

        Positional, and it stops at the first stage that is not the one due. A single CB
        goes straight on to its CD and has still finished. An RGH3 chain does not: its
        third CB stands where the CD is due, so the walk stops with the exploit's own
        stage read as CB_B. The CF and CG are the console's slot's, read only by a walk
        that finished. x360mcp read the walk at 0x417651 and found the flag it clears
        in its very last instruction, which is what decides whether a build draws its
        nonces.
        """
        read, finished = self.positional()
        if finished:
            cf = self.slot
            read["CF"] = cf.nonce
            read["CG"] = Stage(cf.image, cf.at + cf.length).nonce
        return read, finished

    def positional(self) -> tuple:
        """`nonce_walk` short of the slot: the stages' nonces by the buffer they fill,
        and whether the walk reached a CE -- which is also update mode's test of a
        console's bootloaders, "bootloaders retrieved from console are inconsistent,
        cannot proceed!" on an RGH3 chain."""
        read, finished, due = {}, False, 0
        for stage in self.walked:
            if stage.tag == "CB" and due < 2:
                read[("CB_A", "CB_B")[due]] = stage.nonce
                due += 1
            elif stage.tag == "CD" and due in (1, 2):
                read["CD"], due = stage.nonce, 3
            elif stage.tag == "CE" and due == 3:
                read["CE"], finished = stage.nonce, True
                break
            else:
                break
        return read, finished

    def keys(self, cpu_key: bytes = b"") -> tuple:
        """The key each stage in `stages` is sealed under, or None past what opens.

        One image type on one chain shape puts a second pass under the console's key in
        front of CD -- `sealing` says which -- and nothing in an image states its type.
        So the ordinary chain is asked for first and kept unless the stage that would
        take that pass does not open under it, which is a question a reader can settle
        by looking. A stage sealed the ordinary way therefore reads exactly as before.
        """
        plain = sealing.keys(self.stages, cpu_key)
        at = sealing.binding_at(self.stages)
        if at >= 0 or not cpu_key or len(self.stages) < 2:
            return plain
        # No CB_B, so the pass may be in front of the stage behind the single CB.
        stage, key = self.stages[1], plain[1]
        if key is None or sealing.looks_open(stage.tag,
                                             decrypt_bootloader(stage.body, key)):
            return plain
        return sealing.keys(self.stages, cpu_key, second_pass_at=1)

    def opened(self, stage: Stage, key: bytes) -> bytes:
        """One stage's body with the cipher run over it, whatever state it was in."""
        return decrypt_bootloader(stage.body, key)

    def plain(self, stage: Stage, key: bytes) -> bytes:
        """One stage's body in the clear, whichever state this image keeps it in.

        An exploited console leaves some of its chain unsealed, and running the cipher
        over such a body would spoil it. `sealing.looks_open` decides, and this says
        which it did rather than deciding quietly.
        """
        if sealing.looks_open(stage.tag, stage.body):
            logger.info("%s at %#x is already in the clear", stage.tag, stage.at)
            return stage.body
        return self.opened(stage, key)

    def bound(self, cpu_key: bytes) -> Fields | None:
        """What the stage that binds this chain to a console carries, or None.

        None means this chain binds to no console at all, which is a real state and not
        a failure: a chain with a single CB -- a JTAG one -- has no such stage, and
        every stage of it keys from its nonce alone.

        Reaching for the second stage instead would be a quiet mistake. On a split CB
        the second stage is the right one; on a single-CB chain it is the CD, and its
        first bytes read back as a perfectly plausible pairing and lockdown value with
        nothing to say they are neither.
        """
        stages = self.stages
        at = sealing.binding_at(stages)
        if at < 0:
            return None
        key = self.keys(cpu_key)[at]
        if key is None:
            raise ValueError(
                "the stage that binds this chain needs this console's cpu key"
            )
        return Fields(self.plain(stages[at], key))

    @property
    def console(self) -> Fields:
        """The pairing and lockdown value this console boots with, out of its CF.

        A CF needs no console secret: it is sealed under the key every console carries,
        so this answers without one. Which slot it comes from is settled by the lockdown
        value rather than by position -- see the note above.
        """
        return max(self._opened_slots(), key=lambda pair: pair[1].ldv)[1]

    def survey(self, cpu_key: bytes = b"") -> None:
        """Say what this chain is, once."""
        if self.converted:
            logger.info("this chain carries an inserted bootloader; the original "
                        "refuses such a dump rather than reading it")
        for stage, key in zip(self.stages, self.keys(cpu_key), strict=True):
            logger.info("%s build %#x at %#x, %#x bytes, %s", stage.tag, stage.build,
                        stage.at, stage.length,
                        "sealed under %s" % key.hex() if key else "not opened")
        for index, one in enumerate(self.slots):
            logger.info("slot %d: %s build %#x at %#x",
                        index, one.tag, one.build, one.at)

    def __repr__(self) -> str:
        return "Chain(%d stages, %d slots%s)" % (
            len(self.stages), len(self.slots),
            ", converted" if self.converted else ""
        )
