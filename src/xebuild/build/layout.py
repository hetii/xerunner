"""Where each region of an image goes, which is arithmetic rather than choice.

An image is regions one after another, and every boundary below follows from the one
before it. Measured across fifteen images the original built -- four image types over a
16 MB flash, a 64 MB one and an eMMC -- and the rule is the same in all of them.

    0x000000  the header, one page, and zeros to wherever the SMC starts
              the SMC, which ends where the keyvault begins -- `smc_at`
    0x004000  the keyvault
    0x008000  the bootloader chain, stage after stage
    0x070000  XeLL, 0x40000 long, for a glitch image; a retail one has none
              the slot: the CF, then as much of the CG as fits
              the patch slot, one span later
              the CG's tail, then the files, then the table

**XeLL is at 0x70000 whenever there is one**, on every board including the eMMC, and
it is 0x40000 long, so it ends at 0xB0000. A retail image has none.

**The slot rounds up by `max(round_to, 0x10000)`**, from the end of XeLL where there is
one and from the end of the chain where there is not. That step is not the flash's
alone: a 16 MB flash rounds by 0x4000 everywhere else and by 0x10000 here, which is why
a retail chain ending at 0x6CB20 puts its slot at 0x70000 rather than 0x6D000. A big
block flash rounds by its own 0x20000 and so puts it at 0x80000 or 0xC0000.

**The patch slot is one span past the slot**, and it is a region in every image measured
-- a retail one leaves it erased rather than doing without it. Only its first block is
written and the rest of the span stays erased, which is why the span is given here and
not the block: what goes inside it is the patch set's business.

**The CG does not fit the slot, and what spills lands past the patch slot**, at
`slots + 0x20000`. Where that is below the filesystem's own base -- which happens on a
64 MB image, whose base is 0x2B80000 -- the tail goes to the base instead.

**The tail is always the first file**, listed as `sysupdate.xexp1`: at block 0x34 on
a 16 MB image and at block 0 on a 64 MB one, whose filesystem it opens. An earlier
reading had the 64 MB one list nothing there, which was the table's reader dropping
every entry at block 0.

**Four of the eleven types are laid out here, and `for_type` refuses the rest.** Each
refusal says why, and none of them is for want of trying:

* `jtag` builds and is measured, and its filesystem start is what is not understood.
  Two slot pairs and XeLL after the patches put its first file at 0xE4000, which no
  rounding of anything measured gives.
* `devkit` and `testkit`, in both spellings, cannot be built from a retail release at
  all: the original stops at `could not open '17559/_devkit.ini'`, because a release
  carries no file list for them.
* `devgl`, in both spellings, stops at `cd_9452.bin failed signature check, RSA key not
  available for resigning` -- it sits on development bootloaders, and resigning them
  needs a private key that is not ours to have.

So the four served here are the four that can be held against an image. What the
original's own layout tables say about the rest is recorded in x360mcp; a number read
out of a table and never seen in an image is not what this module is for.

**Why this is in `build` and not beside the reading.** Everywhere else, the code that
writes a structure sits with the code that reads it, because one number in two places is
how an image comes to be written and read back consistently wrong. That does not apply
here: nothing reads these numbers back. A build puts them in the header -- the
keyvault's address, the SMC's, the chain's entry point, and the field the original calls
the patch slot offset -- and every reader takes them from the header instead. The
original keeps the same arithmetic as static tables inside its builder, for the same
reason.
"""

from __future__ import annotations

from ..boards.flash import BLOCK, PAGE

# The header is one page, and the rest of the room before the SMC is zeros: measured on
# every image the original built. The eMMC one puts its SMC at 0x800, inside what a NAND
# image leaves empty, so a page is the floor here and not a block. The page's length is
# `boards.flash.PAGE`; there is no second name for it here.
KEYVAULT_AT = 0x4000
CHAIN_AT = 0x8000

# Where XeLL goes when an image carries one, and how much room it is given.
XELL_AT, XELL_SPAN = 0x70000, 0x40000

# The slot and the patch slot get this much each, whatever they put in it.
SLOT_SPAN = 0x10000

# The smallest step the slot rounds by, whatever the flash rounds by elsewhere.
SLOT_STEP = 0x10000

# The types no reference image exists for, and what stops each one being built. Keyed by
# the name `-t` takes, because that is what the message has to name back.
UNMEASURED = {
    "jtag": "a jtag image lays its filesystem somewhere no rounding measured explains",
    "devkit": "no release carries a file list for a devkit image",
    "devkit16": "no release carries a file list for a devkit16 image",
    "testkit": "no release carries a file list for a testkit image",
    "testkit16": "no release carries a file list for a testkit16 image",
    "devgl": "a devgl image needs an RSA key to resign development bootloaders",
    "devgl16": "a devgl16 image needs an RSA key to resign development bootloaders",
}


def smc_at(length: int) -> int:
    """Where an SMC of this length goes: it ends where the keyvault begins.

    Not a property of the part, which is what this first had wrong. Measured on
    sixty-two images the original built: fifty-seven carry a 0x3000 SMC at 0x1000 and
    five carry a 0x3800 one at 0x800, and the same eMMC console is in both groups --
    which rules out the flash and leaves the SMC's own length. The original says it in
    one line as it writes: "reset smc load address to 0x1000 size 0x3000".

    So a longer SMC starts lower, and the page states the pair; a build that worked one
    out and not the other would leave the console told the wrong place.
    """
    if not 0 < length <= KEYVAULT_AT - PAGE:
        raise ValueError(
            "an SMC of %#x bytes does not fit between the header's page and the "
            "keyvault" % length
        )
    return KEYVAULT_AT - length


def slots_at(chain_end: int, xell: bool, round_to: int) -> int:
    """Where the CF goes."""
    at = XELL_AT + XELL_SPAN if xell else chain_end
    step = max(round_to or SLOT_STEP, SLOT_STEP)
    return (at + step - 1) // step * step


def tail_at(slots: int, base: int) -> int:
    """Where the part of the CG that does not fit its slot lands.

    `base` is where the filesystem counts from, in bytes. Past the slot and the patch
    slot, unless the filesystem starts higher than that, which a 64 MB image does.
    """
    return max(slots + SLOT_SPAN * 2, base)


def for_type(image_type, flash, chain_end: int, bigffs: bool = False) -> dict:
    """Every boundary of an image of this type on this flash, by name.

    The SMC is not among them: where it goes follows its own length rather than the type
    or the part, and `smc_at` is that question.

    Refuses the seven types no image of which could be built to hold it against; the
    message says which and why. A number nobody measured is worse here than none.
    """
    if image_type.name in UNMEASURED:
        raise ValueError(
            "%s: %s" % (image_type.name, UNMEASURED[image_type.name])
        )
    xell = image_type.name != "retail"
    slots = slots_at(chain_end, xell, flash.round_to)
    base = flash.base_of(bigffs) * BLOCK
    out = {
        "header": (0, PAGE),
        "keyvault": (KEYVAULT_AT, KEYVAULT_AT),
        "chain": (CHAIN_AT, chain_end - CHAIN_AT),
        "slot": (slots, SLOT_SPAN),
        "patches": (slots + SLOT_SPAN, SLOT_SPAN),
        "tail": (tail_at(slots, base), 0),
    }
    if xell:
        out["xell"] = (XELL_AT, XELL_SPAN)
    return out
