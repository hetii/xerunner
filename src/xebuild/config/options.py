"""The thirty-one settings `-o` carries.

The original keeps them in one table in its binary, each name beside the message it logs
when the name is given, and that message carries the value's format: fourteen are
switches, twelve carry a number, three the name of a button, and two a fixed run of
bytes. The names and the formats here are that table.

Naming an option without a value is the same as setting it true, and a value that starts
`0x` is hexadecimal where anything else is decimal. `macid` is the exception the usage
names: it is hexadecimal either way, with or without separators.

Update mode has no `-o`, so this class is inherited only by the modes that do.
"""

from __future__ import annotations

from .base import BaseConfig

# Every power-on reason the original takes, and the byte it writes for each into the
# image's header. The byte is a device in the high nibble and a button in the low one,
# which is why `remopower` and `remox` share 0x2_; it is written down as measured rather
# than as a rule. x360mcp read all thirteen out of the original's comparison chain at
# 0x425C7E, after measuring eight of them a build at a time. `wiredx` is a name of its
# own and not a shorthand: the chain compares six characters, so it takes `wiredxb3`'s
# value.
BUTTONS = {
    "power": 0x11, "eject": 0x12, "remopower": 0x20, "remox": 0x22, "winbutton": 0x24,
    "kiosk": 0x41, "wirelessx": 0x55, "wiredxf1": 0x56, "wiredxf2": 0x57,
    "wiredxb2": 0x58, "wiredxb1": 0x59, "wiredx": 0x5A, "wiredxb3": 0x5A,
}

# The ranges the original writes a temperature and a fan speed in, read out of its
# settings-block routine at 0x4291F0 and measured at both ends of each: 40 and 120 are
# written, 39 and 121 are not -- "Ini value 39 for cputemp is out of range (40-120), not
# using" -- and the same at 40 and 100 for a fan. Its sample ini says a fan takes 0 to
# 100; the code takes 0 and 40 to 100, and writes 40 as 0xA8, with nothing mapped. What
# it leaves alone this refuses, so that a value asked for is never silently not used.
TEMPERATURE_RANGE = (40, 120)
FAN_RANGE = (40, 100)


class OptionsConfig(BaseConfig):
    """Every `-o` setting, in the order the original's own table holds them."""

    def __init__(self, **settings):
        self.nodvd = False
        self.olddvd = False
        self.cygnos = False
        self.demon = False
        self.nomobile = False
        self.smcnocheck = False
        self.noremap = False
        self.noecdremap = False
        self.nandmu = False
        self.nosecurity = False
        self.nosusecurity = False
        self.patchsmc = False
        self.smcnoeject = False
        self.smcnoblink = False
        self.cputemp = 0
        self.gputemp = 0
        self.edramtemp = 0
        self.overcputemp = 0
        self.overgputemp = 0
        self.overedramtemp = 0
        self.cpufan = None
        self.gpufan = None
        self.cfldv = None
        self.avregion = None
        self.gameregion = 0
        self.dvdregion = None
        self.xellbutton = "eject"
        self.xellbutton2 = None
        self.dualboot = None
        self.macid = None
        self.dvdkey = None
        super().__init__(**settings)

    @property
    def nodvd(self) -> bool:
        """The old ibuild way of starting Xell: the tray fully open.

        Implies `olddvd`.
        """
        return self["nodvd"]

    @nodvd.setter
    def nodvd(self, wanted):
        self["nodvd"] = self.check_truth("nodvd", wanted)

    @property
    def olddvd(self) -> bool:
        """The old fbbuild way of starting Xell: the tray reading not closed."""
        return self["olddvd"]

    @olddvd.setter
    def olddvd(self, wanted):
        self["olddvd"] = self.check_truth("olddvd", wanted)

    @property
    def cygnos(self) -> bool:
        """Sets the UART speed during bootstrap to one a Cygnos understands."""
        return self["cygnos"]

    @cygnos.setter
    def cygnos(self, wanted):
        self["cygnos"] = self.check_truth("cygnos", wanted)

    @property
    def demon(self) -> bool:
        """Sets the UART speed during bootstrap to one a Demon understands."""
        return self["demon"]

    @demon.setter
    def demon(self, wanted):
        self["demon"] = self.check_truth("demon", wanted)

    @property
    def nomobile(self) -> bool:
        """Leaves the dump's `mobile*.dat` files out of the image."""
        return self["nomobile"]

    @nomobile.setter
    def nomobile(self, wanted):
        self["nomobile"] = self.check_truth("nomobile", wanted)

    @property
    def smcnocheck(self) -> bool:
        """The SMC no longer fails the build on a failed integrity or hack check."""
        return self["smcnocheck"]

    @smcnocheck.setter
    def smcnocheck(self, wanted):
        self["smcnocheck"] = self.check_truth("smcnocheck", wanted)

    @property
    def noremap(self) -> bool:
        """Applies no bad block remapping to the final image."""
        return self["noremap"]

    @noremap.setter
    def noremap(self, wanted):
        self["noremap"] = self.check_truth("noremap", wanted)

    @property
    def noecdremap(self) -> bool:
        """With remapping on, leaves blocks whose ECD sums disagree where they are."""
        return self["noecdremap"]

    @noecdremap.setter
    def noecdremap(self, wanted):
        self["noecdremap"] = self.check_truth("noecdremap", wanted)

    @property
    def nandmu(self) -> bool:
        """Copies blocks 0x10 to 0x15B from a big block dump, keeping memory unit
        content."""
        return self["nandmu"]

    @nandmu.setter
    def nandmu(self, wanted):
        self["nandmu"] = self.check_truth("nandmu", wanted)

    @property
    def nosecurity(self) -> bool:
        """The dump is not searched for the security files a file list names."""
        return self["nosecurity"]

    @nosecurity.setter
    def nosecurity(self, wanted):
        self["nosecurity"] = self.check_truth("nosecurity", wanted)

    @property
    def nosusecurity(self) -> bool:
        """The system update container is not searched for them either."""
        return self["nosusecurity"]

    @nosusecurity.setter
    def nosusecurity(self, wanted):
        self["nosusecurity"] = self.check_truth("nosusecurity", wanted)

    @property
    def patchsmc(self) -> bool:
        """Patches a clean SMC to take out the five reset limit. Ignored for retail."""
        return self["patchsmc"]

    @patchsmc.setter
    def patchsmc(self, wanted):
        self["patchsmc"] = self.check_truth("patchsmc", wanted)

    @property
    def smcnoeject(self) -> bool:
        """Patches the SMC so the eject button never reads as pressed."""
        return self["smcnoeject"]

    @smcnoeject.setter
    def smcnoeject(self, wanted):
        self["smcnoeject"] = self.check_truth("smcnoeject", wanted)

    @property
    def smcnoblink(self) -> bool:
        """Patches the SMC so the ring's centre light blinks no more than once."""
        return self["smcnoblink"]

    @smcnoblink.setter
    def smcnoblink(self, wanted):
        self["smcnoblink"] = self.check_truth("smcnoblink", wanted)

    @property
    def cputemp(self) -> int:
        """The target temperature in Centigrade for the CPU when fans are on auto.

        40 to 120, and 0 leaves the block's own value -- see `TEMPERATURE_RANGE`.
        """
        return self["cputemp"]

    @cputemp.setter
    def cputemp(self, value):
        self["cputemp"] = self.check_number(
            "cputemp", value, between=TEMPERATURE_RANGE, zero=True)

    @property
    def gputemp(self) -> int:
        """The target temperature in Centigrade for the GPU when fans are on auto.

        As `cputemp`: 40 to 120, and 0 leaves the block's own value.
        """
        return self["gputemp"]

    @gputemp.setter
    def gputemp(self, value):
        self["gputemp"] = self.check_number(
            "gputemp", value, between=TEMPERATURE_RANGE, zero=True)

    @property
    def edramtemp(self) -> int:
        """The target temperature in Centigrade for the EDRAM when fans are on auto.

        As `cputemp`: 40 to 120, and 0 leaves the block's own value.
        """
        return self["edramtemp"]

    @edramtemp.setter
    def edramtemp(self, value):
        self["edramtemp"] = self.check_number(
            "edramtemp", value, between=TEMPERATURE_RANGE, zero=True)

    @property
    def overcputemp(self) -> int:
        """The overheat temperature in Centigrade for the CPU.

        As `cputemp`: 40 to 120, and 0 leaves the block's own value.
        """
        return self["overcputemp"]

    @overcputemp.setter
    def overcputemp(self, value):
        self["overcputemp"] = self.check_number(
            "overcputemp", value, between=TEMPERATURE_RANGE, zero=True)

    @property
    def overgputemp(self) -> int:
        """The overheat temperature in Centigrade for the GPU.

        As `cputemp`: 40 to 120, and 0 leaves the block's own value.
        """
        return self["overgputemp"]

    @overgputemp.setter
    def overgputemp(self, value):
        self["overgputemp"] = self.check_number(
            "overgputemp", value, between=TEMPERATURE_RANGE, zero=True)

    @property
    def overedramtemp(self) -> int:
        """The overheat temperature in Centigrade for the EDRAM.

        As `cputemp`: 40 to 120, and 0 leaves the block's own value.
        """
        return self["overedramtemp"]

    @overedramtemp.setter
    def overedramtemp(self, value):
        self["overedramtemp"] = self.check_number(
            "overedramtemp", value, between=TEMPERATURE_RANGE, zero=True)

    @property
    def cpufan(self) -> int | None:
        """Runs the CPU fan at this speed always, as a percentage, or None to leave it.

        40 to 100 -- see `FAN_RANGE` -- and 0 puts it back on auto, which the original
        writes as 0x7F: measured over a block whose byte said 0xBC.
        """
        return self["cpufan"]

    @cpufan.setter
    def cpufan(self, value):
        self["cpufan"] = None if value is None else self.check_number(
            "cpufan", value, between=FAN_RANGE, zero=True)

    @property
    def gpufan(self) -> int | None:
        """Runs the GPU fan at this speed always, as a percentage, or None to leave it.

        As `cpufan`: 40 to 100, and 0 is auto.
        """
        return self["gpufan"]

    @gpufan.setter
    def gpufan(self, value):
        self["gpufan"] = None if value is None else self.check_number(
            "gpufan", value, between=FAN_RANGE, zero=True)

    @property
    def cfldv(self) -> int | None:
        """Byte 0x21F of the decrypted CF: the count of 0xF in fuse rows 7 and 8.

        A retail image has to match the console's fuses; a jtag or glitch2 image does
        not care. It is the count of 0xF nibbles burnt into the console's lockdown fuse
        rows, which a real console confirms: one here has `fffffffffffff000` in fuse row
        7 and its CF reports an LDV of 13.

        One to thirty-two, and a value outside that is refused rather than moved to
        the nearest end of it. The original clamps instead, saying "setting to max
        value of 32", which leaves a caller who asked for 200 with an image built for
        32 and no way to notice. Thirty-two is that tool's limit and not the silicon's:
        fuse rows 7 to 11 are all available to the counter, which is eighty nibbles,
        and the original's own ini describes only rows 7 and 8. The narrower range is
        kept on purpose, because this replaces that tool; if a console past 32 ever
        turns up it is one number.

        The original also takes the value modulo 256 before it looks at the range --
        measured, `cfldv=288` passes silently as 32, `=300` is reported as 44 and
        `=256` is refused because it became zero -- so a number far outside the range
        can come out inside it. Nothing here wraps and nothing here substitutes.

        Zero is not a value here, it is the absence of one, which is why the original
        refuses `-o cfldv=0` and why nothing supplied means `None`. What to do with
        nothing is not a question a configuration can answer: the original looks in
        the dump's CF, then settles on 0 for a devkit or testkit image and on 1 with a
        warning for anything else -- an image type and a dump, neither of which lives
        here.
        """
        return self["cfldv"]

    @cfldv.setter
    def cfldv(self, given):
        self["cfldv"] = (
            None if given is None
            else self.check_number("cfldv", given, between=(1, 32))
        )

    @property
    def avregion(self) -> int | None:
        """The video output mode, or None to leave it. 0x100 is NTSC and 0x300 is PAL.

        Thirty-two bits, written whole, 0 included: measured, `avregion=0` zeroes all
        four bytes and `=0x12345678` writes them as they stand. Its sample ini names
        only the two values above.
        """
        return self["avregion"]

    @avregion.setter
    def avregion(self, value):
        self["avregion"] = None if value is None else self.check_number(
            "avregion", value, between=(0, 0xFFFFFFFF))

    @property
    def gameregion(self) -> int:
        """The console's game region, sixteen bits. 0x00FF is NTSC/US; 0 leaves it.

        The original writes the low sixteen bits of whatever it is given and only when
        they are not zero -- `=0x1FFFF` writes FFFF and `=0x10000` nothing, measured.
        Anything past sixteen bits is refused here instead.
        """
        return self["gameregion"]

    @gameregion.setter
    def gameregion(self, value):
        self["gameregion"] = self.check_number("gameregion", value,
                                               between=(0, 0xFFFF))

    @property
    def dvdregion(self) -> int | None:
        """The console's DVD region, thirty-two bits, or None to leave it.

        Written whole, as `avregion` is. 0 is written too, and then the block's rule
        for a DVD region of zero puts 1 there -- see `SmcConfig.sealed`.
        """
        return self["dvdregion"]

    @dvdregion.setter
    def dvdregion(self, value):
        self["dvdregion"] = None if value is None else self.check_number(
            "dvdregion", value, between=(0, 0xFFFFFFFF))

    @property
    def xellbutton(self) -> str | None:
        """Which power-on button starts Xell.

        Ignored when `olddvd` or `nodvd` is set, and the eject button when nothing
        says otherwise.
        """
        return self["xellbutton"]

    @xellbutton.setter
    def xellbutton(self, given):
        self["xellbutton"] = (
            None if given is None
            else self.check_oneof("xellbutton", given, BUTTONS)
        )

    @property
    def xellbutton2(self) -> str | None:
        """A second power-on reason that also starts Xell, or nothing at all."""
        return self["xellbutton2"]

    @xellbutton2.setter
    def xellbutton2(self, given):
        self["xellbutton2"] = (
            None if given is None
            else self.check_oneof("xellbutton2", given, BUTTONS)
        )

    @property
    def dualboot(self) -> str | None:
        """Which power-on button makes the core send !SWITCH on the UART.

        No effect on a single NAND console, and ignored when it is the same button as
        `xellbutton`.
        """
        return self["dualboot"]

    @dualboot.setter
    def dualboot(self, given):
        self["dualboot"] = (
            None if given is None
            else self.check_oneof("dualboot", given, BUTTONS)
        )

    @property
    def macid(self) -> bytes | None:
        """The MAC address written into the SMC configuration."""
        return self["macid"]

    @macid.setter
    def macid(self, given):
        self["macid"] = None if given is None else self.check_hex("macid", given, 6)

    @property
    def dvdkey(self) -> bytes | None:
        """The DVD key patched into glitch, jtag and devkit images, not retail."""
        return self["dvdkey"]

    @dvdkey.setter
    def dvdkey(self, given):
        self["dvdkey"] = (
            None if given is None else self.check_hex("dvdkey", given, 16)
        )
