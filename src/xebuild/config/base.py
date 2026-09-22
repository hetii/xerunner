"""What every mode of the tool has, and the checks every setting is made of.

The original runs in four modes -- build, extract, client, update -- and taking each
one's switch list from the tool and intersecting them leaves three: `-v`, `-noenter` and
`-?`. The last is not a setting but an action: it prints the usage and the run is over.
So two settings are truly universal, and they are the two here. Anything narrower lives
in a class only the modes that have it inherit.

A configuration is a dict with a door. The values live in the dict under the names the
rest of the program reads them by; the attributes are the only way in, and every one of
them checks what it is given before it lands. Nothing downstream checks a value it took
from here.

The checks themselves are the handful of methods below, because the same few questions
are asked over and over -- is this on or off, is this a number, is this one of a known
set. A setter says which question its value has to answer and where to put the answer.
They are named `check_` so that nothing in a class reads like one of its settings: a
setting is a property, a check is a method.

Each of them takes the name to refuse by, and that name is always the field's own, as
it is spelled in the code. A method cannot know which property called it, and a
refusal that says `cfldv is 1 to 32` leaves nobody wondering which setting was meant.
A setting that may be absent says so at its own site: `None if given is None else ...`,
so a value that is really missing is never quietly turned into one that is not.
"""

from __future__ import annotations

import os


class BaseConfig(dict):
    """The settings every mode understands, and the checks they are made of."""

    def __init__(self, **settings):
        super().__init__()
        self.verbose = 0
        self.no_enter = False
        for name, value in settings.items():
            door = getattr(type(self), name, None)
            if door is None or not hasattr(door, "__set__"):
                raise ValueError(
                    "%s is not a setting of %s" % (name, type(self).__name__)
                )
            setattr(self, name, value)

    # --- the checks; not settings, which is why they are named apart ----------
    def check_truth(self, what, given) -> bool:
        """A setting that is on or off, whether it came as a bool or as a word."""
        if isinstance(given, bool):
            return given
        wanted = str(given).strip().lower()
        if wanted not in ("true", "false"):
            raise ValueError("%s is true or false, not %r" % (what, given))
        return wanted == "true"

    def check_number(self, what, given, between=None, base=10) -> int:
        """A value, decimal unless it starts `0x`.

        `base` is for the places the original reads a number as hexadecimal whether or
        not it is written with `0x`, which client mode's legend states of every number
        it takes.

        `between` is the range a value has to be inside, and a value outside it is
        refused. It is never replaced by the nearest end of the range: a number the
        caller did not ask for is a fault nobody can see afterwards, so a wrong value
        has to be said out loud rather than quietly turned into a plausible one. The
        original does replace -- it clamps `cfldv` to 32 and says so -- and this is a
        deliberate divergence from it.

        Negative is refused wherever no range is given, which the original also
        refuses: measured over every option that takes a number, `-o cputemp=-5` and
        its like are turned away.

        A value that is not a number at all is refused too, and there the original
        does not: measured, `-o cputemp=abc` is taken and written through. Reproducing
        that would mean turning nonsense into a value quietly.
        """
        # A bool here is an option that was named with no value after it, which is a
        # missing value rather than a wrong type.
        if isinstance(given, bool):
            raise ValueError("%s needs a value" % what)
        if isinstance(given, int):
            number = given
        else:
            text = str(given).strip()
            try:
                number = int(text, 16) if text[:2].lower() == "0x" else int(text, base)
            except ValueError:
                raise ValueError(
                    "%s is a number, and %r is not" % (what, given)
                ) from None
        if between is not None:
            low, high = between
            if not low <= number <= high:
                raise ValueError(
                    "%s is %d to %d, and this is %d" % (what, low, high, number)
                )
        elif number < 0:
            raise ValueError("%s is not negative: %d" % (what, number))
        return number

    def check_oneof(self, what, given, known) -> str:
        """A name out of a known set, however it was capitalised."""
        wanted = str(given).strip().lower()
        if wanted not in known:
            raise ValueError(
                "%s is one of %s, and this is %r" % (what, ", ".join(known), given)
            )
        return wanted

    def check_hex(self, what, given, length) -> bytes:
        """A fixed run of bytes written as hexadecimal, separators allowed.

        The original takes `:` between the bytes of a MAC address and refuses `-`. A
        dash means the same thing to a reader, so it is read as a colon here.
        """
        if isinstance(given, (bytes, bytearray)):
            if len(given) != length:
                raise ValueError("%s is %d bytes, not %d" % (what, length, len(given)))
            return bytes(given)
        text = str(given).strip()
        for one in (":", "-", " "):
            text = text.replace(one, "")
        if len(text) != length * 2:
            raise ValueError(
                "%s is %d bytes, not %d" % (what, length, len(text) // 2)
            )
        try:
            return bytes.fromhex(text)
        except ValueError:
            raise ValueError(
                "%s is hexadecimal, and %r is not" % (what, given)
            ) from None

    def check_word(self, what, given) -> str:
        """One word, with nothing in it that would break a file name."""
        word = str(given).strip()
        if not word or any(one in word for one in (" ", "/", "\\", ";")):
            raise ValueError("%s is one word: %r" % (what, given))
        return word

    def check_name(self, what, given) -> str:
        """A file name, whatever is in it, as long as there is something."""
        name = str(given).strip()
        if not name:
            raise ValueError("%s needs a name" % what)
        return name

    def check_directory(self, what, given) -> str:
        """A directory that is there to be read."""
        path = str(given).strip().rstrip("/\\")
        if not os.path.isdir(path):
            raise ValueError("%s %r is not a directory" % (what, path))
        return path

    # --- the settings -----------------------------------------------------------
    @property
    def verbose(self) -> int:
        """How much the run says about itself: 0 silent, 1 more, 2 most.

        The original reads the level off the switch rather than counting it: `-v` and
        `-v1` are level 1, `-v2` is level 2, `-v0` is silent, and any other character
        after it is refused with a word and the level left alone.
        """
        return self["verbose"]

    @verbose.setter
    def verbose(self, level):
        if level not in (0, 1, 2):
            raise ValueError("verbosity is 0, 1 or 2, not %r" % (level,))
        self["verbose"] = int(level)

    @property
    def no_enter(self) -> bool:
        """Whether the run ends without waiting for the enter key."""
        return self["no_enter"]

    @no_enter.setter
    def no_enter(self, wanted):
        self["no_enter"] = self.check_truth("no_enter", wanted)

    def __repr__(self) -> str:
        return "%s(%s)" % (
            type(self).__name__,
            ", ".join("%s=%r" % one for one in sorted(self.items())),
        )
