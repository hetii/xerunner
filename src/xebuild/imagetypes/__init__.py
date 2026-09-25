"""Every kind of image the tool builds, one class each.

Eleven names over nine numbers: the three glitches share number 3, and the numbering is
what the original tests rather than the name. The names are the ones its own acceptance
table holds -- read out of the binary, where each sits beside the message it logs -- and
not the six its usage text lists.

Four of the eleven have never been built here, because no release carries a `_devkit`,
`_devkit16`, `_testkit` or `_testkit16` file list. They still say what the original
reaches for, since that much was measured by asking it.
"""

from .jtag import Jtag
from .retail import Retail
from .imagetype import ImageType
from .devgl import Devgl, Devgl16
from .devkit import Devkit, Devkit16
from .testkit import Testkit, Testkit16
from .glitch import Glitch, Glitch2, Glitch2Mfg

ALL = (
    Retail(),
    Jtag(),
    Glitch2Mfg(),
    Glitch2(),
    Glitch(),
    Devkit16(),
    Devkit(),
    Testkit16(),
    Testkit(),
    Devgl16(),
    Devgl(),
)

def for_name(given: str) -> ImageType:
    """The kind of image a `-t` value means.

    The order `ALL` is in is the order the original compares them, so that a longer
    name is reached before the shorter one it starts with.
    """
    wanted = str(given).strip().lower()
    for kind in ALL:
        if kind.name == wanted:
            return kind
    raise ValueError(
        "%s is not an image type; they are %s" % (given, ", ".join(names()))
    )


def names() -> tuple[str, ...]:
    """Every `-t` value there is, in the order the original compares them."""
    return tuple(kind.name for kind in ALL)
