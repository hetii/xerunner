"""Every Xbox 360 console there is, one class each.

Fourteen exist. Seven motherboards were made and five flashes were fitted to them, but
only these fourteen pairings were ever built, so this is a roster and not a matrix: no
entry here stands for a machine nobody made.

J-Runner's own roster lists seventeen, and three of those pairs are one console as far
as an image is concerned -- a Xenon, a Zephyr and a Falcon with the old 64 MB developer
part take the same 16 MB image their 16 MB siblings take.

The fourteen answer to twenty-one `-c` spellings, read out of the original's binary and
each one built with to see what it does. Its usage text lists sixteen of them.
"""

from .board import Board
from .corona import Corona4G, Corona16, CoronaBigBlock
from .falcon import Falcon
from .jasper import Jasper16, JasperBigBlock, JasperXsb
from .trinity import Trinity16, TrinityBigBlock
from .winchester import Winchester4G, Winchester16, WinchesterBigBlock
from .xenon import Xenon
from .zephyr import Zephyr

ALL = (
    Xenon(),
    Zephyr(),
    Falcon(),
    JasperXsb(),
    Jasper16(),
    JasperBigBlock(),
    Trinity16(),
    TrinityBigBlock(),
    Corona16(),
    CoronaBigBlock(),
    Corona4G(),
    Winchester16(),
    WinchesterBigBlock(),
    Winchester4G(),
)


def for_name(given: str) -> tuple[Board, bool]:
    """The console a `-c` name means, and whether it asks for the larger filesystem.

    The larger filesystem is a build's choice and not a property of the machine, so it
    comes back beside the console rather than selecting a different one. Four consoles
    have a spelling for it; the other ten do not, and asking is simply not possible.
    """
    wanted = str(given).strip().lower()
    for board in ALL:
        if wanted in board.spellings:
            return board, wanted == board.bigffs
    raise ValueError(
        "%s is not a console type; the twenty-one are %s"
        % (given, ", ".join(names()))
    )


def names() -> tuple[str, ...]:
    """Every `-c` name there is, in the order the consoles are listed."""
    return tuple(one for board in ALL for one in board.spellings)
