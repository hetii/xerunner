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


def for_dump(raw: bytes, prefer: Board | None = None) -> Board:
    """A console whose flash is the shape this dump is, to read the dump with.

    The original works it out from the dump and says so -- "Detecting NAND controller
    type from dump data... NAND dump is from a small block machine / NAND dump uses big
    block controller" -- and so builds an image of one shape from a dump of another.
    Reading with the wrong geometry is not an error anything notices: two flashes of one
    length can lay their spare out differently, and then the settings blobs are scanned
    at the wrong offsets and an older copy of the filesystem table is read as the live
    one.

    Two things decide it and both are in the dump: its length, and the erase block its
    own header states at 0x70, which is zero where the controller is a small block one.
    x360mcp reads the controller off that same field. Among the consoles here those two
    tell every flash apart. `prefer` is taken when it fits, so a dump read for its own
    console is read exactly as that console's.
    """
    stated = int.from_bytes(bytes(raw[0x70:0x74]), "big")
    fits = [
        board for board in ((prefer,) if prefer is not None else ()) + ALL
        if board.flash.raw_length == len(raw)
        and (board.flash.block_size if board.flash.states_block_size else 0) == stated
    ]
    if not fits:
        raise ValueError(
            "a dump of %#x bytes stating an erase block of %#x is no flash this knows"
            % (len(raw), stated)
        )
    return fits[0]


def names() -> tuple[str, ...]:
    """Every `-c` name there is, in the order the consoles are listed."""
    return tuple(one for board in ALL for one in board.spellings)
