"""Reading one dump the way a build would, and saying what is in it."""

import os
import logging

from .. import boards
from ..image import Dump, dump as dumps, order

logger = logging.getLogger(__name__)


def extract_image(config) -> Dump | None:
    """Read the dump `config.image` names and say what it holds; the dump, or None
    where the original would not read it.

    Each step is the build's own: `image.dump.cut` for a dump longer than any flash,
    `boards.for_dump` for its shape, `image.dump.faulty` for what the original throws
    away, and `Dump.survey` for the rest.
    """
    name = os.path.basename(config.image)
    with open(config.image, "rb") as handle:
        whole = handle.read()
    logger.info("%s file size: %#x", name, len(whole))
    raw = dumps.cut(whole)
    try:
        board = boards.for_dump(raw)
    except ValueError:
        logger.warning("%s is not a correct raw (with ecc) dump size (%#x bytes)", name,
                       len(raw))
        return None
    why = dumps.faulty(raw, board.flash, len(whole))
    if why:
        logger.warning("%s, discarding %s", why, name)
        return None
    # The shape and not the board: one flash serves several consoles, and nothing in
    # a dump names which -- the SMC below does.
    logger.info("read as %s", board.flash.part)
    if board.flash.spare is not None:
        _remaps(raw, board.flash)
    dump = Dump(raw, board)
    dump.survey()
    return dump


def _remaps(raw: bytes, flash) -> None:
    """The blocks the chip has written off or whose code fails, and where each is
    moved to -- the same answer a build acts on, `order.stand_ins`."""
    per = flash.spare.pages_a_block * (flash.spare.length + 0x200)
    for block in order.marked_bad(raw, flash):
        logger.info("bad block at %#x (raw offset %#x)", block, block * per)
    for block in order.failing(raw, flash):
        logger.info("block %#x fails its code (raw offset %#x)", block, block * per)
    for block, stand_in in order.stand_ins(raw, flash, total=len(raw) // per).items():
        logger.info("block %#x is remapped to block %#x", block, stand_in)
