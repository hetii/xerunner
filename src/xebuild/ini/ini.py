"""The system update's file list, as the original writes it."""

import os
import logging
import binascii

from ..files import beside
from ..chain import sealing
from ..build import Material
from ..chain.stage import Stage
from ..release.recipe import canonical
from ..release.container import Container, intact

logger = logging.getLogger(__name__)


def _crc(body: bytes) -> int:
    return binascii.crc32(bytes(body)) & 0xFFFFFFFF


def locate(path: str) -> tuple:
    """`(container, output)`: where the container is, and where its list goes.

    The original tries three places (0x40CC80): the path as a file, then
    `su20076000_00000000` in it, then in `$SystemUpdate` in it. The list goes beside the
    container, `<path>_SU.ini` for a file named outright and `_SU.ini` in the directory
    otherwise -- measured: `d/_SU.ini`, `x/$SystemUpdate/_SU.ini`, `mysu.bin_SU.ini`.
    Both names are found whatever their case, as where the original runs.
    """
    if os.path.isfile(path):
        return path, path + "_SU.ini"
    for where in (path, beside(path, "$SystemUpdate")):
        found = beside(where, "su20076000_00000000") if where else None
        if found is not None:
            return found, os.path.join(where, "_SU.ini")
    raise ValueError("system update container not found at or near %s!!" % path)


def listing(container: Container) -> str:
    """The list, line by line as the original writes it (0x418680, 0x418450).

    `[bl]` holds the CF and the CG, each checksummed as a release's list checksums
    them -- `recipe.canonical` -- under the CF's build number. `[flashfs]` holds every
    file of the container in its order: a `$flash_` file by its name without that,
    and the rest commented out by their whole name, as are `systemupdate*` and
    `oddupd*`. In front of three fonts and a dictionary goes a line of the original's
    own, "added by xebuild", for the base file their patch applies to. Names are
    matched without regard to case: 7258 holds `$flash_XenonCLatin.xttp`, and its
    line is added.
    """
    cf, cg = container.stages
    build = Stage(cf, 0).build
    lines = ["[version]", "%d" % build, "", "[bl]",
             "cf_%d.bin,%08x" % (build, _crc(canonical(cf, "CF"))),
             "cg_%d.bin,%08x" % (build, _crc(canonical(cg, "CG"))), "", "[flashfs]"]
    added = {"xenonclatin.xttp": "xenonclatin.xtt,d5d17ff5",
             "xenonjklatin.xttp": "xenonjklatin.xtt,dde4a14c",
             "ximedic.xexp": "ximedic.xex,1d992bfb"}
    for held in container.held:
        crc = _crc(container.read(held))
        if not held.lower().startswith("$flash_"):
            lines.append(";%s,%08x; commented by xebuild" % (held, crc))
            continue
        name = held[len("$flash_"):]
        for stem, line in added.items():
            if name.lower().startswith(stem):
                lines.append("%s; added by xebuild" % line)
        if name.lower().startswith(("systemupdate", "oddupd")):
            lines.append(";%s,%08x; commented by xebuild" % (name, crc))
        else:
            lines.append("%s,%08x" % (name, crc))
    return "".join(line + "\r\n" for line in lines)


def write_su_ini(config) -> str:
    """Ini mode, whole: the list written beside the container. Returns where it went.

    The 1BL key comes from `1blkey.txt` where the tool runs. A key that fails its sum
    is refused before anything is read -- "1blkey.txt not found or invalid, cannot
    proceed" -- and with none at all the container is still read and checked, and the
    CF is what fails: "could not get CF data from SU!". Measured, both, as the original
    does them; a key that passes is the one every console has, and the CF opens under
    no other.
    """
    key = Material(".").key_in_file("1blkey.txt")
    if key is not None and sealing.key_sum(key) != sealing.key_sum(sealing.ONE_BL_KEY):
        raise ValueError("1BL key 0x%s does not appear to be correct! 1blkey.txt not "
                         "found or invalid, cannot proceed." % key.hex().upper())
    where, out = locate(config.system_update)
    logger.info("SU container found! Loading '%s'", where)
    with open(where, "rb") as handle:
        raw = handle.read()
    if not intact(raw, content_type=0x000B0000, title=0xFFFE07D1, magic=b"SUPD"):
        raise ValueError("checks failed! Container corrupt! could not load container "
                         "'%s'!" % where)
    if key != sealing.ONE_BL_KEY:
        raise ValueError("could not get CF data from SU!")
    text = listing(Container(raw))
    logger.info("output set to file '%s'", out)
    with open(out, "wb") as handle:
        handle.write(text.encode("latin-1"))
    logger.info("Completed output to %s", out)
    return out
