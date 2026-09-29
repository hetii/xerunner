"""Each client action, from the connection to the files it leaves behind."""

import os
import logging

from .. import boards
from ..release import Patches
from ..network.updsrv import PORT
from ..network.info import PUBLIC_KEYS
from ..network import ConsoleInfo, Server, find
from .sysdata import found, send_avatars, send_compatibility

logger = logging.getLogger(__name__)

# What each power-on reason is called in an options.ini and described as, on a slim
# console and on a fat one: the original's own lines (0x45B4D0), which name the wired
# controller's ports differently by the board. Anything else is the eject button.
REASONS = {
    0x11: ("power", "console power button", None),
    0x20: ("remopower", "IR power button", None),
    0x22: ("remox", "IR guide/X button", None),
    0x24: ("winbutton", "IR windows button", None),
    0x41: ("kiosk", "KIOSK debug pin", None),
    0x55: ("wirelessx", "wireless controller", None),
    0x56: ("wiredxf1", "wired controller (front left usb port)",
           "wired controller (front top usb port)"),
    0x57: ("wiredxf2", "wired controller (front right usb port)",
           "wired controller (front bottom usb port)"),
    0x58: ("wiredxb2", "wired controller (rear middle usb port)",
           "wired controller (INVALID FOR FATS!!)"),
    0x59: ("wiredxb1", "wired controller (rear top usb port)",
           "wired controller (INVALID FOR FATS!!)"),
    0x5A: ("wiredxb3", "wired controller (rear bottom usb port)",
           "wired controller (rear usb port)"),
}


def reason(byte: int, fat: bool, report: bool = False) -> tuple:
    """`(name, description)` of a power-on reason, as the original gives them.

    Its report keeps a table of its own (0x40D370), which says "power button" where
    the options.ini's says "console power button" -- measured -- and agrees on the
    rest.
    """
    name, slim, older = REASONS.get(byte, ("eject", "console eject button", None))
    said = older if fat and older else slim
    if report and byte == 0x11:
        said = "power button"
    return name, said


def run_client(config, port: int = PORT) -> None:
    """Connect, say what the console is, do the one action, and hang up -- with a
    shutdown or a reboot in place of the hang-up where asked."""
    address = config.address or find()
    with Server(address, port) as server:
        info = ConsoleInfo(server.info())
        version, peek = info.server_version
        logger.info("connected to %s with updsvr version %d (peek version %d)",
                    info.hardware_type, version, peek)
        action = config.action
        if action == "info":
            _info(server, info, config.directory)
        elif action == "read":
            _save(config.file, server.flash(), "system area")
        elif action == "read-blocks":
            _save(config.file, server.read_blocks(config.block, config.length),
                  "%#x (%d) blocks from block %#x (%d)" % (config.length, config.length,
                                                           config.block, config.block))
        elif action == "keys":
            _keys(info, ".")
        elif action == "write":
            _write(server, info, config.file)
        elif action == "write-blocks":
            _write_blocks(server, info, config.file, config.block)
        elif action == "patches":
            _patches(server, info, config.file)
        elif action in ("avatar", "compatibility"):
            # Both refused without a hard disk, before anything is sent (0x4088C9).
            if not info.hdd:
                raise ValueError("cannot send %s data when a HDD does not exist!"
                                 % ("avatar" if action == "avatar"
                                    else "xbox compatibility"))
            if action == "avatar":
                send_avatars(server, config.directory, info.word(4))
            else:
                send_compatibility(server, config.directory)
        elif action == "binary-patch":
            _binary_patch(server, info, config.file, config.offset)
        elif action == "erase-block":
            logger.info("erasing block %#x...", config.block)
            server.erase_blocks(config.block)
            logger.info("erased block %#x", config.block)
        elif action is not None:
            raise ValueError("%s is not an action this implements yet" % action)
        if config.shutdown:
            logger.info("sending shutdown command")
            server.shut_down()
        elif config.reboot:
            logger.info("sending reboot command")
            server.reboot()


def _save(path: str, body: bytes, what: str) -> None:
    with open(path, "wb") as handle:
        handle.write(body)
    logger.info("wrote %s to %s, %#x (%d) bytes", what, path, len(body), len(body))


def _info(server, info: ConsoleInfo, directory: str | None) -> None:
    """`-i`: the console's report; with a directory, what build mode needs from it --
    the flash as `nanddump.bin`, an `options.ini`, the fuses and the public keys.

    The original asks for the flash header (`GETFflash_hdr`, the first page) for the
    boot options and the bad block list (`GTBB`) before the flash, and so does this.
    It writes the keys and the fuses beside the directory rather than in it --
    `got1BL_pub.bin` for `-i got`, measured -- its name and theirs run together with
    nothing between. This writes them inside it, a deliberate divergence.
    """
    board, hack = info.image_type
    checks = info.key_checks()
    logger.info("running kernel  : %s", info.kernel)
    logger.info("bootstrap type  : %s", info.bootstrap_type)
    logger.info("hardware type   : %s", info.hardware_type)
    logger.info("hardware flags  : 0x%08x", info.hardware)
    logger.info("internal HDD    : %s", "present" if info.hdd else "not present")
    # A server older than 3 stops the report here (0x431AA8), and `-i` still goes on
    # to the bad blocks and the flash but writes nothing else -- measured on the
    # original against a stand-in console saying version 2.
    current = info.server_version[0] >= 3
    header = None
    if current:
        logger.info("Image Type      : %s (%s)", board, hack)
        logger.info("CPU key         : %s (weight:%#x %s; ecd: %s)",
                    info.cpu_key.hex().upper(), checks["cpu weight"],
                    "valid" if checks["cpu weight"] == 53 else "error",
                    "valid" if checks["cpu ecd"] else "error")
        logger.info("DVD key         : %s", info.dvd_key.hex().upper())
        logger.info("1BL key         : %s (%s)", info.one_bl_key.hex().upper(),
                    "good" if checks["1bl"] else "bad")
        for number, line in enumerate(info.fuses):
            logger.info("fuseset %02d: %s", number, line.hex().upper())
        logger.info("Virtual Fuses   : %s",
                    "present" if any(any(one) for one in info.virtual_fuses)
                    else "not present")
        for name, _file, _at, _wanted in PUBLIC_KEYS:
            logger.info("%s RSA pub : %s", name, "good" if checks[name] else "bad")
        header = server.file("flash_hdr")
        if header:
            logger.info("Xell Reason     : %s",
                        reason(header[0x4F], info.fat, True)[1])
            if header[0x4E]:
                logger.info("Xell Alt Reason : %s",
                            reason(header[0x4E], info.fat, True)[1])
            if header[0x4D] & 1:
                logger.info("UART speed      : cygnos/demon speed set")
        logger.info("CF LDV          : %d", info.ldv)
        logger.info("Pairing Value   : 0x%06x", info.pairing)
    else:
        logger.error("updsvr on console needs to be updated!")
    bad = server.bad_blocks()
    if bad:
        logger.info("the console lists %#x bytes of bad blocks", len(bad))
    if directory is None:
        return
    os.makedirs(directory, exist_ok=True)
    _save(os.path.join(directory, "nanddump.bin"), server.flash(), "the flash")
    if not current:
        return
    with open(os.path.join(directory, "options.ini"), "w", newline="\n") as handle:
        handle.write(options_ini(info, header))
    with open(os.path.join(directory, "fuses.txt"), "w", newline="\n") as handle:
        handle.write(fuses_txt(info))
    _keys(info, directory, one_bl=False)


def options_ini(info: ConsoleInfo, header: bytes | None) -> str:
    """The settings the original writes for build mode, byte for byte on every
    answer measured: type, a good 1BL key, CPU key, lockdown, DVD key, and what the
    flash header says of how the console starts (0x430E00) -- the button XeLL starts
    on and a second one, `cygnos` and `nodvd` from the boot options, and on a JTAG
    image with the header's 0x4B set, the dual-boot button. A button carries its
    description after a `;`."""
    board, hack = info.image_type
    out = "type = %s;\n\n" % board
    # Only a 1BL key that sums as one does is written -- measured with one spoiled.
    if info.key_checks()["1bl"]:
        out += "1blkey = %s\n\n" % info.one_bl_key.hex().upper()
    out += "cpukey = %s\n\n" % info.cpu_key.hex().upper()
    out += "cfldv = %d;\n\n" % info.ldv
    out += "dvdkey = %s\n\n" % info.dvd_key.hex().upper()
    if not header:
        return out
    for key, at in (("xellbutton", 0x4F), ("xellbutton2", 0x4E)):
        if key == "xellbutton" or header[at]:
            out += "%s = %s; %s\n\n" % (key, *reason(header[at], info.fat))
    if header[0x4D] & 1:
        out += "cygnos = true;\n\n"
    if header[0x4D] & 2:
        out += "nodvd = true;\n\n"
    if hack == "JTAG" and header[0x4B] == 1 and header[0x4C]:
        out += "dualboot = %s; %s\n\n" % reason(header[0x4C], info.fat)
    return out


def fuses_txt(info: ConsoleInfo) -> str:
    return "\n" + "".join("fuseset %02d: %s\n" % (number, line.hex().upper())
                          for number, line in enumerate(info.fuses))


def _keys(info: ConsoleInfo, directory: str, one_bl: bool = True) -> None:
    """`-keys`: the 1BL key as `1blkey.txt` and the three public keys, each only where
    the original would call it good (0x406CC8, 0x406CFC)."""
    checks = info.key_checks()
    if one_bl:
        if checks["1bl"]:
            with open(os.path.join(directory, "1blkey.txt"), "w", newline="\n") as out:
                out.write(info.one_bl_key.hex().upper() + "\n")
        else:
            logger.error("the 1BL key is not valid; not written")
    for name, file, at, _wanted in PUBLIC_KEYS:
        if checks[name]:
            _save(os.path.join(directory, file), info.public_key(at),
                  "the %s public key" % name)
        else:
            logger.error("the %s public key is not the one expected; not written", name)


def _write(server, info: ConsoleInfo, path: str) -> None:
    """`-w`: the whole system area sent back, as the file holds it."""
    with open(path, "rb") as handle:
        body = handle.read()
    logger.info("read %#x bytes from %s.", len(body), path)
    server.write_flash(body)
    logger.info("file sent OK, the console answered OK")


def _write_blocks(server, info: ConsoleInfo, path: str, first: int) -> None:
    """`-wb`: as many whole raw blocks as the file holds, from `first` on."""
    with open(path, "rb") as handle:
        body = handle.read()
    step = info.block_length
    if not step or len(body) % step:
        raise ValueError("%s is %#x bytes, not a whole number of %#x byte blocks"
                         % (path, len(body), step))
    count = len(body) // step
    logger.info("writing %#x (%d) blocks to the console from block %#x (%d)", count,
                count, first, first)
    server.write_blocks(first, body, count)
    logger.info("wrote %#x (%d) bytes to the console's flash", len(body), len(body))


def _patches(server, info: ConsoleInfo, path: str | None) -> None:
    """`-p`: the console's patches replaced, from a file or from the release named
    after its running kernel.

    Automatically the file is `<build>/bin/patches_<prefix><board>.bin` beside where
    this runs, the prefix and the board by the hack the console reports, as the
    original picks it -- measured on eight consoles made up for it: `fat` alone for
    Glitch on any board, `g2` and `g2m` with the board for Glitch2 and Glitch2M, the
    board alone for JTAG, and a retail console refused, "unable to determine console
    hack type!". The name is found whatever its case, as the original, on a file
    system that ignores case, finds `patches_g2Trinity.bin`.

    The console's current patches are asked for first (`GETFpatches`) and the update
    stops without them, as the original's does. What goes back is what build mode lays
    in the patch slot: a JTAG console takes the whole file, a Glitch2M one the last set
    alone, and the others sixteen bytes of 0xFF and the last set -- each measured.
    The original's usage says an addon already on the console is kept; a console slot
    carrying one, as build mode's `-a` lays it, was not taken for one, so what it
    recognises as an addon is not known, and nothing here keeps one.
    """
    board, hack = info.image_type
    if path is None:
        prefix = {"JTAG": "", "Glitch2": "g2", "Glitch2M": "g2m"}.get(hack)
        if hack.startswith("Glitch") and prefix is None:
            prefix, board = "fat", ""
        if prefix is None:
            raise ValueError("unable to determine console hack type!")
        named = info.bootstrap_type if board else ""
        path = found(os.path.join(info.kernel.split(".")[2], "bin"),
                      "patches_%s%s.bin" % (prefix, named))
        logger.info("updating patches in auto mode: %s", path)
    with open(path, "rb") as handle:
        body = handle.read()
    current = server.file("patches")
    if current is None:
        raise ValueError("failed to retrieve current patches from console!")
    patches = Patches(body)
    last = patches.set_raw(len(patches.sets) - 1)
    if hack == "JTAG":
        sent = body
    elif hack == "Glitch2M":
        sent = last
    else:
        sent = b"\xff" * 0x10 + last
    server.write_patches(sent)
    logger.info("patches updated OK")


def _binary_patch(server, info: ConsoleInfo, path: str, offset: int) -> None:
    """`-bp`: the file's bytes put into the flash at a logical offset -- one that
    counts no spare -- by reading the blocks it touches, patching them and writing them
    back, as the original's 0x407BF0 does.

    Sizes are the console's own, counted logically: its flash length and block length
    in `GTIN` come with spare, 0x4200 bytes to every 0x4000, and an eMMC console's
    (0x3000000) have none. A file that would reach the end of the flash is refused.
    Each page the file lands in has its bytes put into its 0x200 of data and its
    code recomputed (0x40FBB0, `Spare.with_ecc`); on eMMC the bytes go in as they
    are.

    **The block it starts at is `offset // block` here, where the original's is
    always zero**: at 0x407CC9 it divides the remainder instead of the offset, so every
    `-bp` reads, patches and writes back the first blocks of the flash -- measured,
    it overwrote a console's flash header. The position inside the block and the
    number of blocks it computes are right, and this keeps them. A deliberate
    divergence: the fault destroys a console, and the usage says what was meant.
    """
    with open(path, "rb") as handle:
        body = handle.read()
    if not body:
        raise ValueError("Unable to read file %s!" % path)
    emmc = info.flash_length == 0x3000000
    if emmc:
        size, block = info.flash_length, info.block_length
    else:
        size = info.flash_length // 0x4200 * 0x4000
        block = info.block_length // 0x4200 * 0x4000
    if offset + len(body) >= size:
        raise ValueError("File %s size patched into offset 0x%x will exceed NAND "
                         "system area (0x%x)!" % (path, offset, size))
    first, inside = divmod(offset, block)
    count = -(-(inside + len(body)) // block)
    logger.info("Reading 0x%x blocks from console starting at block 0x%x (%d)...",
                count, first, first)
    raw = bytearray(server.read_blocks(first, count))
    if emmc:
        raw[inside:inside + len(body)] = body
    else:
        # Page by page: 0x200 of data, then 0x10 of spare the patch never reaches.
        spare = next(one.flash.spare for one in boards.ALL
                     if one.flash.spare is not None)
        at = 0
        while at < len(body):
            page, within = divmod(inside + at, 0x200)
            take = min(0x200 - within, len(body) - at)
            start = page * 0x210
            raw[start + within:start + within + take] = body[at:at + take]
            data = bytes(raw[start:start + 0x200])
            raw[start + 0x200:start + 0x210] = spare.with_ecc(
                data, bytes(raw[start + 0x200:start + 0x210]))
            at += take
    logger.info("Writing 0x%x blocks to console starting at block 0x%x...", count,
                first)
    server.write_blocks(first, bytes(raw), count)
    logger.info("Success! Completed patching NAND!")
