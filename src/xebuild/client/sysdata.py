"""What goes on a console's hard disk rather than its flash: avatar data, from a system
update's manifest, and compatibility data, a directory copied as it stands.

Both format a partition first, so whatever was on it is gone. Both were run on the
original against a stand-in server that records the wire -- the 17559 system update's
151 files, and trees made up for `-c` -- and this sends the same commands, in the same
order, with the same bytes.
"""

from __future__ import annotations

import os
import hashlib
import logging
import contextlib

from ..network import ServerError
from ..release.container import intact
from ..release.manifest import Manifest

logger = logging.getLogger(__name__)


def found(directory: str, name: str) -> str:
    """`name` in `directory` whatever its case, or the name as it stands -- the
    original runs where case does not count."""
    if os.path.isdir(directory):
        for one in sorted(os.listdir(directory)):
            if one.lower() == name.lower():
                return os.path.join(directory, one)
    return os.path.join(directory, name)


def _quietly_unmount(server, drive: str) -> None:
    """The unmount the original sends on its way out of a failure, whose answer it
    does not look at."""
    with contextlib.suppress(ServerError, OSError):
        server.unmount(drive)


def avatar_items(where: str, kernel: int) -> tuple:
    """`(manifest, directories, [(path on the console, bytes)])` for a system update
    in `where`, checked as the original checks it before it formats anything
    (0x432B10) -- or ValueError, saying why, in its words.

    The manifest is `system.manifest` in `where`, then in `$SystemUpdate` under it.
    The original adds those names to the directory as given, with no separator of its
    own, so `-e su` looks for `susystem.manifest` and finds nothing -- measured. That
    is a fault, and this joins them as paths: a deliberate divergence.

    It has to be the running kernel's version, the bottom nibble aside -- "must match
    running kernel", as the usage says. Each row is then loaded and checked, and the
    first that fails ends it: a container must hold together (`intact`) and be as long
    as its row says, a plain file must be as long and hash to the row's SHA-1. `flash`
    is the image and is passed over, and so is a row of any other kind, silently. At
    most 0x100 files, the size of the original's list; rows past that are dropped.

    Where each goes, measured: a container to `Content\\0000000000000000\\<title>\\
    <type>\\`, a plain file to a directory named for its row's version. The directories
    are the running kernel's version first, then each other version a plain file
    names, then the content tree -- four fixed names (0x45C644), made whatever the
    containers' titles are.
    """
    kernel &= 0xFFFFFFF0
    for path in (os.path.join(where, "system.manifest"),
                 os.path.join(where, "$SystemUpdate", "system.manifest")):
        if os.path.isfile(path):
            break
        logger.debug("manifest not found at %s", path)
    else:
        raise ValueError("could not find manifest data for sysex!")
    logger.debug("loading manifest %s", path)
    with open(path, "rb") as handle:
        manifest = Manifest(handle.read())
    if not manifest.raw:
        raise ValueError("could not read manifest data for sysex!")
    said = manifest.refusal()
    if said:
        raise ValueError(said)
    version = manifest.version
    logger.debug("Manifest flash version: %d.%d.%d.%d", version >> 28,
                 (version >> 24) & 0xF, (version >> 8) & 0xFFFF, version & 0xF)
    if version != kernel:
        raise ValueError("this system extended data is not the correct version!")
    beside = os.path.dirname(path)
    versions, items = [kernel], []
    for entry in manifest.entries:
        if len(items) > 0xFF:
            break
        if entry.source == "flash" or entry.kind not in (2, 3):
            continue
        local = found(beside, entry.source)
        logger.debug("%03d: %s", len(items) + 1, local)
        if not entry.size:
            raise ValueError("%s: input len is 0!" % local)
        if not os.path.isfile(local):
            raise ValueError("%s: could not read file!" % local)
        with open(local, "rb") as handle:
            body = handle.read()
        if entry.kind == 2:
            if not intact(body, entry.header_hash) or len(body) != entry.size:
                raise ValueError("%s: checks failed! Container corrupt!" % local)
            path = "SSEP:\\Content\\0000000000000000\\%08X\\%08X\\%s" % (
                entry.title, entry.content_type, entry.target)
        else:
            if len(body) != entry.size:
                raise ValueError("%s: file size FAIL! 0x%x is not 0x%x!"
                                 % (local, len(body), entry.size))
            if hashlib.sha1(body).digest() != entry.hash:
                raise ValueError("%s: file corrupt, hash check FAILED!!" % local)
            path = "SSEP:\\%08X\\%s" % (entry.version, entry.target)
            if entry.version not in versions:
                versions.append(entry.version)
        items.append((path, body))
    logger.debug("found %d items to send to xbox!", len(items))
    content = ("SSEP:\\Content", "SSEP:\\Content\\0000000000000000",
               "SSEP:\\Content\\0000000000000000\\FFFE07DF",
               "SSEP:\\Content\\0000000000000000\\FFFE07DF\\00008000")
    return manifest, ["SSEP:\\%08X" % one for one in versions] + list(content), items


def send_avatars(server, where: str, kernel: int) -> None:
    """Avatar data from the system update in `where` onto the console's system
    extended partition (0x432E50): everything loaded and checked, the partition
    formatted and mounted as `SSEP:`, the directories made, each file sent and the
    manifest last, and the partition unmounted -- which the original also sends after
    a format, a mount, a directory or a file that failed, and so does this.
    """
    logger.info("loading avatar data...")
    try:
        manifest, directories, items = avatar_items(where, kernel)
    except ValueError as why:
        raise ValueError("%s; avatar data skipped, unable to load data!"
                         % why) from None
    logger.info("formatting HDD partition...")
    try:
        server.format_extended()
    except ServerError:
        _quietly_unmount(server, "SSEP")
        raise ValueError("unable to format sysex partition!") from None
    try:
        server.mount("SSEP", "\\SEP")
    except ServerError:
        _quietly_unmount(server, "SSEP")
        raise ValueError("unable to mount sysex partition!") from None
    sending = None
    try:
        for sending in directories:
            server.make_directory(sending)
            logger.debug("created dir: %s", sending)
        logger.info("sending avatar files to HDD partition...")
        for number, (sending, body) in enumerate(items, 1):
            logger.debug("sending %03d: 0x%08x (%d) bytes, %s", number, len(body),
                         len(body), sending)
            server.send_file(sending, body)
        sending = "SSEP:\\system.manifest"
        server.send_file(sending, manifest.raw)
    except ServerError:
        _quietly_unmount(server, "SSEP")
        raise ValueError("aborting sending avatar data, failed to send %s"
                         % sending) from None
    logger.info("success! Avatar data is successfully sent to the console!")
    server.unmount("SSEP")


def send_compatibility(server, where: str) -> None:
    """`-c`: the compatibility partition formatted, mounted as `XCOM:`, and `where`
    copied onto it as it stands (0x433440) -- nothing is sent unless it holds an
    `index`, and nothing checks what it holds."""
    if not os.path.isfile(found(where, "index")):
        raise ValueError("compatibility data skipped, unable to find index!")
    logger.info("formatting compatibility partition...")
    try:
        server.format_compatibility()
    except ServerError:
        raise ValueError("unable to format compatibility partition!") from None
    try:
        server.mount("XCOM", "\\Device\\Harddisk0\\SystemPartition")
    except ServerError:
        raise ValueError("unable to mount compatibility partition!") from None
    try:
        _send_tree(server, where, "XCOM:")
    except ServerError:
        _quietly_unmount(server, "XCOM")
        raise ValueError("Sending files to compatibility partition failed!") from None
    logger.info("sent files to partition OK!")
    server.unmount("XCOM")


def _send_tree(server, local: str, remote: str) -> None:
    """A directory copied onto the console, in the order the original's walk takes
    (0x433130) -- measured under wine as by name with case not counted. A directory
    whose name begins with a dot is passed over and a file whose does is not, as there;
    a file that cannot be read is passed over without a word; an empty file is sent
    empty."""
    for name in sorted(os.listdir(local), key=str.lower):
        here, there = os.path.join(local, name), remote + "\\" + name
        if os.path.isdir(here):
            if name.startswith("."):
                continue
            logger.debug("creating directory %s...", there)
            server.make_directory(there)
            _send_tree(server, here, there)
        elif os.path.isfile(here):
            try:
                with open(here, "rb") as handle:
                    body = handle.read()
            except OSError:
                continue
            logger.debug("sending file %s, %#x bytes", there, len(body))
            server.send_file(there, body)
