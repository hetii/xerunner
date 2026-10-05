"""The console the material is built around: its dump, its key, and what the original
says of them.

`XEBUILD_E2E_DUMP` names a dump and `XEBUILD_E2E_CPUKEY` its key, and
`XEBUILD_E2E_BOARD` the name `-c` takes for it when the board its SMC names is not
enough -- a big block or larger-filesystem variant. Without a dump the original builds
one from J-Runner's donor files under a key made up for it, as J-Runner does for a
console whose flash is lost; see `donor`. `XEBUILD_E2E_FOREIGN_DUMP` (and
`XEBUILD_E2E_FOREIGN_BOARD`) name the other console a build is handed files of, the
foreign donor otherwise.

What a test expects of the console -- its serial, lockdown value, pairing, the blobs and
whether it keeps a manufacturing block -- is what the original prints for it, read out
of its log, never out of this tool.
"""

import os
import re
import shutil

from . import runs
from .material import digest

class Console:
    """The console's files and the variables naming them."""

    def __init__(self, where: str):
        self.where = where
        self.dump = os.path.join(where, "nanddump.bin")
        with open(os.path.join(where, "console.txt")) as handle:
            self.key, self.board = handle.read().split()
        with open(os.path.join(where, "original.txt"), encoding="latin-1") as handle:
            said = handle.read()
        # The first four bytes of the dump's SMC as it decrypts: the cipher's seed.
        with open(os.path.join(where, "smc-seed.bin"), "rb") as handle:
            self.smc_seed = handle.read()
        self.env = {
            "XEBUILD_DUMP": self.dump,
            "XEBUILD_CPUKEY": self.key,
            "XEBUILD_DUMP_BOARD": self.board,
            "XEBUILD_SEALED_SMC": os.path.join(where, "smc-sealed.bin"),
            **told(said),
        }


def told(said: str) -> dict:
    """What the original's log says of the console, as the tests' variables."""
    found = {}
    serial = re.search(r"^Serial\s*:\s*(\d+)", said, re.M)
    if serial:
        found["XEBUILD_SERIAL"] = serial.group(1)
    ldv = re.search(r"^CF LDV\s*:\s*(\d+)", said, re.M)
    if ldv:
        found["XEBUILD_LDV"] = ldv.group(1)
    pairing = re.search(r"^pairing set to: ([0-9a-fA-F ]+)$", said, re.M)
    if pairing:
        found["XEBUILD_PAIRING"] = pairing.group(1).replace(" ", "").lower()
    blobs = []
    for name, version, offset in re.findall(
            r"^\s+(\S+)\s+version (\d+) found at offset (0x[0-9a-f]+)", said, re.M):
        # The original prints `mobileB.dat`; the file is `MobileB.dat`.
        name = "M" + name[1:] if name.startswith("mobile") else name
        blobs.append("%s:%d:%s" % (name, int(version), hex(int(offset, 16))))
    if blobs:
        found["XEBUILD_DUMP_BLOBS"] = " ".join(blobs)
    found["XEBUILD_MANUFACTURING"] = (
        "yes" if "Manufacturing.data found at offset" in said else "no")
    return found


def make(material) -> Console:
    """The console part: the dump given, or the donor console's image."""
    given = os.environ.get("XEBUILD_E2E_DUMP", "")
    if given:
        key = os.environ.get("XEBUILD_E2E_CPUKEY", "").strip().upper()
        if len(key) != 32:
            raise RuntimeError("XEBUILD_E2E_DUMP names a dump, and XEBUILD_E2E_CPUKEY "
                               "has to name its CPU key, 32 hex digits")
        with open(given, "rb") as handle:
            raw = handle.read()
        board = os.environ.get("XEBUILD_E2E_BOARD", "") or board_of(raw)
    else:
        from . import donor
        given, board, key = donor.image(material, "console")
        with open(given, "rb") as handle:
            raw = handle.read()
    return Console(material.made(
        "console", {"dump": digest(given), "key": key, "board": board},
        lambda into: lay(material, into, raw, key, board)))


def lay(material, into: str, raw: bytes, key: str, board: str) -> None:
    """The console's files, and the original's log of one build from them."""
    from xebuild.boards import for_name
    from xebuild.image import Image
    with open(os.path.join(into, "nanddump.bin"), "wb") as handle:
        handle.write(raw)
    with open(os.path.join(into, "console.txt"), "w") as handle:
        handle.write("%s %s\n" % (key, board))
    image = Image(raw, for_name(board)[0].flash)
    head = image.header
    sealed = bytes(image.flat[head.smc_at:head.smc_at + head.smc_size])
    with open(os.path.join(into, "smc-sealed.bin"), "wb") as handle:
        handle.write(sealed)
    from xebuild.crypto.formats import decrypt_smc
    with open(os.path.join(into, "smc-seed.bin"), "wb") as handle:
        handle.write(decrypt_smc(sealed)[:4])
    data = os.path.join(material.xebuild, "data")
    work = runs.lay(material, os.path.join(into, "run"), {
        "nanddump.bin": os.path.join(into, "nanddump.bin"),
        "cpukey.txt": key.encode(),
        "options.ini": os.path.join(data, "options.ini"),
        **{name: os.path.join(data, name) for name in runs.XELL}})
    said = runs.build(material, work, ["-t", "glitch2", "-c", board, "-f", "17559",
                                       "-d", "data", "-noenter", "-v", "out.bin"])
    with open(os.path.join(into, "original.txt"), "w", encoding="latin-1") as handle:
        handle.write(said)
    shutil.rmtree(work)


def board_of(raw: bytes) -> str:
    """The board the dump's own SMC names, as `-c` spells it."""
    from xebuild.crypto.formats import decrypt_smc
    from xebuild.smc import Smc
    from xebuild.boards import for_name
    from xebuild.image import Image
    image = Image(raw, for_name("trinity")[0].flash)
    head = image.header
    smc = Smc(decrypt_smc(bytes(image.flat[head.smc_at:head.smc_at + head.smc_size])))
    if not smc.motherboard:
        raise RuntimeError("the dump's SMC names no board; say which with "
                           "XEBUILD_E2E_BOARD")
    return smc.motherboard.lower()


def foreign(material) -> tuple:
    """Another console, whose sealed files a build is handed as not its own: the dump
    `XEBUILD_E2E_FOREIGN_DUMP` names, or the foreign donor's image. Returns its dump,
    the board `-c` takes for it, and a digest for the stamps."""
    given = os.environ.get("XEBUILD_E2E_FOREIGN_DUMP", "")
    if given:
        with open(given, "rb") as handle:
            raw = handle.read()
        board = os.environ.get("XEBUILD_E2E_FOREIGN_BOARD", "") or board_of(raw)
    else:
        from . import donor
        given, board, _ = donor.image(material, "foreign")
        with open(given, "rb") as handle:
            raw = handle.read()
    where = material.made("foreign", {"dump": digest(given), "board": board},
                          lambda into: _keep_foreign(into, raw, board))
    with open(os.path.join(where, "nanddump.bin"), "rb") as handle:
        return handle.read(), board, digest(os.path.join(where, "nanddump.bin"))


def _keep_foreign(into: str, raw: bytes, board: str) -> None:
    with open(os.path.join(into, "nanddump.bin"), "wb") as handle:
        handle.write(raw)
    with open(os.path.join(into, "board.txt"), "w") as handle:
        handle.write(board + "\n")
