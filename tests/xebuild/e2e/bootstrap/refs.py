"""Reference images: whole builds of the original, one per type and board.

Each is `-t <type> -c <board> -f 17559 -d data` over the console's dump, with
J-Runner's options.ini and loaders and one of its SMC images as `smc.bin`. The SMC goes
in under the dump's own seed -- the four bytes its cipher discards -- in place of the
file's, which is how the images the tests were written against were laid. Each keeps the
clock it was first built at, so the console these were measured on gets them back byte
for byte.
"""

import os
import concurrent.futures

from . import runs
from .material import digest

# (type, board, J-Runner SMC, the clock it was built at)
IMAGES = (
    ("glitch", "falcon", "FALCON_SMC+.bin", 0x6AB3ED9A),
    ("glitch", "trinity", "TRINITY_SMC+.bin", 0x6AB3ED98),
    ("glitch", "trinitybb", "TRINITY_SMC+.bin", 0x6AB3ED98),
    ("glitch2", "corona4g", "CORONA_SMC+.bin", 0x6AB3ED9E),
    ("glitch2", "falcon", "FALCON_SMC+.bin", 0x6AB3EDA0),
    ("glitch2", "trinity", "TRINITY_SMC+.bin", 0x6AB3ED9C),
    ("glitch2", "trinitybb", "TRINITY_SMC+.bin", 0x6AB3ED9C),
    ("glitch2m", "corona4g", "CORONA_SMC+.bin", 0x6AB3EDA2),
    ("glitch2m", "falcon", "FALCON_SMC+.bin", 0x6AB3EDA4),
    ("glitch2m", "trinity", "TRINITY_SMC+.bin", 0x6AB3EDA0),
    ("glitch2m", "trinitybb", "TRINITY_SMC+.bin", 0x6AB3EDA2),
    ("jtag", "falcon", "SMCfzj.bin", 0x6AB3EDA6),
    ("retail", "corona4g", "CORONA_CLEAN.bin", 0x6AB3ED96),
    ("retail", "falcon", "FALCON_CLEAN.bin", 0x6AB3ED96),
    ("retail", "trinity", "TRINITY_CLEAN.bin", 0x6AB3ED92),
    ("retail", "trinitybb", "TRINITY_CLEAN.bin", 0x6AB3ED94),
)


def make(material) -> dict:
    console = material.console
    where = material.made("refs", {"dump": digest(console.dump), "key": console.key},
                          lambda into: _build_all(material, into))
    return {"XEBUILD_REFS": where,
            "XEBUILD_REFERENCE_IMAGE": os.path.join(where, "glitch2-trinity.bin"),
            "XEBUILD_EMMC": os.path.join(where, "retail-corona4g.bin")}


def _build_all(material, into: str) -> None:
    with concurrent.futures.ThreadPoolExecutor(runs.WORKERS) as pool:
        for failed in pool.map(lambda one: _build(material, into, *one), IMAGES):
            if failed:
                raise RuntimeError(failed)


def _build(material, into: str, kind: str, board: str, smc: str, when: int):
    name = "%s-%s.bin" % (kind, board)
    work = os.path.join(into, "run-" + name)
    data = os.path.join(material.xebuild, "data")
    with open(os.path.join(data, smc), "rb") as handle:
        plain = material.console.smc_seed + handle.read()[4:]
    runs.lay(material, work, {**runs.console_files(material), "smc.bin": plain}, when)
    said = runs.build(material, work, ["-t", kind, "-c", board, "-f", "17559", "-d",
                                       "data", "-noenter", "out.bin"])
    return runs.keep(work, "out.bin", os.path.join(into, name), said)
