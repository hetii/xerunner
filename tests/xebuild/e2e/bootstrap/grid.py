"""The grid: every `-o` option on every image type, one board each, by the original.

Each cell is one build from the console's dump with one option, J-Runner's SMC for the
type in `smc.bin`. What is kept is small, because the image is not: `manifest.json`
says, cell by cell, the command line's parts, the SHA-256 of the image the original
built and the clock its crl.bin carries -- or that the original refused, and its last
words. `e2e_grid` builds each cell here and holds the image's SHA-256 against it.
"""

import os
import json
import hashlib
import concurrent.futures

from . import runs

OPTIONS = ("nodvd", "olddvd", "cygnos", "demon", "nomobile", "smcnocheck", "noremap",
           "noecdremap", "nandmu", "nosecurity", "nosusecurity", "patchsmc=false",
           "patchsmc", "smcnoeject", "smcnoblink", "cputemp=70", "gputemp=71",
           "edramtemp=72", "overcputemp=85", "overgputemp=86", "overedramtemp=87",
           "cpufan=60", "gpufan=55", "cfldv=10", "avregion=0x100", "gameregion=0x00FF",
           "dvdregion=1", "xellbutton=power", "xellbutton2=power", "dualboot=power",
           "macid=002248F10102", "dvdkey=00112233445566778899AABBCCDDEEFF")

# type: (board, J-Runner SMC, release)
TYPES = {"retail": ("trinity", "TRINITY_CLEAN.bin", "17559"),
         "glitch": ("falcon", "FALCON_SMC+.bin", "17559"),
         "glitch2": ("trinity", "TRINITY_SMC+.bin", "17559"),
         "glitch2m": ("trinity", "TRINITY_SMC+.bin", "17559"),
         "jtag": ("falcon", "SMCfzj.bin", "17559"),
         "devkit": ("falcon", "FALCON_CLEAN.bin", "17489")}

# The options that move the layout, on a big block and an eMMC part as well.
LAYOUT = ("nomobile", "nosecurity", "nosusecurity", "nandmu", "cfldv=10",
          "macid=002248F10102", "cputemp=70")
BOARDS = (("jasperbb", "JASPER_SMC+.bin"), ("corona4g", "CORONA_SMC+.bin"))


def cells() -> list:
    """Every cell as (name, type, board, option, SMC, release)."""
    out = []
    for kind, (board, smc, release) in TYPES.items():
        for option in OPTIONS:
            out.append(("%s-%s-%s" % (kind, board, option), kind, board, option, smc,
                        release))
    for board, smc in BOARDS:
        for option in LAYOUT:
            out.append(("glitch2-%s-%s" % (board, option), "glitch2", board, option,
                        smc, "17559"))
    return out


def make(material) -> dict:
    where = material.made("grid", {"console": material.stamp("console"),
                                   "cells": material.stamp("cells")},
                          lambda into: _make_all(material, into))
    return {"XEBUILD_GRID": where}


def _make_all(material, into: str) -> None:
    # The devkit cells take the cells' own copy of 17489, made-up rawpatch files in it.
    devkit = material.path("cells", "devkit-17489-falcon", "release", "17489")
    with concurrent.futures.ThreadPoolExecutor(runs.WORKERS) as pool:
        found = dict(pool.map(lambda cell: _record(material, into, cell, devkit),
                              cells()))
    with open(os.path.join(into, "manifest.json"), "w") as handle:
        json.dump({"devkit_release": devkit, "cells": found}, handle, indent=1,
                  sort_keys=True)


def _record(material, into: str, cell: tuple, devkit: str) -> tuple:
    from xebuild.boards import for_name
    from xebuild.build import security
    from xebuild.crypto import formats
    from xebuild.config import BuildConfig
    from xebuild.image import Image
    from xebuild.imagetypes import for_name as type_for
    name, kind, board, option, smc, release = cell
    data = os.path.join(material.xebuild, "data")
    work = runs.lay(material, os.path.join(into, "run-" + name), {
        **runs.console_files(material), "smc.bin": os.path.join(data, smc)},
        releases={release: devkit} if kind == "devkit" else None)
    said = runs.build(material, work, ["-t", kind, "-c", board, "-f", release, "-d",
                                       "data", "-noenter", "-o", option, "out.bin"])
    told = {"type": kind, "board": board, "option": option, "smc": smc,
            "release": release}
    made = os.path.join(work, "out.bin")
    if not os.path.isfile(made):
        told["refused"] = [line for line in said.splitlines() if line.strip()][-6:]
    else:
        with open(made, "rb") as handle:
            raw = handle.read()
        told["sha256"] = hashlib.sha256(raw).hexdigest()
        console, bigffs = for_name(board)
        flash, bigffs = type_for(kind).shape(console, bigffs)
        image = Image(raw, flash, bigffs)
        key = bytes.fromhex(material.console.key)
        xex = BuildConfig(one_bl_key=bytes.fromhex(runs.ONE_BL_KEY)).xex_key
        if "crl.bin" in {entry.name for entry in image.directory.entries}:
            told["when"] = security.when_in(formats.decrypt_crl(
                image.read("crl.bin"), key, xex)[0])
        else:
            told["when"] = runs.WHEN
    runs.clear(work)
    return name, told
