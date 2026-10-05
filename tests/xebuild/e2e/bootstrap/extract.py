"""Extract mode: the original's report on each dump the material holds.

`manifest.json` names each dump and where it lies; beside it a directory a dump holds
`original.txt`, what `xeBuild.exe extract -v -noenter nanddump.bin` printed for it.
"""

import os
import json
import concurrent.futures

from . import runs

# name: where the dump is, relative to the material's root
DUMPS = {
    "bench-trinity": ("console", "nanddump.bin"),
    "rgh3-trinity": ("cells", "rgh3-norandom", "data", "nanddump.bin"),
    "badblocks-16mb": ("cells", "badblocks-noecdremap", "data", "nanddump.bin"),
    "badblocks-bigblock": ("cells", "badblocks-bigblock", "data", "nanddump.bin"),
    "mu-jasper256-64mb": ("cells", "mu64-nandmu", "data", "nanddump.bin"),
    "mu-jasper256-256mb": ("cells", "mu256-nandmu", "data", "nanddump.bin"),
    "emmc-corona4g": ("refs", "glitch2-corona4g.bin"),
    "bigblock-trinitybb": ("refs", "glitch2-trinitybb.bin"),
    "jtag-falcon-image": ("refs", "jtag-falcon.bin"),
}


def make(material, after: dict) -> dict:
    """`after` is the stamps of the parts the dumps come from."""
    where = material.made("extract", after, lambda into: _make_all(material, into))
    return {"XEBUILD_EXTRACT": where}


def _make_all(material, into: str) -> None:
    manifest = {name: os.path.realpath(material.path(*parts))
                for name, parts in DUMPS.items()}
    with open(os.path.join(into, "manifest.json"), "w") as handle:
        json.dump(manifest, handle, indent=1)
    with concurrent.futures.ThreadPoolExecutor(runs.WORKERS) as pool:
        list(pool.map(lambda one: _report(material, into, *one), manifest.items()))


def _report(material, into: str, name: str, dump: str) -> None:
    here = os.path.join(into, name)
    work = runs.lay(material, os.path.join(here, "run"))
    runs.link(dump, os.path.join(work, "nanddump.bin"))
    said = runs.build(material, work, ["extract", "-v", "-noenter", "nanddump.bin"])
    with open(os.path.join(here, "original.txt"), "w", encoding="latin-1") as handle:
        handle.write(said)
    runs.clear(work)
