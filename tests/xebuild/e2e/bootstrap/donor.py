"""Consoles for when no dump is given: images the original builds from donor files.

J-Runner makes an image for a console whose flash is lost from loose files: a borrowed
keyvault, its SMC and SMC settings, built with `-norandom` so nothing is drawn. The
original does the same here for two consoles, each under a CPU key made up for it --
106 key bits, 53 of them set, the check bits computed -- and what it builds stands in
for a dump: the console the material is built around, a glitch2 Trinity, and another
whose sealed files a build is handed as foreign, a retail Xenon. Each is built with
J-Runner's launch.xex and lhelper.xex in its base directory, so its flash carries them
as a console's does.
"""

import os
import concurrent.futures

from . import runs

# name: (board, type, keyvault, SMC, SMC settings, CPU key)
DONORS = {
    "console": ("trinity", "glitch2", "slim_nofcrt.bin", "TRINITY_SMC+.bin",
                "Trinity.bin", "7E5068DBB3FD03F04E367028D475EEC2"),
    "foreign": ("xenon", "retail", "phat_t1.bin", "XENON_CLEAN.bin", "Xenon.bin",
                "C00F82E6A179EB95DBAD41A585C3AE0F"),
}


def image(material, which: str) -> tuple:
    """The donor image `which` names, as (its path, its board, its CPU key)."""
    where = material.made("donor", {"jrunner": material.stamp("releases")},
                          lambda into: _make_all(material, into))
    board, _, _, _, _, key = DONORS[which]
    return os.path.join(where, which + ".bin"), board, key


def _make_all(material, into: str) -> None:
    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        for failed in pool.map(lambda name: _build(material, into, name), DONORS):
            if failed:
                raise RuntimeError(failed)


def _build(material, into: str, name: str):
    board, kind, keyvault, smc, settings, key = DONORS[name]
    donor = os.path.join(material.xebuild, "Donor Files")
    data = os.path.join(material.xebuild, "data")
    work = runs.lay(material, os.path.join(into, "run-" + name), {
        "cpukey.txt": key.encode(),
        "kv.bin": os.path.join(donor, keyvault),
        "fcrt.bin": os.path.join(donor, "fcrt.bin"),
        "smc.bin": os.path.join(data, smc),
        "smc_config.bin": os.path.join(donor, "smc_config", settings),
        "options.ini": os.path.join(data, "options.ini"),
        **{one: os.path.join(data, one) for one in runs.XELL}})
    # In the base directory, as J-Runner has them, so the image carries them as a
    # console's flash does: the release's list names `..\\launch.xex`.
    runs.put(work, {one: os.path.join(material.xebuild, one)
                    for one in ("launch.xex", "lhelper.xex")})
    said = runs.build(material, work, ["-t", kind, "-c", board, "-f", "17559",
                                       "-d", "data", "-noenter", "-norandom",
                                       "-o", "cfldv=14", "out.bin"])
    return runs.keep(work, "out.bin", os.path.join(into, name + ".bin"), said)
