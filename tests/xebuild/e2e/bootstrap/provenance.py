"""Which copy of a firmware file the original takes, measured: `expected.json`.

Both copies of three files pass their checksum -- the disk's in `common/` is forged
to the same CRC32 with different bytes -- and `launch.xex` lies on disk as 0x1000 bytes
of "L" or not at all, so the image shows which copy each one followed. Four runs of
the original against `update/_serve`: a glitch2 build from the console's dump and
from the dump with one byte of xenonclatin.xtt spoiled, and an update with and
without launch.xex on disk. The forging and spoiling are `e2e_provenance`'s own.
"""

import os
import json
import hashlib

from . import runs

HOW = ("Which copy of each firmware file the original xeBuild v1.21.810 put in its "
       "image, measured under wine with a frozen clock. The disk's copies in common/ "
       "were forged to the same CRC32 as the genuine ones with different bytes, so "
       "the image shows which copy went in. Build: -t glitch2 -c trinity -f 17559 "
       "with update/_serve/flash.bin as nanddump.bin. Update: -f 17559 -d dump "
       "-nowrite against a stand-in serving update/_serve/serve_files.json. launch.xex "
       "on disk is 0x1000 bytes of 'L'. bad-dump has one byte of xenonclatin.xtt's "
       "data changed in the dump, its page's code put right.")


def make(material) -> dict:
    where = material.made("provenance", {"update": material.stamp("update")},
                          lambda into: _make_all(material, into))
    return {"XEBUILD_PROVENANCE": where}


def _make_all(material, into: str) -> None:
    from ..e2e_provenance import LAUNCH, NAMES, forged, spoiled
    from xebuild.boards import for_name
    from xebuild.image import Image
    serve = material.path("update", "_serve")
    with open(os.path.join(serve, "serve_files.json")) as handle:
        table = json.load(handle)
    with open(os.path.join(serve, "flash.bin"), "rb") as handle:
        dump = handle.read()
    common = os.path.join(material.xebuild, "common")
    disk = {}
    for name in NAMES:
        with open(os.path.join(common, name), "rb") as handle:
            disk[name] = forged(handle.read())
    disk["launch.xex"] = LAUNCH
    flash = for_name("trinity")[0].flash
    expected = {"_how": HOW}

    def chosen(image: bytes, console: dict) -> dict:
        read = Image(image, flash)
        out = {}
        for name in (*NAMES, "launch.xex"):
            got = hashlib.sha1(read.read(name)).digest()
            out[name] = ("console" if got == console[name] else
                         "disk" if got == hashlib.sha1(disk[name]).digest() else "?")
        return out

    for case, raw in (("build-dump", dump),
                      ("build-bad-dump", spoiled(dump, "xenonclatin.xtt"))):
        work = _lay(material, os.path.join(into, "run-" + case), disk, True)
        runs.put(os.path.join(work, "data"), {
            "nanddump.bin": raw, "cpukey.txt": material.console.key.encode(),
            **{name: os.path.join(material.xebuild, "data", name)
               for name in ("options.ini", *runs.XELL)}})
        said = runs.build(material, work, ["-t", "glitch2", "-c", "trinity",
                                           "-f", "17559", "-d", "data", "-noenter",
                                           "out.bin"])
        read = Image(raw, flash)
        console = {name: hashlib.sha1(read.read(name)).digest()
                   for name in (*NAMES, "launch.xex")}
        expected[case] = chosen(_read(os.path.join(work, "out.bin"), said), console)
        runs.clear(work)
    served = {name: hashlib.sha1(_read(os.path.join(
        serve, table["files"]["usv:\\" + name]))).digest()
        for name in (*NAMES, "launch.xex")}
    for case, launch in (("update-launch-on-disk", True), ("update-no-launch", False)):
        work = _lay(material, os.path.join(into, "run-" + case), disk, launch)
        files = {}
        for key in ("info", "flash", "bootloaders"):
            files[key] = _bring(work, serve, table[key])
        files["files"] = {name: _bring(work, serve, path)
                          for name, path in table["files"].items()}
        files["idle"] = 300
        said, _ = runs.with_server(material, work, [
            "update", "-ip", "127.0.0.1", "-f", "17559", "-d", "dump", "-nowrite",
            "-noenter"], files, timeout=1800)
        kept = [one for one in os.listdir(os.path.join(work, "dump"))
                if one.startswith("17559_") and one.endswith(".bin")]
        image = _read(os.path.join(work, "dump", kept[0]), said)
        expected[case] = chosen(image, served)
        if not launch:
            with open(os.path.join(into, case + ".original.txt"), "w",
                      encoding="latin-1") as handle:
                handle.write(said)
        runs.clear(work)
    with open(os.path.join(into, "expected.json"), "w") as handle:
        handle.write("{\n" + ",\n".join(
            "  %s: %s" % (json.dumps(key), json.dumps(value))
            for key, value in expected.items()) + "\n}\n")


def _lay(material, work: str, disk: dict, launch: bool) -> str:
    """J-Runner's releases with `common/` as links but for the three forged files,
    the loaders in the base directory, and launch.xex there or not."""
    runs.lay(material, work)
    os.remove(os.path.join(work, "common"))
    runs.put(os.path.join(work, "common"), {name: body for name, body in disk.items()
                                            if name != "launch.xex"})
    source = os.path.join(material.xebuild, "common")
    for name in os.listdir(source):
        target = os.path.join(work, "common", name)
        if not os.path.lexists(target):
            runs.link(os.path.join(source, name), target)
    data = os.path.join(material.xebuild, "data")
    runs.put(work, {name: os.path.join(data, name) for name in runs.XELL})
    if launch:
        runs.put(work, {"launch.xex": disk["launch.xex"]})
    return work


def _bring(work: str, serve: str, path: str) -> str:
    name = "served_" + os.path.basename(path).replace(":", "_")
    runs.link(os.path.join(serve, path), os.path.join(work, name))
    return name


def _read(path: str, said: str = "") -> bytes:
    if not os.path.isfile(path):
        raise RuntimeError("the original made no %s:\n%s" % (path, said[-3000:]))
    with open(path, "rb") as handle:
        return handle.read()
