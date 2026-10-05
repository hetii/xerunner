"""Ini mode: one run of the original per case, in a directory laid as the case says.

Each case is `argv.json`, the original's command line; `case.json`, how its directory
was laid -- each file from a release's update container (`rel:<version>`) or written
as text (`text:`), a byte flipped where one was, the `1blkey.txt` it had if any; and
what it made: its log as `original.txt` and every file it wrote or changed under
`made/`.
"""

import os
import json
import shutil
import concurrent.futures

from . import runs

KEY = runs.ONE_BL_KEY
SU = "su20076000_00000000"

# name: (command line, files laid, the byte flipped, the 1blkey.txt)
CASES = {
    "badkey": (["ini", SU], {SU: "rel:17559"}, None, "0" * 32),
    "corrupt": (["ini", SU], {SU: "rel:17559"}, [SU, 0x10000], KEY),
    "dir": (["ini", "d"], {"d/" + SU: "rel:17559"}, None, KEY),
    "dir-slash": (["ini", "d/"], {"d/" + SU: "rel:17559"}, None, KEY),
    "extra-arg": (["ini", SU, "-noenter"], {SU: "rel:17559"}, None, KEY),
    "missing": (["ini", "nothing"], {}, None, KEY),
    "noarg": (["ini"], {SU: "rel:17559"}, None, KEY),
    "nokey": (["ini", SU], {SU: "rel:17559"}, None, None),
    "rel-13604": (["ini", SU], {SU: "rel:13604"}, None, KEY),
    "rel-15574": (["ini", SU], {SU: "rel:15574"}, None, KEY),
    "rel-17559": (["ini", SU], {SU: "rel:17559"}, None, KEY),
    "rel-7258": (["ini", SU], {SU: "rel:7258"}, None, KEY),
    "rel-9199": (["ini", SU], {SU: "rel:9199"}, None, KEY),
    "renamed": (["ini", "mysu.bin"], {"mysu.bin": "rel:17559"}, None, KEY),
    "stale-output": (["ini", SU],
                     {SU: "rel:17559", SU + "_SU.ini": "text:stale line\n"}, None, KEY),
    "systemupdate": (["ini", "x"], {"x/$SystemUpdate/" + SU: "rel:17559"}, None, KEY),
}


def make(material) -> dict:
    where = material.made("ini", {"releases": material.stamp("releases")},
                          lambda into: _make_all(material, into))
    return {"XEBUILD_INI": where}


def _make_all(material, into: str) -> None:
    with concurrent.futures.ThreadPoolExecutor(runs.WORKERS) as pool:
        list(pool.map(lambda name: _record(material, into, name), sorted(CASES)))


def _record(material, into: str, name: str) -> None:
    argv, lay, flip, key = CASES[name]
    here = os.path.join(into, name)
    os.makedirs(here)
    with open(os.path.join(here, "argv.json"), "w") as handle:
        json.dump(argv, handle)
    with open(os.path.join(here, "case.json"), "w") as handle:
        json.dump({"lay": lay, **({"flip": flip} if flip else {}), "key": key}, handle,
                  indent=1)
    work = os.path.join(here, "run")
    os.makedirs(work)
    for dest, source in lay.items():
        path = os.path.join(work, dest)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        kind, _, what = source.partition(":")
        if kind == "rel":
            shutil.copyfile(os.path.join(material.releases, what, SU), path)
        else:
            with open(path, "w", newline="") as handle:
                handle.write(what)
    if flip:
        with open(os.path.join(work, flip[0]), "r+b") as handle:
            handle.seek(flip[1])
            byte = handle.read(1)[0]
            handle.seek(flip[1])
            handle.write(bytes([byte ^ 1]))
    if key is not None:
        with open(os.path.join(work, "1blkey.txt"), "w") as handle:
            handle.write(key)
    before = _files(work)
    with open(os.path.join(material.xebuild, "xeBuild.exe"), "rb") as handle:
        exe = handle.read()
    with open(os.path.join(work, "xeBuild.exe"), "wb") as handle:
        handle.write(exe)
    said = runs.build(material, work, argv)
    with open(os.path.join(here, "original.txt"), "w", encoding="latin-1") as handle:
        handle.write(said)
    os.makedirs(os.path.join(here, "made"))
    for path, body in _files(work).items():
        if path in ("xeBuild.exe", "build.log") or before.get(path) == body:
            continue
        target = os.path.join(here, "made", path)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as handle:
            handle.write(body)
    runs.clear(work)


def _files(where: str) -> dict:
    out = {}
    for root, _, names in os.walk(where):
        for one in names:
            path = os.path.join(root, one)
            with open(path, "rb") as handle:
                out[os.path.relpath(path, where)] = handle.read()
    return out
