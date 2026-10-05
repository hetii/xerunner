"""One run of the original, in a directory laid out as J-Runner lays its own.

The original takes every relative name against the directory its exe is in, so a run
gets a directory of its own: the patched exe, the releases it may read as links, and a
per-build `data` directory holding what the case hands it.
"""

import os
import json
import shutil

from . import original

# The clock the recordings made after 2026-09-24 were made with.
WHEN = 0x5A123457

# How many runs of the original go at once; each is a container of its own.
WORKERS = max(1, min(16, (os.cpu_count() or 2) - 1))

# The 1BL key, which J-Runner's options.ini hands every build.
ONE_BL_KEY = "DD88AD0C9ED669E7B56794FB68563EFA"

# The loaders every build's data directory carries.
XELL = ("xell-1f.bin", "xell-2f.bin", "xell-gggggg.bin")


def lay(material, work: str, data: dict | None = None, when: int = WHEN,
        releases: dict | None = None) -> str:
    """`work` laid out for one run, and returns it.

    `data` maps a name in `data/` to the path of the file it is, or to bytes. The
    releases are J-Runner's, each a link, unless `releases` names a directory in place
    of one of them; `common` always comes along.
    """
    os.makedirs(work, exist_ok=True)
    with open(os.path.join(material.xebuild, "xeBuild.exe"), "rb") as handle:
        exe = handle.read()
    with open(os.path.join(work, "xeBuild.exe"), "wb") as handle:
        handle.write(original.frozen(exe, when))
    for name in os.listdir(material.releases):
        if name == "data":
            continue
        source = (releases or {}).get(name) or os.path.join(material.releases, name)
        link(source, os.path.join(work, name))
    for name, source in (releases or {}).items():
        if not os.path.exists(os.path.join(work, name)):
            link(source, os.path.join(work, name))
    if data is not None:
        put(os.path.join(work, "data"), data)
    return work


def console_files(material) -> dict:
    """The per-build directory J-Runner lays for the console: its dump and key, the
    options.ini that carries the 1BL key, and the loaders."""
    data = os.path.join(material.xebuild, "data")
    return {"nanddump.bin": material.console.dump,
            "cpukey.txt": material.console.key.encode(),
            "options.ini": os.path.join(data, "options.ini"),
            **{name: os.path.join(data, name) for name in XELL}}


def keep(work: str, made: str, target: str, said: str) -> str | None:
    """`made` in `work` moved to `target` and `work` cleared; or why there is none."""
    if not os.path.isfile(os.path.join(work, made)):
        return "the original made no %s in %s:\n%s" % (made, work, said[-3000:])
    os.replace(os.path.join(work, made), target)
    shutil.rmtree(work)
    return None


def clear(work: str) -> None:
    """A run's directory, gone once what it made has been kept."""
    shutil.rmtree(work)


def put(where: str, files: dict) -> None:
    """Each of `files` into `where`: bytes written, a path linked."""
    os.makedirs(where, exist_ok=True)
    for name, source in files.items():
        target = os.path.join(where, name)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if isinstance(source, (bytes, bytearray)):
            with open(target, "wb") as handle:
                handle.write(source)
        else:
            link(source, target)


def link(source: str, target: str) -> None:
    """A link where links are cheap; a copy on Windows, where they need a privilege."""
    if os.name == "nt":
        if os.path.isdir(source):
            shutil.copytree(source, target)
        else:
            shutil.copyfile(source, target)
    else:
        os.symlink(os.path.abspath(source), target)


def with_server(material, work: str, args: list, table: dict,
                timeout: float = 900) -> tuple:
    """The original's log and the stand-in's wire log for `xeBuild.exe <args>` run
    in `work` against `server.py` answering from `table` -- a serve.json, its paths
    relative to `work`."""
    shutil.copyfile(os.path.join(os.path.dirname(__file__), "server.py"),
                    os.path.join(work, "server.py"))
    with open(os.path.join(work, "serve.json"), "w") as handle:
        json.dump(table, handle)
    mount = os.path.commonpath([os.path.abspath(material.root), os.path.abspath(work)])
    said = original.run(work, "xeBuild.exe", args, mount, timeout,
                        server=os.path.join(work, "server.py"))
    with open(os.path.join(work, "wire.log"), encoding="latin-1") as handle:
        return said, handle.read()


def build(material, work: str, args: list, timeout: float = 900) -> str:
    """The original's log for `xeBuild.exe <args>` run in `work`."""
    mount = os.path.commonpath([os.path.abspath(material.root), os.path.abspath(work)])
    return original.run(work, "xeBuild.exe", args, mount, timeout)
