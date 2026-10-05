"""Update mode: the original against a stand-in console, run by run.

`_serve/` is the stand-in console -- the dump as its flash, the files the update asks
for by name out of it, and its answer to GTIN -- and every other directory one run of
`xeBuild.exe update -ip 127.0.0.1 ...`, holding `argv.json`, `original.txt`,
`wire.log`, `payloads/` and `made/`; where the console answered differently,
`served/` holds what it answered and `served.json` says which; `_older/` holds runs
against a console saying an older server or peek version.

`provenance/` comes from the same stand-in: which copy of three firmware files the
original took in build and update mode, when the console's and the disk's copies both
pass their checks.
"""

import os
import json
import shutil
import struct
import hashlib
import concurrent.futures

from . import runs, serving, crafted

# The addon records a console's server hands over, by name.
ADDONS = {"hvFixKeys": "00002dc800000001" "0000001800000002",
          "nofcrt": "000611a000000001" "0002e24000000003",
          "nohdd": "0015dd3000000001", "nohdmiwait": "0015bc8000000001",
          "nointmu": "0008e09800000001" "000e25a800000001" "0008f3f800000001",
          "nolan": "000d1ee400000001",
          "noSShdd": "0015d9d800000002" "0015dafc00000001" "0015db0800000001",
          "nowifi": "0014b77800000002" "001341f000000002"}
NOFCRT = bytes.fromhex(ADDONS["nofcrt"])
BLMOD = bytes(range(256)) * 2

NOWRITE = ["-f", "17559", "-d", "dump", "-nowrite", "-noava", "-noreeb"]
ADDONS_RUN = ["-v", "-f", "17559", "-d", "dump", "-nowrite", "-noava", "-noreeb"]
JTAG_RUN = ["-v", "-f", "17559", "-d", "dump", "-nowrite"]

# name: (switches between -ip and -noenter, clock, what the console answers
# differently: {"caps": bits of word 8, "files": {name: bytes}, "jtag": True,
# "pairing": three bytes}, what is placed in the release)
RUNS = {
    "nowrite-d": (NOWRITE, 0x5A123457, None, None),
    "nowrite-even": (NOWRITE, 0x5A123456, None, None),
    "nowrite-nodump": (["-f", "17559", "-nowrite", "-noava", "-noreeb"], 0x5A123457,
                       None, None),
    "clean-d2": (["-f", "17559", "-d", "dump", "-clean", "-v", "-nowrite", "-v"],
                 0x5A123457, None, None),
    "write-reboot": (["-f", "17559", "-noava"], 0x5A123457, None, None),
    "write-noreeb": (["-f", "17559", "-noava", "-noreeb"], 0x5A123457, None, None),
    "write-avatar": (["-f", "17559", "-noreeb"], 0x5A123457, None, None),
    "write-avatar-su": (["-f", "17559", "-v", "-noreeb"], 0x5A123457, None,
                        "system_update"),
    "addons-nofcrt": (ADDONS_RUN, 0x5A123457, {"caps": 4, "addons": NOFCRT}, None),
    "addons-all": (ADDONS_RUN, 0x5A123457,
                   {"caps": 4, "addons": b"".join(bytes.fromhex(one)
                                                  for one in ADDONS.values())}, None),
    "addons-partial": (ADDONS_RUN, 0x5A123457, {"caps": 4, "addons": NOFCRT[:8]}, None),
    "addons-odd": (ADDONS_RUN, 0x5A123457, {"caps": 4, "addons": NOFCRT + b"\x01\x02"},
                   None),
    "addons-cmdline": (["-v", "-f", "17559", "-d", "dump", "-a", "nolan", "-nowrite",
                        "-noava", "-noreeb"], 0x5A123457,
                       {"caps": 4, "addons": NOFCRT}, None),
    "addons-blmod": (ADDONS_RUN, 0x5A123457,
                     {"caps": 6, "addons": NOFCRT, "blmod": BLMOD}, None),
    "jtag-falcon": (JTAG_RUN, 0x5A123457, {"jtag": True}, None),
    "jtag-falcon-blmod": (JTAG_RUN, 0x5A123457, {"jtag": True, "caps": 2,
                                                 "blmod": BLMOD}, None),
    "jtag-falcon-pairing": (JTAG_RUN, 0x5A123457, {"jtag": True,
                                                   "pairing": 0x5A7C31}, None),
    "jtag-6717": (["-v", "-f", "6717", "-d", "dump", "-nowrite"], 0x5A123457,
                  {"jtag": True}, None),
    "jtag-6717-meta": (["-v", "-f", "6717", "-d", "dump", "-nowrite"], 0x5A123457,
                       {"jtag": True}, "meta:dash.xex"),
}

OLDER = {"up-v2p1": 0x201, "up-v2p2": 0x202, "up-v3p1": 0x301}

HARNESS = {"xeBuild.exe", "server.py", "serve.json", "wire.log", "ready", "payloads",
           "xell-gggggg.bin", "xell-1f.bin", "xell-2f.bin"}


def make(material, serve_from=None) -> dict:
    """`serve_from` is a `_serve` directory to answer from instead of the console
    made from the dump."""
    inputs = {"console": material.stamp("console"), "serve": serve_from or ""}
    where = material.made("update", inputs,
                          lambda into: _make_all(material, into, serve_from))
    return {"XEBUILD_UPDATE": where}


def _make_all(material, into: str, serve_from) -> None:
    serve = os.path.join(into, "_serve")
    if serve_from:
        shutil.copytree(serve_from, serve)
    else:
        _console(material, serve)
    jobs = [(_run, name) for name in RUNS] + [(_older, name) for name in OLDER]
    with concurrent.futures.ThreadPoolExecutor(runs.WORKERS) as pool:
        list(pool.map(lambda job: job[0](material, into, job[1]), jobs))


def _console(material, serve: str) -> None:
    """The stand-in console: the dump as its flash and everything the update asks
    for out of it -- `serve.json` naming what the runs read, `serve_files.json` those
    and the firmware files provenance's runs read besides."""
    from xebuild.boards import for_name
    from xebuild.image import Dump
    console = material.console
    with open(console.dump, "rb") as handle:
        raw = handle.read()
    board, bigffs = for_name(console.board)
    dump = Dump(raw, board, bigffs)
    image = dump.image
    flat = bytes(image.flat)
    files, table = {}, {}

    def put(name, body):
        stored = name.replace("\\", "_")
        files[stored] = body
        table[name] = stored

    for name in ("crl.bin", "dae.bin", "extended.bin", "fcrt.bin", "secdata.bin"):
        put("usv:\\" + name, image.read(name))
    put("BLDR\\kv_enc", dump.sealed_keyvault)
    put("BLDR\\smc_enc", dump.smc)
    # A donor's image carries no blobs, and a console without them has none to hand.
    for name in ("MobileB.dat", "MobileC.dat", "MobileD.dat", "MobileE.dat"):
        if name in image.blobs:
            put("usv:\\" + name, image.blob(name))
    put("usv:\\Statistics.settings", dump.statistics[:0x400])
    put("usv:\\Manufacturing.data", dump.manufacturing[:0x80])
    put("usv:\\Static.settings", flat[board.flash.smc_config:
                                      board.flash.smc_config + 0x4000])
    put("flash_hdr", flat[:0x200])
    served = dict(table)
    # The console's own copy of one firmware file says so in its last sixteen bytes,
    # so the image shows which copy a build took.
    clatin = image.read("xenonclatin.xtt")
    put("usv:\\xenonclatin.xtt", clatin[:-0x10] + b"CONSOLE-VERSION!")
    names = {entry.name for entry in image.directory.entries}
    for name in ("xenonjklatin.xtt", "ximedic.xex", "launch.xex", "lhelper.xex",
                 "launch.ini"):
        if name in names:
            put("usv:\\" + name, image.read(name))
        elif os.path.isfile(os.path.join(material.xebuild, name)):
            # A donor's image is built from a release without the base directory's
            # launch files beside it; a console that has them got them from there.
            # J-Runner ships no launch.ini, and a console without one hands none.
            with open(os.path.join(material.xebuild, name), "rb") as handle:
                put("usv:\\" + name, handle.read())
    files.update({"flash.bin": raw, "bootloaders.bin": flat[:0xB0000],
                  "flash_hdr.bin": flat[:0x200],
                  "info.bin": serving.info(raw, console.board,
                                           bytes.fromhex(console.key), "glitch2",
                                           int(console.env.get("XEBUILD_LDV", "1")))})
    runs.put(serve, files)
    base = {"info": "info.bin", "flash": "flash.bin", "bootloaders": "bootloaders.bin",
            "idle": 300}
    with open(os.path.join(serve, "serve.json"), "w") as handle:
        json.dump({**base, "files": served}, handle, indent=1)
    with open(os.path.join(serve, "serve_files.json"), "w") as handle:
        json.dump({**base, "files": table}, handle, indent=1)


def _served(material, serve: str, here: str, change: dict) -> dict:
    """What the console answers in one run: `_serve`'s table with `change` made, the
    changed answers kept in `here/served/` as `e2e_update` reads them."""
    with open(os.path.join(serve, "serve.json")) as handle:
        table = json.load(handle)
    with open(os.path.join(serve, "info.bin"), "rb") as handle:
        info = bytearray(handle.read())
    own = os.path.join(here, "served")
    kept, record = {}, {"info": "info.bin", "files": {}}
    info[0x0B] |= change.get("caps", 0)
    for key in ("addons", "blmod"):
        if key in change:
            kept[key + ".bin"] = change[key]
            record["files"][key] = key + ".bin"
    if change.get("jtag"):
        # A JTAG Falcon: it hands over no bootloaders, and its keyvault and SMC by
        # name, the SMC J-Runner's JTAG one sealed under the console's own seed.
        info[0x0C:0x10] = struct.pack(">I", 0x80000002)
        with open(os.path.join(serve, table["files"]["BLDR\\smc_enc"]), "rb") as handle:
            seed = handle.read()[:4]
        with open(os.path.join(material.xebuild, "data", "SMCfzj.bin"), "rb") as handle:
            plain = handle.read()
        from xebuild.crypto.formats import decrypt_smc, encrypt_smc
        # A plain SMC image ends in four zero bytes; J-Runner ships some sealed.
        if plain[-4:] != bytes(4):
            plain = decrypt_smc(plain)
        kept["smc_enc.bin"] = encrypt_smc(plain, seed)
        with open(os.path.join(serve, table["files"]["BLDR\\kv_enc"]), "rb") as handle:
            kept["kv_enc.bin"] = handle.read()
        record["files"].update({"smc_enc": "smc_enc.bin", "kv_enc": "kv_enc.bin"})
        record["no_bootloaders"] = True
    if "pairing" in change:
        info[0x1C:0x1F] = change["pairing"].to_bytes(3, "big")
    kept["info.bin"] = bytes(info)
    runs.put(own, kept)
    with open(os.path.join(own, "served.json"), "w") as handle:
        json.dump(record, handle)
    table["files"].update(record["files"])
    if record.get("no_bootloaders"):
        del table["bootloaders"]
    table["info"] = os.path.join(own, "info.bin")
    for key, name in record["files"].items():
        table["files"][key] = os.path.join(own, name)
    return table


def _lay(material, here: str, serve: str, table: dict, placed,
         when: int = runs.WHEN) -> tuple:
    """The run's directory: J-Runner's releases and loaders, and the stand-in's files
    as `table` names them, each a link; the release as links, file by file, where
    something is placed beside it."""
    work = os.path.join(here, "run")
    runs.lay(material, work, when=when)
    data = os.path.join(material.xebuild, "data")
    runs.put(work, {name: os.path.join(data, name) for name in runs.XELL})
    linked = {}
    for key in ("info", "flash", "bootloaders"):
        if key in table:
            linked[key] = _bring(work, serve, table[key])
    files = {name: _bring(work, serve, path) for name, path in table["files"].items()}
    if placed is not None:
        version = "6717" if placed.startswith("meta") else "17559"
        os.remove(os.path.join(work, version))
        source = os.path.join(material.xebuild, version)
        os.makedirs(os.path.join(work, version))
        for one in os.listdir(source):
            runs.link(os.path.join(source, one), os.path.join(work, version, one))
        if placed == "system_update":
            runs.link(os.path.join(material.system_update, "$SystemUpdate"),
                      os.path.join(work, version, "$SystemUpdate"))
        else:
            name = placed.partition(":")[2] + ".meta"
            runs.put(os.path.join(here, "release"), {name: crafted.META})
            runs.link(os.path.join(here, "release", name),
                      os.path.join(work, version, name))
    return work, {**linked, "files": files, "idle": table.get("idle", 300)}


def _bring(work: str, serve: str, path: str) -> str:
    """A served file linked into the run's directory, by a name of its own there."""
    source = path if os.path.isabs(path) else os.path.join(serve, path)
    name = "served_" + os.path.basename(source).replace(":", "_")
    target = os.path.join(work, name)
    if not os.path.lexists(target):
        runs.link(source, target)
    return name


def _run(material, into: str, name: str) -> None:
    words, when, change, placed = RUNS[name]
    here = os.path.join(into, name)
    serve = os.path.join(into, "_serve")
    if change:
        table = _served(material, serve, here, change)
    else:
        with open(os.path.join(serve, "serve.json")) as handle:
            table = json.load(handle)
    work, table = _lay(material, here, serve, table, placed, when)
    before = set(os.listdir(work))
    argv = ["update", "-ip", "127.0.0.1", *words, "-noenter"]
    said, wire = runs.with_server(material, work, argv, table, timeout=1800)
    with open(os.path.join(here, "original.txt"), "w", encoding="latin-1") as handle:
        handle.write(said)
    with open(os.path.join(here, "wire.log"), "w", encoding="latin-1") as handle:
        handle.write(wire)
    with open(os.path.join(here, "argv.json"), "w") as handle:
        json.dump(argv, handle)
    payloads = os.path.join(work, "payloads")
    if placed == "system_update":
        # The image, and of every file after it only its SHA-1.
        found = sorted(os.listdir(payloads))
        sums = {}
        for one in found:
            with open(os.path.join(payloads, one), "rb") as handle:
                sums[one] = hashlib.sha1(handle.read()).hexdigest()
        with open(os.path.join(here, "payloads.sha1.json"), "w") as handle:
            json.dump(sums, handle, indent=1)
        os.makedirs(os.path.join(here, "payloads"))
        shutil.copyfile(os.path.join(payloads, found[0]),
                        os.path.join(here, "payloads", found[0]))
        with open(os.path.join(here, "placed.json"), "w") as handle:
            json.dump({"system_update": "17559"}, handle)
    elif os.listdir(payloads):
        shutil.copytree(payloads, os.path.join(here, "payloads"))
    for one in sorted(set(os.listdir(work)) - before - HARNESS):
        if placed == "system_update":
            break
        source = os.path.join(work, one)
        target = os.path.join(here, "made", one)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if os.path.isdir(source):
            shutil.copytree(source, target)
        else:
            shutil.copyfile(source, target)
    runs.clear(work)


def _older(material, into: str, name: str) -> None:
    here = os.path.join(into, "_older", name)
    serve = os.path.join(into, "_serve")
    with open(os.path.join(serve, "serve.json")) as handle:
        table = json.load(handle)
    with open(os.path.join(serve, "info.bin"), "rb") as handle:
        info = struct.pack(">I", OLDER[name]) + handle.read()[4:]
    runs.put(here, {"info.bin": info})
    table["info"] = os.path.join(here, "info.bin")
    work, table = _lay(material, here, serve, table, None)
    argv = ["update", "-ip", "127.0.0.1", "-f", "17559", "-nowrite", "-noenter"]
    said, wire = runs.with_server(material, work, argv, table)
    with open(os.path.join(here, "original.txt"), "w", encoding="latin-1") as handle:
        handle.write(said)
    with open(os.path.join(here, "wire.log"), "w", encoding="latin-1") as handle:
        handle.write(wire)
    with open(os.path.join(here, "argv.json"), "w") as handle:
        json.dump(argv, handle)
    runs.clear(work)
