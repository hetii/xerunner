"""Client mode: the original against a stand-in console, action by action.

`_serve/` is the stand-in console -- see `serving` -- and every other directory one
run of `xeBuild.exe client ... -ip 127.0.0.1 -noenter`, holding `argv.json`,
`original.txt`, `wire.log`, `payloads/` and `made/`, the files it wrote. Beside them,
as `e2e_client` reads them:

- `_older/` -- `-i` against a console saying an older server or peek version;
- `_patches/` -- `-p` over consoles made up from `_info/`'s answers;
- `_info/` -- `-i got` over answers changed one field at a time;
- `_sysdata/` -- `-e` and `-c` on made-up trees, with `supd17559` the system update.
"""

import os
import json
import shutil
import struct
import hashlib
import concurrent.futures

from . import runs, serving

TAIL = ["-ip", "127.0.0.1", "-noenter"]

# The actions run on the stand-in as it is: name -> the switches before -ip.
ACTIONS = {
    "info": ["-i"],
    "info-dir": ["-i", "got"],
    "info-shutdown-reboot": ["-i", "-s", "-reboot"],
    "read": ["-r", "read.bin"],
    "read-blocks": ["-rb", "blocks.bin", "100", "2"],
    "keys": ["-keys"],
    "shutdown": ["-s"],
    "reboot": ["-reboot"],
    "reboot-then-shutdown": ["-reboot", "-s"],
    "shutdown-then-reboot": ["-s", "-reboot"],
    "write": ["-w", "in.bin"],
    "write-blocks": ["-wb", "wb.bin", "100"],
    "erase-block": ["-eb", "100"],
    "patches-auto": ["-p"],
    "patches-file": ["-p", "patches.bin"],
    "binary-patch": ["-bp", "bp.bin", "4210"],
    "binary-patch-block0": ["-bp", "bp.bin", "1F0"],
}

# Server and peek versions below what the original wants: name -> (word 0, -i got?)
OLDER = {"cl-v2p2": (0x202, False), "cl-v3p0": (0x300, False),
         "cl-v3p1": (0x301, False), "cld-v2p2": (0x202, True)}


def _word(at: int, value: int):
    return lambda info, header: (info[:at] + struct.pack(">I", value) + info[at + 4:],
                                 header)


def _bytes(at: int, value: bytes):
    return lambda info, header: (info[:at] + value + info[at + len(value):], header)


def _reason(at: int, value: bytes):
    return lambda info, header: (info, header[:at] + value + header[at + len(value):])


def _both(*changes):
    def change(info, header):
        for one in changes:
            info, header = one(info, header)
        return info, header
    return change


# The answers `-i got` runs over, each the stand-in's with one thing changed.
INFO = {
    "jtag-falcon": _both(_word(0x0C, 0x80000002), _word(0x10, 0x20000227)),
    "glitch2-trinity": _word(0x0C, 0x20000004),
    "glitch2m-trinity": _word(0x0C, 0x10000004),
    "retail-trinity": _word(0x0C, 0x00000004),
    "glitch-xenon": _both(_word(0x0C, 0x40000000), _word(0x10, 0x00000227)),
    "corona-4g": _both(_word(0x0C, 0x40000005), _word(0x10, 0x50000227),
                       _word(0x14, 0x3000000)),
    "jasper-bigffs": _both(_word(0x0C, 0x40000003), _word(0x10, 0x30000227),
                           _word(0x14, 0x4200000)),
    "cpukey-weight": "weight",
    "cpukey-ecd": _bytes(0x2F, b"\x7c"),
    "1blkey-bad": _bytes(0x100, b"\x00"),
    "pirs-bad": _bytes(0x300, b"\x00\x00"),
    "virtual-fuses": _bytes(0xA0, bytes.fromhex("c0ffffffffffffff")),
    "no-hdd": _word(0x10, 0x40000207),
    "fat-wired-rear": _both(_word(0x0C, 0x40000002), _word(0x10, 0x20000227),
                            _reason(0x4F, b"\x5a")),
    "slim-wired-front": _reason(0x4F, b"\x56"),
    "power-button": _reason(0x4F, b"\x11"),
    "alt-cygnos-nodvd": _reason(0x4D, b"\x03\x11"),
    "jtag-dualboot": _both(_word(0x0C, 0x80000002), _word(0x10, 0x20000227),
                           _reason(0x4B, b"\x01\x11")),
}

# `-p` over the made-up consoles, and over the stand-in with an addon in its slot.
PATCHES = {name: (name, "patches.bin", []) for name in (
    "glitch2-trinity", "glitch2m-trinity", "jtag-falcon", "glitch-xenon",
    "retail-trinity", "corona-4g", "jasper-bigffs", "fat-wired-rear")}
PATCHES["addon-kept"] = (None, "patches_addon.bin", [])
PATCHES["addon-kept-file"] = (None, "patches_addon.bin", ["patches.bin"])

# `-e` and `-c` on trees: name -> (switches, whose answer, the tree's name)
SYSDATA = {
    "compat": (["-c", "compat/", "-v"], "_serve", "compat_tree"),
    "compat-noslash": (["-c", "compat"], "_serve", "compat_tree"),
    "compat-noindex": (["-c", "compat/"], "_serve", "compat_noindex"),
    "compat-nohdd": (["-c", "compat/"], "_info/no-hdd", "compat_tree"),
    "avatar-nohdd": (["-e", "su/"], "_info/no-hdd", "su"),
    "avatar-flat": (["-e", "flat/", "-v"], "_serve", "su_flat"),
    "avatar-noslash": (["-e", "su", "-v"], "_serve", "su"),
    "avatar-corrupt-container": (["-e", "su/", "-v"], "_serve", "su_corrupt_container"),
    "avatar-corrupt-file": (["-e", "su/", "-v"], "_serve", "su_corrupt_file"),
    "avatar-missing-file": (["-e", "su/", "-v"], "_serve", "su_missing_file"),
    "avatar-header-hash": (["-e", "su/", "-v"], "_serve", "su_header_hash"),
    "avatar-flip-sig": (["-e", "su/", "-v"], "_serve", "flip_0x10"),
    "avatar-flip-l1": (["-e", "su/", "-v"], "_serve", "flip_0xb6100"),
    "avatar-flip-l0tail": (["-e", "su/", "-v"], "_serve", "flip_0xb7f00"),
    "avatar-flip-tail": (["-e", "su/", "-v"], "_serve", "flip_-0x5"),
}

# What a run leaves beside it that is the harness's, not the original's.
HARNESS = {"xeBuild.exe", "server.py", "serve.json", "wire.log", "ready", "payloads",
           "17559", "common"}


def make(material, serve_from=None) -> dict:
    """`serve_from` is a `_serve` directory to answer from instead of the console
    made from the dump -- one captured off a real console, to hold a recording made
    here against one made there."""
    inputs = {"console": material.stamp("console"), "cells": material.stamp("cells"),
              "serve": serve_from or ""}
    where = material.made("client", inputs,
                          lambda into: _make_all(material, into, serve_from))
    return {"XEBUILD_CLIENT": where}


def _make_all(material, into: str, serve_from) -> None:
    serve = os.path.join(into, "_serve")
    if serve_from:
        shutil.copytree(serve_from, serve)
    else:
        _console(material, serve)
    os.makedirs(os.path.join(into, "_sysdata"))
    runs.link(material.system_update, os.path.join(into, "_sysdata", "supd17559"))
    _info_answers(serve, os.path.join(into, "_info"))
    jobs = [(_action, name) for name in ACTIONS] + [(_avatar, "avatar")]
    jobs += [(_older, name) for name in OLDER] + [(_patches, name) for name in PATCHES]
    jobs += [(_info, name) for name in INFO] + [(_sysdata, name) for name in SYSDATA]
    with concurrent.futures.ThreadPoolExecutor(runs.WORKERS) as pool:
        list(pool.map(lambda job: job[0](material, into, job[1]), jobs))


def _console(material, serve: str) -> None:
    """The stand-in console: the dump's RGH3 form where a board has one, as the
    console these were first recorded on ran, its first 0xB0000 bytes the
    bootloaders, its patch slot at 0xC0000, and an answer to GTIN for it."""
    from xebuild.boards import for_name
    from xebuild.image import Image
    console = material.console
    shared = material.path("cells-shared", "rgh3.bin")
    path = shared if console.board.startswith("trinity") else console.dump
    with open(path, "rb") as handle:
        raw = handle.read()
    flat = bytes(Image(raw, for_name(console.board)[0].flash).flat)
    os.makedirs(serve)
    slot = flat[0xC0000:0xD0000]
    addon = _read(os.path.join(material.xebuild, "17559", "bin", "xl_usb.bin"))
    files = {
        "flash.bin": raw,
        "bootloaders.bin": flat[:0xB0000],
        "flash_hdr.bin": flat[:0x200],
        "info.bin": serving.info(raw, console.board, bytes.fromhex(console.key),
                                 "glitch" if path == shared else "glitch2",
                                 int(console.env.get("XEBUILD_LDV", "1"))),
        "patches.bin": slot,
        "patches_addon.bin": serving.with_addon(slot, addon),
        "wb.bin": bytes(range(256)) * (0x8400 // 256),
    }
    runs.put(serve, files)


def _info_answers(serve: str, where: str) -> None:
    """`_info/`'s answers and headers, each the stand-in's with one thing changed."""
    with open(os.path.join(serve, "info.bin"), "rb") as handle:
        info = handle.read()
    with open(os.path.join(serve, "flash_hdr.bin"), "rb") as handle:
        header = handle.read()
    for name, change in INFO.items():
        if change == "weight":
            # The key with its first byte's every bit set: 53 bits no longer.
            made = (info[:0x20] + b"\xff" + info[0x21:], header)
        else:
            made = change(info, header)
        runs.put(os.path.join(where, name), {"info.bin": made[0],
                                             "flash_hdr.bin": made[1]})


def _work(material, here: str, serve: str, extra: dict) -> str:
    work = os.path.join(here, "run")
    runs.lay(material, work)
    runs.put(work, extra)
    return work


def _table(files: dict, bootloaders: bool = False) -> dict:
    table = {"info": "info.bin", "flash": "flash.bin", "files": files, "idle": 120}
    if bootloaders:
        table["bootloaders"] = "bootloaders.bin"
    return table


def _keep(here: str, work: str, argv: list, said: str, wire: str, before: set,
          sums: bool = False) -> None:
    with open(os.path.join(here, "original.txt"), "w", encoding="latin-1") as handle:
        handle.write(said)
    with open(os.path.join(here, "wire.log"), "w", encoding="latin-1") as handle:
        handle.write(wire)
    with open(os.path.join(here, "argv.json"), "w") as handle:
        json.dump(argv, handle)
    payloads = os.path.join(work, "payloads")
    if sums:
        found = {}
        if os.path.isdir(payloads):
            found = {one: _sha1(os.path.join(payloads, one))
                     for one in sorted(os.listdir(payloads))}
        with open(os.path.join(here, "payloads.sha1.json"), "w") as handle:
            json.dump(found, handle, indent=1)
    elif os.path.isdir(payloads):
        shutil.copytree(payloads, os.path.join(here, "payloads"))
    for one in sorted(set(os.listdir(work)) - before - HARNESS):
        source = os.path.join(work, one)
        target = os.path.join(here, "made", one)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if os.path.isdir(source):
            shutil.copytree(source, target)
        else:
            shutil.copyfile(source, target)
    runs.clear(work)


def _sha1(path: str) -> str:
    with open(path, "rb") as handle:
        return hashlib.sha1(handle.read()).hexdigest()


def _action(material, into: str, name: str) -> None:
    here = os.path.join(into, name)
    serve = os.path.join(into, "_serve")
    release = os.path.join(material.xebuild, "17559")
    work = _work(material, here, serve, {
        "info.bin": os.path.join(serve, "info.bin"),
        "bootloaders.bin": os.path.join(serve, "bootloaders.bin"),
        "flash.bin": os.path.join(serve, "flash.bin"),
        "flash_hdr.bin": os.path.join(serve, "flash_hdr.bin"),
        "in.bin": os.path.join(serve, "flash.bin"),
        "wb.bin": os.path.join(serve, "wb.bin"),
        "bp.bin": b"PATCHED!" * 4,
        "console_patches.bin": os.path.join(serve, "patches.bin"),
        "patches.bin": os.path.join(release, "bin", "patches_g2trinity.bin")})
    before = set(os.listdir(work))
    argv = ["client"] + ACTIONS[name] + TAIL
    said, wire = runs.with_server(material, work, argv, _table(
        {"flash_hdr": "flash_hdr.bin", "patches": "console_patches.bin"}, True))
    _keep(here, work, argv, said, wire, before)


def _avatar(material, into: str, name: str) -> None:
    here = os.path.join(into, name)
    serve = os.path.join(into, "_serve")
    work = _work(material, here, serve, {
        one: os.path.join(serve, one) for one in ("info.bin", "flash.bin",
                                                  "flash_hdr.bin")})
    runs.link(material.system_update, os.path.join(work, "su"))
    argv = ["client", "-e", "su/", *TAIL]
    said, wire = runs.with_server(material, work, argv,
                                  _table({"flash_hdr": "flash_hdr.bin"}))
    _keep(here, work, argv, said, wire, set(os.listdir(work)) | {"su"}, sums=True)
    shutil.rmtree(os.path.join(here, "made"), ignore_errors=True)


def _older(material, into: str, name: str) -> None:
    word, got = OLDER[name]
    here = os.path.join(into, "_older", name)
    serve = os.path.join(into, "_serve")
    with open(os.path.join(serve, "info.bin"), "rb") as handle:
        info = struct.pack(">I", word) + handle.read()[4:]
    work = _work(material, here, serve, {
        "info.bin": info, "flash.bin": os.path.join(serve, "flash.bin"),
        "bootloaders.bin": os.path.join(serve, "bootloaders.bin"),
        "flash_hdr.bin": os.path.join(serve, "flash_hdr.bin")})
    before = set(os.listdir(work))
    argv = ["client", "-ip", "127.0.0.1", "-i", *(["got"] if got else []), "-noenter"]
    said, wire = runs.with_server(material, work, argv,
                                  _table({"flash_hdr": "flash_hdr.bin"}, True))
    runs.put(here, {"info.bin": info})
    _keep(here, work, argv, said, wire, before)
    # The log the original keeps of itself is not among what a run is held to here.
    if os.path.isfile(os.path.join(here, "made", "client.log")):
        os.remove(os.path.join(here, "made", "client.log"))
    if os.path.isdir(os.path.join(here, "made")) and not os.listdir(
            os.path.join(here, "made")):
        os.rmdir(os.path.join(here, "made"))


def _patches(material, into: str, name: str) -> None:
    answer, slot, words = PATCHES[name]
    here = os.path.join(into, "_patches", name)
    serve = os.path.join(into, "_serve")
    info = os.path.join(into, "_info", answer, "info.bin") if answer else \
        os.path.join(serve, "info.bin")
    release = os.path.join(material.xebuild, "17559")
    work = _work(material, here, serve, {
        "info.bin": info, "slot.bin": os.path.join(serve, slot),
        "flash.bin": os.path.join(serve, "flash.bin"),
        "flash_hdr.bin": os.path.join(serve, "flash_hdr.bin"),
        "patches.bin": os.path.join(release, "bin", "patches_g2trinity.bin")})
    argv = ["client", "-p", *words, *TAIL]
    said, wire = runs.with_server(material, work, argv, _table(
        {"flash_hdr": "flash_hdr.bin", "patches": "slot.bin"}))
    runs.put(here, {"info.bin": _read(info),
                    "slot.bin": _read(os.path.join(serve, slot))})
    _keep(here, work, argv, said, wire, set(os.listdir(work)))
    shutil.rmtree(os.path.join(here, "made"), ignore_errors=True)


def _info(material, into: str, name: str) -> None:
    here = os.path.join(into, "_info", name)
    serve = os.path.join(into, "_serve")
    work = _work(material, here, serve, {
        "info.bin": os.path.join(here, "info.bin"),
        "flash_hdr.bin": os.path.join(here, "flash_hdr.bin"),
        "flash.bin": os.path.join(serve, "flash.bin")})
    argv = ["client", "-i", "got", *TAIL]
    said, _wire = runs.with_server(material, work, argv,
                                   _table({"flash_hdr": "flash_hdr.bin"}))
    with open(os.path.join(here, "original.txt"), "w", encoding="latin-1") as handle:
        handle.write(said)
    made = os.path.join(work, "got", "options.ini")
    if os.path.isfile(made):
        shutil.copyfile(made, os.path.join(here, "options.ini"))
    runs.clear(work)


def _sysdata(material, into: str, name: str) -> None:
    words, answer, tree = SYSDATA[name]
    here = os.path.join(into, "_sysdata", name)
    serve = os.path.join(into, "_serve")
    work = _work(material, here, serve, {
        "info.bin": os.path.join(into, answer, "info.bin"),
        "flash.bin": os.path.join(serve, "flash.bin"),
        "flash_hdr.bin": os.path.join(serve, "flash_hdr.bin")})
    TREES[tree](material, work)
    argv = ["client", *words, *TAIL]
    said, wire = runs.with_server(material, work, argv,
                                  _table({"flash_hdr": "flash_hdr.bin"}), timeout=1800)
    with open(os.path.join(here, "case.json"), "w") as handle:
        json.dump({"argv": argv, "serve": answer, "tree": tree}, handle)
    _keep(here, work, argv, said, wire, set(os.listdir(work)), sums=True)
    os.remove(os.path.join(here, "argv.json"))
    shutil.rmtree(os.path.join(here, "made"), ignore_errors=True)


def _read(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


# --- the trees -e and -c run on -----------------------------------------------------

def _compat(material, work):
    runs.put(work, {"compat/index": b"index body\n", "compat/alpha.txt": b"a" * 0x123,
                    "compat/Zeta.txt": b"z" * 0x40, "compat/empty.bin": b"",
                    "compat/.dotfile": b"dot", "compat/.hidden/d.bin": b"d" * 0x10,
                    "compat/Sub/b.bin": bytes(range(256)) * 3,
                    "compat/Sub/Deeper/c.bin": b"c" * 0x2001})
    os.makedirs(os.path.join(work, "compat", "EmptyDir"))


def _compat_noindex(material, work):
    _compat(material, work)
    os.remove(os.path.join(work, "compat", "index"))


def _system_update(material, work, where="su"):
    source = os.path.join(material.system_update, "$SystemUpdate")
    target = os.path.join(work, where) if where == "flat" else \
        os.path.join(work, where, "$SystemUpdate")
    os.makedirs(target)
    for one in os.listdir(source):
        runs.link(os.path.join(source, one), os.path.join(target, one))


def _changed(name: str, at: int | None):
    def lay(material, work):
        _system_update(material, work)
        path = os.path.join(work, "su", "$SystemUpdate", name)
        body = bytearray(_read(path))
        os.remove(path)
        if at is not None:
            body[at if at >= 0 else len(body) + at] ^= 1
            with open(path, "wb") as handle:
                handle.write(body)
    return lay


TREES = {
    "compat_tree": _compat,
    "compat_noindex": _compat_noindex,
    "su": _system_update,
    "su_flat": lambda material, work: _system_update(material, work, "flat"),
    "su_corrupt_container": _changed("FFFE07DF00000001", 0xD000),
    "su_corrupt_file": _changed("nuihud.xex", 0x100),
    "su_missing_file": _changed("nuihud.xex", None),
    "su_header_hash": _changed("FFFE07DF00000001", 0x32C),
    "flip_0x10": _changed("FFFE07DF00000001", 0x10),
    "flip_0xb6100": _changed("FFFE07DF00000001", 0xB6100),
    "flip_0xb7f00": _changed("FFFE07DF00000001", 0xB7F00),
    "flip_-0x5": _changed("FFFE07DF00000001", -5),
}
