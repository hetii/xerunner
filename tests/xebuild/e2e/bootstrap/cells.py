"""Cells: one build of the original each, from material staged for one question.

A cell is `cell.json` -- the type, the board and the settings by `BuildConfig`'s names,
and the release when it is not J-Runner's 17559 -- the per-build `data/` the original
was handed, and the `theirs.bin` it built. What each one asks is in `e2e_build`'s
`WhatTheOriginalBuiltFromEachCell`; how its material is made is the table below.

A cell's data is J-Runner's per-build directory -- the CPU key, options.ini and the
three loaders -- and whatever its row adds by name: a file of J-Runner's (`jr:`), the
console's dump or a dump made from it (`dump`, `dump:<kind>`), one of its security
files open or sealed (`own:`, `open:`), another console's (`foreign:`), or bytes.
"""

import os
import json
import shutil
import concurrent.futures

from . import runs, crafted
from .material import digest

# Settings a cell names, and the switch the original takes each as.
SWITCHES = {"noecdremap": ["-o", "noecdremap"], "noremap": ["-o", "noremap"],
            "nandmu": ["-o", "nandmu"], "cygnos": ["-o", "cygnos"],
            "nomobile": ["-o", "nomobile"], "no_random": ["-norandom"]}

# Bytes several rows hand in.
META = crafted.META
FUSES = b"\xa5" * 0x60
VFUSES = bytes.fromhex("1122334455667788") * 12

DONOR = {"kv.bin": "jr:Donor Files/slim_nofcrt.bin",
         "fcrt.bin": "jr:Donor Files/fcrt.bin"}


def _smc(name: str) -> str:
    return "jr:data/%s.bin" % name


def _donor(board: str, smc: str) -> dict:
    return {**DONOR, "smc.bin": "jr:data/" + smc,
            "smc_config.bin": "jr:Donor Files/smc_config/%s.bin" % board}


TRINITY = {"nanddump.bin": "dump", "smc.bin": _smc("TRINITY_SMC+")}
FALCON_JTAG = {"nanddump.bin": "dump", "smc.bin": _smc("SMCfzj")}
DONOR_SETTINGS = {"cfldv": 14, "no_random": True}

# name: (type, board, settings, the clock it runs at, its data, its release)
# A release is a version and what is changed in a copy of it, or None for 17559 as
# J-Runner ships it.
CELLS = {
    "badblocks-16mb-to-bb": ("glitch2", "jasperbb", {}, 0x5A123457,
                             {"nanddump.bin": "dump:bad_blocks",
                              "smc.bin": _smc("JASPER_SMC+")}, ("17559", {})),
    "badblocks-bigblock": ("glitch2", "jasperbb", {}, 0x5A123457,
                           {"nanddump.bin": "dump:big_bad_block",
                            "smc.bin": _smc("JASPER_SMC+")}, ("17559", {})),
    "badblocks-noecdremap": ("glitch2", "trinity", {"noecdremap": True}, 0x6AB4C66E,
                             {**TRINITY, "nanddump.bin": "dump:bad_blocks"}, None),
    "badblocks-noremap": ("glitch2", "trinity", {"noremap": True}, 0x6AB4C66E,
                          {**TRINITY, "nanddump.bin": "dump:bad_blocks"}, None),
    "badblocks-plain": ("glitch2", "trinity", {}, 0x6AB4C66E,
                        {**TRINITY, "nanddump.bin": "dump:bad_blocks"}, None),
    "blmod-cbb": ("glitch2", "trinity", {}, 0x5A123457,
                  {"nanddump.bin": "dump", "blmod.bin": "count:0x200"}, None),
    "blmod-cbb-no-xell": ("glitch2", "trinity", {}, 0x5A123457,
                          {"nanddump.bin": "dump", "blmod.bin": "count:0x4000"}, None),
    "blmod-cbb-truncated": ("glitch2", "trinity", {}, 0x5A123457,
                            {"nanddump.bin": "dump", "blmod.bin": "count:0x6000"},
                            None),
    "devkit-17489-falcon": ("devkit", "falcon", {}, 0x6AB46F42,
                            {"nanddump.bin": "dump"}, ("17489", "devkit")),
    "devkit-17489-jasper": ("devkit", "jasper", {}, 0x6AB4D1B6,
                            {"nanddump.bin": "dump", "smc.bin": _smc("JASPER_CLEAN")},
                            ("17489", "devkit")),
    "devkit-17489-jasperbb": ("devkit", "jasperbb", {}, 0x6AB4D1B6,
                              {"nanddump.bin": "dump",
                               "smc.bin": _smc("JASPER_CLEAN")}, ("17489", "devkit")),
    "devkit-17489-xenon": ("devkit", "xenon", {}, 0x6AB4D1B6,
                           {"nanddump.bin": "dump", "smc.bin": _smc("XENON_CLEAN")},
                           ("17489", "devkit")),
    "devkit-1838-falcon": ("devkit", "falcon", {}, 0x6AB4D1B6,
                           {"nanddump.bin": "dump", "smc.bin": _smc("FALCON_CLEAN")},
                           ("1838", "devkit")),
    "donor-glitch-falcon": ("glitch", "falcon", DONOR_SETTINGS, 0x6AB4C514,
                            _donor("Falcon", "FALCON_SMC+.bin"), None),
    "donor-glitch2-corona": ("glitch2", "corona", DONOR_SETTINGS, 0x6AB4C3C0,
                             _donor("Corona", "CORONA_SMC+.bin"), None),
    "donor-glitch2-corona4g": ("glitch2", "corona4g", DONOR_SETTINGS, 0x6AB4C528,
                               _donor("Corona", "CORONA_SMC+.bin"), None),
    "donor-glitch2-jasperbb": ("glitch2", "jasperbb", DONOR_SETTINGS, 0x6AB4C528,
                               _donor("Jasper", "JASPER_SMC+.bin"), None),
    "donor-glitch2-trinity": ("glitch2", "trinity", DONOR_SETTINGS, 0x6AB4C3C0,
                              _donor("Trinity", "TRINITY_SMC+.bin"), None),
    "donor-glitch2m-trinity": ("glitch2m", "trinity", DONOR_SETTINGS, 0x6AB4C514,
                               _donor("Trinity", "TRINITY_SMC+.bin"), None),
    "donor-jtag-falcon": ("jtag", "falcon", DONOR_SETTINGS, 0x6AB4C3C0,
                          _donor("Falcon", "SMCfzj.bin"), None),
    "donor-jtag-xenon": ("jtag", "xenon", DONOR_SETTINGS, 0x6AB4C528,
                         _donor("Xenon", "SMCx.bin"), None),
    "donor-retail-falcon": ("retail", "falcon", DONOR_SETTINGS, 0x6AB4C528,
                            _donor("Falcon", "FALCON_CLEAN.bin"), None),
    "donor-retail-trinity": ("retail", "trinity", DONOR_SETTINGS, 0x6AB4C514,
                             _donor("Trinity", "TRINITY_CLEAN.bin"), None),
    "fullflash-run": ("glitch2", "trinity", {}, 0x5A123457, TRINITY,
                      ("17559", "pad:0x138000")),
    "fullflash-run4f": ("glitch2", "trinity", {}, 0x5A123457, TRINITY,
                        ("17559", "pad:0x13C000")),
    "fullflash-run50": ("glitch2", "trinity", {}, 0x5A123457, TRINITY,
                        ("17559", "pad:0x140000")),
    "jtag-no-second-pair": ("jtag", "falcon", {}, 0x5A123457, FALCON_JTAG,
                            ("17559", "no_second_pair")),
    "loader-fb9199": ("jtag", "falcon", {}, 0x5A123457, FALCON_JTAG,
                      ("9199", "freeboot:same")),
    "loader-fbm-cygnos": ("jtag", "falcon", {"cygnos": True}, 0x5A123457, FALCON_JTAG,
                          ("17559", "freeboot:flip+count")),
    "loader-fbm-plain": ("jtag", "falcon", {}, 0x5A123457, FALCON_JTAG,
                         ("17559", "freeboot:flip+count")),
    "loader-fbv-app": ("jtag", "falcon", {}, 0x5A123457, FALCON_JTAG,
                       ("17559", "freeboot:count")),
    "loader-fbv-flip": ("jtag", "falcon", {}, 0x5A123457, FALCON_JTAG,
                        ("17559", "freeboot:flip")),
    "loader-plv-flip": ("jtag", "falcon", {}, 0x5A123457, FALCON_JTAG,
                        ("17559", "payload:flip")),
    "loader-plv-imm": ("jtag", "falcon", {}, 0x5A123457, FALCON_JTAG,
                       ("17559", "payload:imm")),
    "loader-plv-op": ("jtag", "falcon", {}, 0x5A123457, FALCON_JTAG,
                      ("17559", "payload:op")),
    "loader-plv-same": ("jtag", "falcon", {}, 0x5A123457, FALCON_JTAG,
                        ("17559", "payload:same")),
    "material-crl": ("glitch2", "trinity", {}, 0x5A123457,
                     {**TRINITY, "crl.bin": "open:crl.bin"}, ("17559", {})),
    "material-crl-foreign": ("glitch2", "trinity", {}, 0x5A123457,
                             {**TRINITY, "crl.bin": "foreign:crl.bin"}, ("17559", {})),
    "material-crl-own": ("glitch2", "trinity", {}, 0x5A123457,
                         {**TRINITY, "crl.bin": "own:crl.bin"}, ("17559", {})),
    "material-dae": ("glitch2", "trinity", {}, 0x5A123457,
                     {**TRINITY, "dae.bin": "open:dae.bin"}, ("17559", {})),
    "material-ext-foreign": ("glitch2", "trinity", {}, 0x5A123457,
                             {**TRINITY, "extended.bin": "foreign:extended.bin"},
                             ("17559", {})),
    "material-extended": ("glitch2", "trinity", {}, 0x5A123457,
                          {**TRINITY, "extended.bin": "open:extended.bin"},
                          ("17559", {})),
    "material-fcrt-donor": ("glitch2", "trinity", {}, 0x5A123457,
                            {**TRINITY, "fcrt.bin": "jr:Donor Files/fcrt.bin"},
                            ("17559", {})),
    "material-fuses-glitch2m": ("glitch2m", "trinity", {}, 0x5A123457,
                                {**TRINITY, "fuses.bin": FUSES}, None),
    "material-fuses-jtag": ("jtag", "falcon", {}, 0x5A123457,
                            {**FALCON_JTAG, "fuses.bin": FUSES}, None),
    "material-fuses-jtag-short": ("jtag", "falcon", {}, 0x5A123457,
                                  {**FALCON_JTAG, "fuses.bin": FUSES[:0x20]}, None),
    "material-kv-donor": ("glitch2", "trinity", {}, 0x5A123457,
                          {**TRINITY, "kv.bin": "jr:Donor Files/slim_nofcrt.bin"},
                          ("17559", {})),
    "material-kv-foreign-sealed": ("glitch2", "trinity", {}, 0x5A123457,
                                   {**TRINITY, "kv.bin": "foreign:kv.bin"},
                                   ("17559", {})),
    "material-kv-own-sealed": ("glitch2", "trinity", {}, 0x5A123457,
                               {**TRINITY, "kv.bin": "own:kv.bin"}, ("17559", {})),
    "material-manufacturing-dump": ("glitch2", "trinity", {}, 0x5A123457,
                                    {"nanddump.bin": "dump:manufacturing"}, None),
    "material-manufacturing-dump-nomobile": ("glitch2", "trinity", {"nomobile": True},
                                             0x5A123457,
                                             {"nanddump.bin": "dump:manufacturing"},
                                             None),
    "material-manufacturing-long": ("glitch2", "trinity", {}, 0x5A123457,
                                    {"nanddump.bin": "dump",
                                     "Manufacturing.data": b"\x77" * 0x1400}, None),
    "material-manufacturing-short": ("glitch2", "trinity", {}, 0x5A123457,
                                     {"nanddump.bin": "dump",
                                      "Manufacturing.data": b"\x44" * 0x80}, None),
    "material-meta-6717-dash": ("jtag", "falcon", {}, 0x5A123456, FALCON_JTAG,
                                ("6717", "meta:dash.xex")),
    "material-meta-common-donor": ("glitch2", "trinity", DONOR_SETTINGS, 0x5A123457,
                                   _donor("Trinity", "TRINITY_SMC+.bin"),
                                   ("17559", "meta-common:xenonclatin.xtt")),
    "material-meta-crl": ("glitch2", "trinity", {}, 0x5A123456,
                          {"nanddump.bin": "dump", "crl.bin": "own:crl.bin",
                           "crl.bin.meta": META}, None),
    "material-meta-crl-short": ("glitch2", "trinity", {}, 0x5A123456,
                                {"nanddump.bin": "dump", "crl.bin": "own:crl.bin",
                                 "crl.bin.meta": META[:2]}, None),
    "material-meta-dae": ("glitch2", "trinity", {}, 0x5A123456,
                          {"nanddump.bin": "dump", "dae.bin": "own:dae.bin",
                           "dae.bin.meta": META}, None),
    "material-meta-extended": ("glitch2", "trinity", {}, 0x5A123456,
                               {"nanddump.bin": "dump",
                                "extended.bin": "own:extended.bin",
                                "extended.bin.meta": META}, None),
    "material-meta-fcrt": ("glitch2", "trinity", {}, 0x5A123456,
                           {"nanddump.bin": "dump", "fcrt.bin": "own:fcrt.bin",
                            "fcrt.bin.meta": META}, None),
    "material-meta-secdata": ("glitch2", "trinity", {}, 0x5A123456,
                              {"nanddump.bin": "dump", "secdata.bin": "own:secdata.bin",
                               "secdata.bin.meta": META}, None),
    "material-mixed-dae": ("glitch2", "trinity", {}, 0x5A123457,
                           {**TRINITY, "dae.bin": "mixed:dae.bin"}, ("17559", {})),
    "material-mobileB": ("glitch2", "trinity", {}, 0x5A123457,
                         {**TRINITY, "MobileB.dat": "drawn:MobileB.dat:0x800"},
                         ("17559", {})),
    "material-mobileF": ("glitch2", "trinity", {}, 0x5A123457,
                         {"nanddump.bin": "dump", "MobileF.dat": "mobile:0x5a"}, None),
    "material-mobileJ-nomobile": ("glitch2", "trinity", {"nomobile": True}, 0x5A123457,
                                  {"nanddump.bin": "dump",
                                   "MobileJ.dat": "mobile:0x5a"}, None),
    "material-own-dae": ("glitch2", "trinity", {}, 0x5A123457,
                         {**TRINITY, "dae.bin": "own:dae.bin"}, ("17559", {})),
    "material-own-ext": ("glitch2", "trinity", {}, 0x5A123457,
                         {**TRINITY, "extended.bin": "own:extended.bin"},
                         ("17559", {})),
    "material-own-sec": ("glitch2", "trinity", {}, 0x5A123457,
                         {**TRINITY, "secdata.bin": "own:secdata.bin"}, ("17559", {})),
    "material-plainz-ext": ("glitch2", "trinity", {}, 0x5A123457,
                            {**TRINITY, "extended.bin": "zeroed:extended.bin"},
                            ("17559", {})),
    "material-sec-foreign": ("glitch2", "trinity", {}, 0x5A123457,
                             {**TRINITY, "secdata.bin": "foreign:secdata.bin"},
                             ("17559", {})),
    "material-secdata": ("glitch2", "trinity", {}, 0x5A123457,
                         {**TRINITY, "secdata.bin": "open:secdata.bin"}, ("17559", {})),
    "material-short-ext": ("glitch2", "trinity", {}, 0x5A123457,
                           {**TRINITY, "extended.bin": "short:extended.bin:0x3000"},
                           ("17559", {})),
    "material-short-sec": ("glitch2", "trinity", {}, 0x5A123457,
                           {**TRINITY, "secdata.bin": "short:secdata.bin:0x200"},
                           ("17559", {})),
    "material-smc_config": ("glitch2", "trinity", {}, 0x5A123457,
                            {**TRINITY,
                             "smc_config.bin": "jr:Donor Files/smc_config/Trinity.bin"},
                            ("17559", {})),
    "material-statistics": ("glitch2", "trinity", {}, 0x5A123457,
                            {"nanddump.bin": "dump",
                             "Statistics.settings": "count:0x1000"}, None),
    "material-statistics-long": ("glitch2", "trinity", {}, 0x5A123457,
                                 {"nanddump.bin": "dump",
                                  "Statistics.settings": b"\x33" * 0x1400}, None),
    "material-statistics-nomobile": ("glitch2", "trinity", {"nomobile": True},
                                     0x5A123457,
                                     {"nanddump.bin": "dump",
                                      "Statistics.settings": "count:0x1000"}, None),
    "material-statistics-short": ("glitch2", "trinity", {}, 0x5A123457,
                                  {"nanddump.bin": "dump",
                                   "Statistics.settings": b"\x22" * 0x400}, None),
    "mu256-nandmu": ("glitch2", "jasper256", {"nandmu": True}, 0x6AB4C7CC,
                     {"nanddump.bin": "dump:mu256", "smc.bin": _smc("JASPER_SMC+")},
                     None),
    "mu64-nandmu": ("glitch2", "jasper256", {"nandmu": True}, 0x6AB4C7CC,
                    {"nanddump.bin": "dump:mu64", "smc.bin": _smc("JASPER_SMC+")},
                    None),
    "mu64-plain": ("glitch2", "jasper256", {}, 0x6AB4C7CC,
                   {"nanddump.bin": "dump:mu64", "smc.bin": _smc("JASPER_SMC+")},
                   None),
    "patchname-i-and-r": ("glitch2", "trinity",
                          {"firmware_ext": "X", "section_ext": "Y"},
                          0x5A123457, TRINITY, ("17559", "i_and_r")),
    "rgh3-norandom": ("glitch2", "trinity", {"no_random": True}, 0x5A123457,
                      {**TRINITY, "nanddump.bin": "dump:rgh3"}, ("17559", {})),
}

# The clock a cell's cell.json states, where the build's own cannot be read back.
TOLD_WHEN = {name: 1511142486 for name in CELLS if name.startswith("material-meta-")
             and name not in ("material-meta-common-donor",)}

# The big block image the bad block and memory-unit dumps start from: a retail
# jasperbb build of the console's dump, with J-Runner's clean Jasper SMC under the
# dump's seed, at the clock it was first made at.
BIG_BLOCK_BASE = ("retail", "jasperbb", "JASPER_CLEAN.bin", 0x6AB472F6)


def make(material) -> dict:
    console = material.console
    inputs = {"dump": digest(console.dump), "key": console.key,
              "foreign": material.foreign_digest}
    where = material.made("cells", inputs, lambda into: _make_all(material, into))
    return {"XEBUILD_CELLS": where}


def _make_all(material, into: str) -> None:
    kit = Kit(material, into, material.path("cells-shared"))
    with concurrent.futures.ThreadPoolExecutor(runs.WORKERS) as pool:
        for failed in pool.map(lambda name: _make(kit, name), sorted(CELLS)):
            if failed:
                raise RuntimeError(failed)


class Kit:
    """What the cells share: the console's dump in its several forms, the foreign
    console's files, the original's exe, made once each."""

    def __init__(self, material, into: str, shared: str):
        self.material = material
        self.into = into
        self.shared = shared
        shutil.rmtree(shared, ignore_errors=True)
        os.makedirs(shared)
        console = material.console
        with open(console.dump, "rb") as handle:
            self.raw = handle.read()
        self.cpu_key = bytes.fromhex(console.key)
        self.one_bl_key = bytes.fromhex(runs.ONE_BL_KEY)
        from xebuild.config import BuildConfig
        self.xex_key = BuildConfig(one_bl_key=self.one_bl_key).xex_key
        with open(os.path.join(material.xebuild, "xeBuild.exe"), "rb") as handle:
            self.exe = handle.read()
        self.dumps = {"dump": console.dump}
        self.dumps["bad_blocks"] = self._keep("bad_blocks",
                                              crafted.bad_blocks(self.raw))
        self.dumps["manufacturing"] = self._keep("manufacturing",
                                                 crafted.manufacturing(self.raw))
        with open(os.path.join(material.jrunner, "common", "xell-images", "glitch2",
                               "TRINITY_RGH3.ecc"), "rb") as handle:
            ecc = handle.read()
        self.dumps["rgh3"] = self._keep("rgh3", crafted.rgh3(
            self.raw, ecc, self.cpu_key, self.one_bl_key))
        base = self._big_block_base()
        self.dumps["big_bad_block"] = self._keep("big_bad_block",
                                                 crafted.big_bad_block(base))
        self.dumps["mu64"] = self._keep("mu64", crafted.memory_units(base, len(base)))
        self.dumps["mu256"] = self._keep("mu256",
                                         crafted.memory_units(base, 0x10800000))

    def _keep(self, name: str, raw: bytes) -> str:
        path = os.path.join(self.shared, name + ".bin")
        with open(path, "wb") as handle:
            handle.write(raw)
        return path

    def _big_block_base(self) -> bytes:
        kind, board, smc, when = BIG_BLOCK_BASE
        work = os.path.join(self.shared, "run-base")
        with open(os.path.join(self.material.xebuild, "data", smc), "rb") as handle:
            plain = self.material.console.smc_seed + handle.read()[4:]
        runs.lay(self.material, work, {**runs.console_files(self.material),
                                       "smc.bin": plain}, when)
        said = runs.build(self.material, work, ["-t", kind, "-c", board, "-f", "17559",
                                                "-d", "data", "-noenter", "out.bin"])
        failed = runs.keep(work, "out.bin", os.path.join(self.shared, "base.bin"), said)
        if failed:
            raise RuntimeError(failed)
        with open(os.path.join(self.shared, "base.bin"), "rb") as handle:
            return handle.read()

    def file(self, token):
        """A data file's content from its row: a path to link, or bytes."""
        if isinstance(token, bytes):
            return token
        kind, _, rest = token.partition(":")
        material = self.material
        if kind == "jr":
            return os.path.join(material.xebuild, rest)
        if kind == "dump":
            return self.dumps[rest or "dump"]
        if kind == "own":
            if rest == "kv.bin":
                return crafted.keyvault(self.raw)
            return crafted.security_file(self.raw, rest)
        if kind == "open":
            return crafted.opened(self.raw, rest, self.cpu_key, self.xex_key)
        if kind == "zeroed":
            return bytes(0x10) + crafted.opened(self.raw, rest, self.cpu_key,
                                                self.xex_key)[0x10:]
        if kind == "short":
            name, _, length = rest.partition(":")
            return crafted.opened(self.raw, name, self.cpu_key,
                                  self.xex_key)[:int(length, 0)]
        if kind == "mixed":
            return crafted.mixed_dae(self.raw, self.cpu_key, self.xex_key)
        if kind == "foreign":
            raw, board = material.foreign
            if rest == "kv.bin":
                return crafted.keyvault(raw)
            return crafted.image(raw, board).read(rest)
        if kind == "mobile":
            return crafted.mobile(self.raw, int(rest, 0))
        if kind == "count":
            return bytes(index & 0xFF for index in range(int(rest, 0)))
        if kind == "drawn":
            name, _, length = rest.partition(":")
            return crafted.drawn(name, int(length, 0))
        raise ValueError("no recipe for %r" % token)

    def release(self, where: str, version: str, change, data: str) -> str:
        """A copy of J-Runner's release `version` beside a `common` and the cell's
        `data`, `change` made in it; files left as they are stay links.

        `data` is there because a release names files relative to the base directory
        the original runs in -- devkit's list has `..\\data\\xell-gggggg.bin` -- and
        the per-build directory is in it.
        """
        source = os.path.join(self.material.xebuild, version)
        target = os.path.join(where, version)
        _linked_tree(source, target)
        runs.link(data, os.path.join(where, "data"))
        common = os.path.join(where, "common")
        runs.link(os.path.join(self.material.xebuild, "common"), common)
        for name, content in self._changes(version, change).items():
            if name.startswith("../common/"):
                os.remove(common)
                _linked_tree(os.path.join(self.material.xebuild, "common"), common)
                path = os.path.join(common, name[len("../common/"):])
            else:
                path = os.path.join(target, name)
            if os.path.lexists(path):
                os.remove(path)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as handle:
                handle.write(content)
        return target

    def _changes(self, version: str, change) -> dict:
        """What a release row changes, as names in the release and their bytes."""
        if isinstance(change, dict):
            return change
        kind, _, rest = change.partition(":")
        release = os.path.join(self.material.xebuild, version)

        def read(name):
            with open(os.path.join(release, name), "rb") as handle:
                return handle.read()

        if kind == "devkit":
            return {"vfuses_khv.bin": VFUSES, "xell_reason.bin": b"\xab"}
        if kind == "pad":
            text = read("_glitch2.ini").replace(
                b"[flashfs]\n", b"[flashfs]\r\npad.bin,\n", 1)
            return {"_glitch2.ini": text, "pad.bin": b"\x5a" * int(rest, 0)}
        if kind == "no_second_pair":
            text = read("_jtag.ini")
            for pair in (b"cf_17559.bin,0883e155", b"cg_17559.bin,10fbc84d"):
                text = text.replace(pair, b"none,00000000")
            with open(os.path.join(self.material.xebuild, "1838", "SE_1838.bin"),
                      "rb") as handle:
                return {"_jtag.ini": text, "SE_1838.bin": handle.read()}
        if kind in ("freeboot", "payload"):
            blob = crafted.builtin(self.exe, kind + ".bin")
            edits = {"same": lambda b: b, "flip": lambda b: crafted.flipped(b, 0x100),
                     "count": lambda b: b + crafted.COUNTING,
                     "flip+count": lambda b: (crafted.flipped(b, 0x100)
                                              + crafted.COUNTING),
                     "imm": lambda b: crafted.flipped(b, 0x52, b"\x12\x34"),
                     "op": lambda b: crafted.flipped(b, 0x50, b"\x60\x00")}
            return {"bin/%s.bin" % kind: edits[rest](blob)}
        if kind == "meta":
            return {rest + ".meta": META}
        if kind == "meta-common":
            return {"../common/" + rest + ".meta": META}
        if kind == "i_and_r":
            text = read("_glitch2.ini")
            section = text[text.index(b"[trinitybl]\n"):]
            section = section[:section.index(b"\n\n") + 1]
            added = (section[:-1] + b"\r\n\r\n" + section.replace(b"[trinitybl]",
                                                                 b"[trinitybl_Y]"))
            out = {"_glitch2_X.ini": text.replace(section, added, 1)}
            patches = read("bin/patches_g2trinity.bin")
            for mark, suffix in enumerate(("X", "Y", "X_Y", "Y_X"), 1):
                out["bin/patches_g2trinity_%s.bin" % suffix] = crafted.flipped(
                    patches, 0x91F, bytes([mark]))
            return out
        raise ValueError("no release recipe for %r" % change)



def _linked_tree(source: str, target: str) -> None:
    for root, _dirs, names in os.walk(source):
        here = os.path.join(target, os.path.relpath(root, source))
        os.makedirs(here, exist_ok=True)
        for name in names:
            runs.link(os.path.join(root, name), os.path.join(here, name))


def _make(kit: Kit, name: str):
    kind, board, settings, when, data, release = CELLS[name]
    material = kit.material
    here = os.path.join(kit.into, name)
    files = {file: path for file, path in runs.console_files(material).items()
             if file != "nanddump.bin"}
    for file, token in data.items():
        files[file] = kit.file(token)
    runs.put(os.path.join(here, "data"), files)
    told = {"type": kind, "board": board, "settings": settings}
    releases, version = {}, "17559"
    if release is not None:
        version, change = release
        told["release"] = kit.release(os.path.join(here, "release"), version, change,
                                      os.path.join(here, "data"))
        releases = {version: told["release"],
                    "common": os.path.join(here, "release", "common")}
    if name in TOLD_WHEN:
        told["when"] = TOLD_WHEN[name]
    with open(os.path.join(here, "cell.json"), "w") as handle:
        json.dump(told, handle)
    args = ["-t", kind, "-c", board, "-f", version, "-d", "data", "-noenter"]
    for setting, value in settings.items():
        if setting == "cfldv":
            args += ["-o", "cfldv=%d" % value]
        elif setting == "firmware_ext":
            args += ["-i", value]
        elif setting == "section_ext":
            args += ["-r", value]
        else:
            args += SWITCHES[setting]
    work = os.path.join(here, "run")
    runs.lay(material, work, None, when, releases)
    runs.link(os.path.join(here, "data"), os.path.join(work, "data"))
    said = runs.build(material, work, [*args, "out.bin"])
    return runs.keep(work, "out.bin", os.path.join(here, "theirs.bin"), said)
