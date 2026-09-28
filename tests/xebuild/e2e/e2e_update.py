"""Update mode against the original, over a stand-in console.

Skipped unless `XEBUILD_UPDATE` names a directory of recordings: `_serve/` is the
stand-in console -- the bench console before RGH3, its bootloaders, flash, info and
files as `serve.json` names them -- and each other directory one run of the original,
`xeBuild.exe update -ip 127.0.0.1 -f 17559 ...` under wine with its clock frozen at
0x5A123457 (0x5A123456 for `nowrite-even`), holding `wire.log`, `payloads/` and
`made/`.

Each run is repeated here with the settings the original actually ended up with. Two
of its switches eat the word after them -- see `cli.command.parse_update` -- so
`write-noreeb` rebooted and is compared as such.

The `addons-` runs were made against the stand-in with its answer to GTIN saying it has
addons and, in `addons-blmod`, a blmod to hand over, and with those files made up for
it; each run's `served/` holds what it answered differently from `_serve/`.

The `jtag-` runs are a console saying JTAG on a Falcon, which hands over no
bootloaders and its keyvault and SMC as `kv_enc` and `smc_enc` -- a JTAG SMC, sealed
for it -- and in `jtag-falcon-blmod` a blmod as well, which a JTAG image does not take.

`write-avatar-su` was run with the 17559 system update in the release's directory, so
the avatar data went too; it keeps the image and only the SHA-1 of every file after it,
and runs here only when `XEBUILD_SYSTEM_UPDATE` names that update.

Two ranges of the image are left out of the comparison: the rest of the 0x1000 blocks
`Manufacturing.data` (0x80 bytes) and `Statistics.settings` (0x400) go into. The
original writes what its heap last held there -- the text of the release's file list,
an HMAC pad -- and this leaves them erased, a deliberate divergence; see
`BuildUpdate._console_statistics`.
"""

import os
import json
import shutil
import hashlib
import tempfile
import unittest

from .standin import StandIn
from xebuild.image import Image
from xebuild.boards import for_name
from xebuild.update import run_update
from xebuild.config import UpdateConfig

RUNS = {
    "nowrite-d": ({"dump_to": "dump", "no_write": True}, 0x5A123457),
    "nowrite-even": ({"dump_to": "dump", "no_write": True}, 0x5A123456),
    "nowrite-nodump": ({"no_write": True}, 0x5A123457),
    "clean-d2": ({"dump_to": "dump", "no_write": True, "clean": True}, 0x5A123457),
    "write-reboot": ({"no_avatar": True}, 0x5A123457),
    "write-noreeb": ({"no_avatar": True}, 0x5A123457),
    "write-avatar": ({"no_reboot": True}, 0x5A123457),
    "write-avatar-su": ({"no_reboot": True}, 0x5A123457),
    "addons-nofcrt": ({"dump_to": "dump", "no_write": True}, 0x5A123457),
    "addons-all": ({"dump_to": "dump", "no_write": True}, 0x5A123457),
    "addons-partial": ({"dump_to": "dump", "no_write": True}, 0x5A123457),
    "addons-odd": ({"dump_to": "dump", "no_write": True}, 0x5A123457),
    "addons-cmdline": ({"dump_to": "dump", "no_write": True, "append": ("nolan",)},
                       0x5A123457),
    "addons-blmod": ({"dump_to": "dump", "no_write": True}, 0x5A123457),
    "jtag-falcon": ({"dump_to": "dump", "no_write": True}, 0x5A123457),
    "jtag-falcon-blmod": ({"dump_to": "dump", "no_write": True}, 0x5A123457),
    "jtag-falcon-pairing": ({"dump_to": "dump", "no_write": True}, 0x5A123457),
    "jtag-6717": ({"dump_to": "dump", "no_write": True, "data": "6717"}, 0x5A123457),
}
HEAP_LEFTOVERS = ((0xF74080, 0xF75000), (0xF78400, 0xF79000))


class EachRunAsTheOriginalDidIt(unittest.TestCase):
    """Each run's recording. `AnOlderServer` takes its helpers and replaces its test
    by naming its own the same, so the runs do not go again under it."""

    @classmethod
    def setUpClass(cls):
        cls.where = os.environ.get("XEBUILD_UPDATE", "")
        cls.release = os.environ.get("XEBUILD_ORIGINAL_DIR", "")
        if not os.path.isdir(os.path.join(cls.where, "_serve")) or \
                not os.path.isdir(cls.release):
            raise unittest.SkipTest("XEBUILD_UPDATE or XEBUILD_ORIGINAL_DIR is not "
                                    "set: the recordings and the xeBuild folder")

    def serve_for(self, recorded: str) -> str:
        """`_serve/`, or where a run answered differently a copy of it made of links
        with the run's own `served/` files over them."""
        own = os.path.join(recorded, "served")
        shared = os.path.join(self.where, "_serve")
        if not os.path.isdir(own):
            return shared
        serve = tempfile.mkdtemp(prefix="xebuild-serve-")
        self.addCleanup(shutil.rmtree, serve, ignore_errors=True)
        with open(os.path.join(own, "served.json")) as handle:
            served = json.load(handle)
        with open(os.path.join(shared, "serve.json")) as handle:
            table = json.load(handle)
        table["files"].update(served["files"])
        if served.get("no_bootloaders"):
            del table["bootloaders"]
        table["info"] = "served-" + served["info"]
        for one in os.listdir(shared):
            if one != "serve.json":
                os.symlink(os.path.join(shared, one), os.path.join(serve, one))
        for one in os.listdir(own):
            if one != "served.json":
                name = "served-" + one if one == served["info"] else one
                os.symlink(os.path.join(own, one), os.path.join(serve, name))
        with open(os.path.join(serve, "serve.json"), "x") as handle:
            json.dump(table, handle)
        return serve

    def run_ours(self, settings, when, system_update=None, serve=None):
        work = tempfile.mkdtemp(prefix="xebuild-update-")
        self.addCleanup(shutil.rmtree, work, ignore_errors=True)
        os.symlink(os.path.join(self.release, "common"), os.path.join(work, "common"))
        version = settings.get("data", "17559")
        if system_update is None:
            os.symlink(os.path.join(self.release, version), os.path.join(work, version))
        else:
            # The release as links, file by file, with the update beside them.
            os.makedirs(os.path.join(work, version))
            for one in os.listdir(os.path.join(self.release, version)):
                os.symlink(os.path.join(self.release, version, one),
                           os.path.join(work, version, one))
            os.symlink(os.path.join(system_update, "$SystemUpdate"),
                       os.path.join(work, version, "$SystemUpdate"))
        for one in ("xell-gggggg.bin", "xell-1f.bin", "xell-2f.bin"):
            shutil.copy(os.path.join(self.release, "data", one), work)
        stand_in = StandIn(serve or os.path.join(self.where, "_serve"))
        self.stand_in = stand_in
        stand_in.start()
        here = os.getcwd()
        os.chdir(work)
        try:
            config = UpdateConfig(address="127.0.0.1", **{"data": "17559", **settings})
            run_update(config, port=stand_in.port, when=when)
        finally:
            os.chdir(here)
            stand_in.join(30)
        return stand_in, work

    def same_image(self, ours: bytes, theirs: bytes, what: str):
        board, _ = for_name("trinity")
        a, b = Image(ours, board.flash), Image(theirs, board.flash)
        keep = bytearray(len(a.flat))
        for start, end in HEAP_LEFTOVERS:
            keep[start:end] = b"\x01" * (end - start)
        wrong = [at for at in range(len(a.flat))
                 if a.flat[at] != b.flat[at] and not keep[at]]
        self.assertEqual(wrong[:8], [], what)
        pairs = enumerate(zip(a.spares, b.spares, strict=True))
        pages = [page for page, (x, y) in pairs
                 if x != y and not any(page * 0x200 < e and s < (page + 1) * 0x200
                                       for s, e in HEAP_LEFTOVERS)]
        self.assertEqual(pages, [], what)

    def test_the_wire_the_image_and_what_is_kept(self):
        for name, (settings, when) in RUNS.items():
            recorded = os.path.join(self.where, name)
            if not os.path.isdir(recorded):
                continue
            system_update = None
            if os.path.isfile(recorded + "/placed.json"):
                system_update = os.environ.get("XEBUILD_SYSTEM_UPDATE", "")
                if not os.path.isdir(system_update):
                    continue
            with self.subTest(name):
                stand_in, work = self.run_ours(settings, when, system_update,
                                               self.serve_for(recorded))
                with open(recorded + "/wire.log") as handle:
                    wanted = [one for one in handle.read().splitlines() if one]
                self.assertEqual(stand_in.lines, wanted)
                summed = {}
                if os.path.isfile(recorded + "/payloads.sha1.json"):
                    with open(recorded + "/payloads.sha1.json") as handle:
                        summed = json.load(handle)
                for number, body in enumerate(stand_in.payloads, 1):
                    kept = recorded + "/payloads/payload%02d.bin" % number
                    if os.path.isfile(kept):
                        with open(kept, "rb") as handle:
                            self.same_image(body, handle.read(), "payload %d" % number)
                    else:
                        self.assertEqual(hashlib.sha1(body).hexdigest(),
                                         summed["payload%02d.bin" % number], number)
                kept = recorded + "/made/dump"
                if not os.path.isdir(kept):
                    continue
                for one in sorted(os.listdir(kept)):
                    if one.endswith(".log"):
                        continue
                    with open(os.path.join(kept, one), "rb") as a, \
                            open(os.path.join(work, "dump", one), "rb") as b:
                        if one.endswith(".bin") and \
                                one.startswith(settings.get("data", "17559") + "_"):
                            self.same_image(b.read(), a.read(), one)
                        else:
                            self.assertEqual(b.read(), a.read(), one)


class AnOlderServer(EachRunAsTheOriginalDidIt):
    """`_older/`: a console saying an older server or peek version. The original
    refuses right after GTIN -- the peek version first, "console hv patches are not
    recent enough to support update mode!", then "updsvr on console needs to be
    updated!" below version 3 -- and hangs up without a QUIT."""

    def test_the_wire_the_image_and_what_is_kept(self):
        where = os.path.join(self.where, "_older")
        if not os.path.isdir(where):
            self.skipTest("XEBUILD_UPDATE holds no _older recordings")
        for name in sorted(os.listdir(where)):
            with self.subTest(name):
                one = os.path.join(where, name)
                serve = tempfile.mkdtemp(prefix="xebuild-serve-")
                self.addCleanup(shutil.rmtree, serve, ignore_errors=True)
                shared = os.path.join(self.where, "_serve")
                for part in os.listdir(shared):
                    if part != "info.bin":
                        os.symlink(os.path.join(shared, part),
                                   os.path.join(serve, part))
                shutil.copy(one + "/info.bin", serve + "/info.bin")
                with open(one + "/original.txt", errors="replace") as handle:
                    said = handle.read()
                wanted = ("hv patches are not recent enough" if "hv patches" in said
                          else "updsvr on console needs to be updated")
                with self.assertRaisesRegex(ValueError, wanted):
                    self.run_ours({"no_write": True}, None, serve=serve)
                with open(one + "/wire.log") as handle:
                    self.assertEqual(self.stand_in.lines,
                                     [line for line in handle.read().splitlines()
                                      if line])


if __name__ == "__main__":
    unittest.main()
