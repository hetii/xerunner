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

`write-avatar-su` was run with the 17559 system update in the release's directory, so
the avatar data went too; it keeps the image and only the SHA-1 of every file after it,
and runs here only when `XEBUILD_SYSTEM_UPDATE` names that update.

Two ranges of the image are left out of the comparison: the rest of the 0x1000 blocks
`Manufacturing.data` (0x80 bytes) and `Statistics.settings` (0x400) go into. The
original fills them with bytes it was handed nowhere, the same on every run; this
leaves them erased. An open question.
"""

import hashlib
import json
import os
import shutil
import tempfile
import unittest

from xebuild.boards import for_name
from xebuild.config import UpdateConfig
from xebuild.image import Image
from xebuild.update import run_update

from .standin import StandIn

RUNS = {
    "nowrite-d": ({"dump_to": "dump", "no_write": True}, 0x5A123457),
    "nowrite-even": ({"dump_to": "dump", "no_write": True}, 0x5A123456),
    "nowrite-nodump": ({"no_write": True}, 0x5A123457),
    "clean-d2": ({"dump_to": "dump", "no_write": True, "clean": True}, 0x5A123457),
    "write-reboot": ({"no_avatar": True}, 0x5A123457),
    "write-noreeb": ({"no_avatar": True}, 0x5A123457),
    "write-avatar": ({"no_reboot": True}, 0x5A123457),
    "write-avatar-su": ({"no_reboot": True}, 0x5A123457),
}
UNEXPLAINED = ((0xF74080, 0xF75000), (0xF78400, 0xF79000))


class EachRunAsTheOriginalDidIt(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.where = os.environ.get("XEBUILD_UPDATE", "")
        cls.release = os.environ.get("XEBUILD_ORIGINAL_DIR", "")
        if not os.path.isdir(os.path.join(cls.where, "_serve")) or \
                not os.path.isdir(cls.release):
            raise unittest.SkipTest("XEBUILD_UPDATE or XEBUILD_ORIGINAL_DIR is not "
                                    "set: the recordings and the xeBuild folder")

    def run_ours(self, settings, when, system_update=None):
        work = tempfile.mkdtemp(prefix="xebuild-update-")
        self.addCleanup(shutil.rmtree, work, ignore_errors=True)
        os.symlink(os.path.join(self.release, "common"), os.path.join(work, "common"))
        if system_update is None:
            os.symlink(os.path.join(self.release, "17559"), os.path.join(work, "17559"))
        else:
            # The release as links, file by file, with the update beside them.
            os.makedirs(os.path.join(work, "17559"))
            for one in os.listdir(os.path.join(self.release, "17559")):
                os.symlink(os.path.join(self.release, "17559", one),
                           os.path.join(work, "17559", one))
            os.symlink(os.path.join(system_update, "$SystemUpdate"),
                       os.path.join(work, "17559", "$SystemUpdate"))
        for one in ("xell-gggggg.bin", "xell-1f.bin", "xell-2f.bin"):
            shutil.copy(os.path.join(self.release, "data", one), work)
        stand_in = StandIn(os.path.join(self.where, "_serve"))
        stand_in.start()
        here = os.getcwd()
        os.chdir(work)
        try:
            config = UpdateConfig(address="127.0.0.1", data="17559", **settings)
            run_update(config, port=stand_in.port, when=when)
        finally:
            os.chdir(here)
        stand_in.join(30)
        return stand_in, work

    def same_image(self, ours: bytes, theirs: bytes, what: str):
        board, _ = for_name("trinity")
        a, b = Image(ours, board.flash), Image(theirs, board.flash)
        keep = bytearray(len(a.flat))
        for start, end in UNEXPLAINED:
            keep[start:end] = b"\x01" * (end - start)
        wrong = [at for at in range(len(a.flat))
                 if a.flat[at] != b.flat[at] and not keep[at]]
        self.assertEqual(wrong[:8], [], what)
        pairs = enumerate(zip(a.spares, b.spares, strict=True))
        pages = [page for page, (x, y) in pairs
                 if x != y and not any(page * 0x200 < e and s < (page + 1) * 0x200
                                       for s, e in UNEXPLAINED)]
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
                stand_in, work = self.run_ours(settings, when, system_update)
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
                        if one.endswith(".bin") and one.startswith("17559_"):
                            self.same_image(b.read(), a.read(), one)
                        else:
                            self.assertEqual(b.read(), a.read(), one)


if __name__ == "__main__":
    unittest.main()
