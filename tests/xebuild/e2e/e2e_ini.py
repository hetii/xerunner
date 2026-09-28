"""Ini mode against the original, case by case.

Skipped unless `XEBUILD_INI` names a directory of recordings and `XEBUILD_RELEASE_DIR`
a release beside the others, whose system update containers the cases are laid from.
Each case holds `argv.json` -- the original's command line, `xeBuild.exe ini ...` under
wine -- its log as `original.txt`, the files it wrote under `made/`, and `case.json`
saying how its directory was laid: which file came from which release's container or
was written as text, a byte flipped where one was, and the `1blkey.txt` it had, if any.
The original also leaves its own `build.log`, which is not kept.
"""

import os
import io
import json
import shutil
import tempfile
import unittest
import contextlib

from xebuild.cli import main


class EachCaseAsTheOriginalDidIt(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.where = os.environ.get("XEBUILD_INI", "")
        release = os.environ.get("XEBUILD_RELEASE_DIR", "")
        if not os.path.isdir(cls.where) or not os.path.isdir(release):
            raise unittest.SkipTest("XEBUILD_INI or XEBUILD_RELEASE_DIR is not set: "
                                    "the recordings and the releases")
        cls.releases = os.path.dirname(os.path.abspath(release))

    def lay(self, work: str, case: dict) -> None:
        for dest, source in case["lay"].items():
            path = os.path.join(work, dest)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            kind, _, what = source.partition(":")
            if kind == "rel":
                shutil.copy(os.path.join(self.releases, what, "su20076000_00000000"),
                            path)
            else:
                with open(path, "w", newline="") as handle:
                    handle.write(what)
        if "flip" in case:
            name, at = case["flip"]
            with open(os.path.join(work, name), "r+b") as handle:
                handle.seek(at)
                byte = handle.read(1)[0]
                handle.seek(at)
                handle.write(bytes([byte ^ 1]))
        if case["key"] is not None:
            with open(os.path.join(work, "1blkey.txt"), "w") as handle:
                handle.write(case["key"])

    def test_the_files_and_the_refusals(self):
        for name in sorted(os.listdir(self.where)):
            one = os.path.join(self.where, name)
            with self.subTest(name):
                with open(os.path.join(one, "case.json")) as handle:
                    case = json.load(handle)
                with open(os.path.join(one, "argv.json")) as handle:
                    argv = json.load(handle)
                work = tempfile.mkdtemp(prefix="xebuild-ini-")
                self.addCleanup(shutil.rmtree, work, ignore_errors=True)
                self.lay(work, case)
                before = self.files(work)
                here = os.getcwd()
                os.chdir(work)
                try:
                    with contextlib.redirect_stderr(io.StringIO()), \
                            contextlib.redirect_stdout(io.StringIO()):
                        status = main(argv)
                finally:
                    os.chdir(here)
                with open(os.path.join(one, "original.txt"), errors="replace") as h:
                    said = h.read()
                refused = "Completed output to" not in said
                self.assertEqual(status != 0, refused)
                theirs = self.files(os.path.join(one, "made"))
                # What it wrote: every new file, and one that was there and changed.
                ours = {key: body for key, body in self.files(work).items()
                        if before.get(key) != body}
                self.assertEqual(sorted(ours), sorted(theirs))
                for key, body in theirs.items():
                    self.assertEqual(ours[key], body, key)

    @staticmethod
    def files(where: str) -> dict:
        out = {}
        for root, _dirs, names in os.walk(where):
            for one in names:
                with open(os.path.join(root, one), "rb") as handle:
                    out[os.path.relpath(os.path.join(root, one), where)] = handle.read()
        return out


if __name__ == "__main__":
    unittest.main()
