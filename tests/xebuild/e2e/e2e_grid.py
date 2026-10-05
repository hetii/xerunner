"""Every `-o` option on every image type, against what the original built.

Skipped unless `XEBUILD_GRID` names the grid's `manifest.json` -- see
`bootstrap/grid.py`, which made it -- with `XEBUILD_DUMP`, `XEBUILD_CPUKEY`,
`XEBUILD_SMC_DIR` and `XEBUILD_RELEASE_DIR` naming what the original was given. Each
cell is built here from the same per-build directory and its image's SHA-256 held
against the original's; a cell the original refused has to be refused here too.
"""

import os
import json
import shutil
import hashlib
import tempfile
import unittest
import functools

from typing import ClassVar
from xebuild.release import Release
from ..test_chain import ONE_BL_KEY
from xebuild.config import BuildConfig
from xebuild.build import Build, Material
from xebuild.cli.command import parse_build
from .bootstrap.grid import TYPES, cells

Release = functools.partial(Release, one_bl_key=ONE_BL_KEY)
BuildConfig = functools.partial(BuildConfig, one_bl_key=ONE_BL_KEY)


class EachOptionOnEachType(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        where = os.environ.get("XEBUILD_GRID", "")
        manifest = os.path.join(where, "manifest.json")
        needed = ("XEBUILD_DUMP", "XEBUILD_CPUKEY", "XEBUILD_SMC_DIR",
                  "XEBUILD_RELEASE_DIR")
        if not os.path.isfile(manifest) or not all(os.environ.get(one)
                                                   for one in needed):
            raise unittest.SkipTest("XEBUILD_GRID, XEBUILD_DUMP, XEBUILD_CPUKEY, "
                                    "XEBUILD_SMC_DIR and XEBUILD_RELEASE_DIR are "
                                    "needed")
        with open(manifest) as handle:
            found = json.load(handle)
        cls.cells, cls.devkit = found["cells"], found["devkit_release"]
        cls.releases = os.path.dirname(os.environ["XEBUILD_RELEASE_DIR"])

    # One test a type, so that they run side by side; and the two big parts.
    GROUPS: ClassVar[dict] = {kind: ("%s-%s-" % (kind, board),)
                              for kind, (board, _, _) in TYPES.items()}
    GROUPS["big_parts"] = ("glitch2-jasperbb-", "glitch2-corona4g-")

    def test_no_cell_is_left_out(self):
        self.assertEqual(sorted(self.cells), sorted(one[0] for one in cells()))
        grouped = [name for prefixes in self.GROUPS.values() for name in self.cells
                   if name.startswith(prefixes)]
        self.assertEqual(sorted(grouped), sorted(self.cells))

    def test_retail(self):
        self._each("retail")

    def test_glitch(self):
        self._each("glitch")

    def test_glitch2(self):
        self._each("glitch2")

    def test_glitch2m(self):
        self._each("glitch2m")

    def test_jtag(self):
        self._each("jtag")

    def test_devkit(self):
        self._each("devkit")

    def test_big_parts(self):
        self._each("big_parts")

    def _each(self, group: str):
        for name in sorted(self.cells):
            if not name.startswith(self.GROUPS[group]):
                continue
            told = self.cells[name]
            with self.subTest(name):
                data = self._data(told["smc"])
                release = self.devkit if told["type"] == "devkit" else \
                    os.path.join(self.releases, told["release"])
                settings = parse_build(["-o", told["option"]])
                config = BuildConfig(ini=os.path.join(data, "options.ini"),
                                     image_type=told["type"], console=told["board"],
                                     per_build=data, **settings)
                one = Build(config, Material(data), Release(
                    release, os.path.join(os.path.dirname(release), "common")))
                if "refused" in told:
                    with self.assertRaises(ValueError):
                        one.image(None)
                    continue
                raw = one.image(told["when"]).raw
                self.assertEqual(hashlib.sha256(raw).hexdigest(), told["sha256"])

    def _data(self, smc: str) -> str:
        """The per-build directory the original was given, as links."""
        where = tempfile.mkdtemp(prefix="xebuild-e2e-grid-")
        self.addCleanup(shutil.rmtree, where, ignore_errors=True)
        shipped = os.environ["XEBUILD_SMC_DIR"]
        os.symlink(os.environ["XEBUILD_DUMP"], os.path.join(where, "nanddump.bin"))
        with open(os.path.join(where, "cpukey.txt"), "w") as handle:
            handle.write(os.environ["XEBUILD_CPUKEY"])
        for name in ("options.ini", "xell-gggggg.bin", "xell-1f.bin", "xell-2f.bin"):
            os.symlink(os.path.join(shipped, name), os.path.join(where, name))
        os.symlink(os.path.join(shipped, smc), os.path.join(where, "smc.bin"))
        return where


if __name__ == "__main__":
    unittest.main()
