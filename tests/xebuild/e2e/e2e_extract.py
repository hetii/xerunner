"""Extract mode's facts, dump by dump, against what the original's extract mode reports.

Skipped unless `XEBUILD_EXTRACT` names a directory holding a `manifest.json` -- a name
for each dump and where the dump is -- and, per name, `original.txt`: the original's
report on that dump, `xeBuild.exe extract -v -noenter nanddump.bin`. What is compared
are numbers, never wording: where each blob, file and stage is and how long, what is
remapped where, and how much of the dump is read.
"""

import json
import os
import re
import unittest

from xebuild import boards
from xebuild.image import Dump, order
from xebuild.image import dump as dumps

HEX = r"0x([0-9a-fA-F]+)"


def said(report: str) -> dict:
    """The numbers in one of the original's reports."""
    blobs = {}
    for name, version, at, length in re.findall(
            r"^\s+(fsroot|mobile\w\.dat)\s+version (\d+) found at offset %s len %s"
            % (HEX, HEX), report, re.M):
        blobs[name if name == "fsroot" else "M" + name[1:]] = (
            int(version), int(at, 16), int(length, 16))
    files = [(name, int(sector, 16), int(at, 16), int(size, 16), int(stamp, 16))
             for sector, at, size, stamp, name in re.findall(
                 r"^sector: %s offset: %s size: %s timestamp: %s name: (.+?)\s*$"
                 % (HEX, HEX, HEX, HEX), report, re.M)]
    stages = [(tag, int(build), int(at, 16), int(length, 16))
              for tag, build, at, length in re.findall(
                  r"^(\w\w) v(\d+) at %s size %s" % (HEX, HEX), report, re.M)]
    remaps = {int(source, 16): int(dest, 16) for source, dest in re.findall(
        r"^\d+: source: %s dest: %s" % (HEX, HEX), report, re.M)}
    end = re.search(r"final truncated bootloader size %s" % HEX, report)
    config = re.search(r"seeking smc config in dump\.\.\.found at offset %s" % HEX,
                       report)
    loaded = re.search(r"Loading NAND dump \(%s bytes\)" % HEX, report)
    return {"blobs": blobs, "files": files, "stages": stages, "remaps": remaps,
            "end": int(end.group(1), 16) if end else None,
            "config": int(config.group(1), 16) if config else None,
            "loaded": int(loaded.group(1), 16) if loaded else None}


class EachDumpAsTheOriginalReadsIt(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        where = os.environ.get("XEBUILD_EXTRACT", "")
        manifest = os.path.join(where, "manifest.json")
        if not os.path.isfile(manifest):
            raise unittest.SkipTest("XEBUILD_EXTRACT names no manifest of dumps")
        with open(manifest) as handle:
            cls.dumps = json.load(handle)
        cls.read = []
        for name, path in sorted(cls.dumps.items()):
            with open(os.path.join(where, name, "original.txt"),
                      errors="replace") as handle:
                theirs = said(handle.read())
            with open(path, "rb") as handle:
                whole = handle.read()
            raw = dumps.cut(whole)
            board = boards.for_dump(raw)
            cls.read.append((name, theirs, raw, board, len(whole), Dump(raw, board)))

    def each(self):
        for name, theirs, raw, board, whole, dump in self.read:
            self.assertEqual(dumps.faulty(raw, board.flash, whole), "", name)
            yield name, theirs, raw, board, dump

    def test_what_is_read_and_how_much_of_it(self):
        for name, theirs, raw, _board, dump in self.each():
            with self.subTest(name):
                self.assertEqual(len(raw), theirs["loaded"])
                self.assertEqual(dump.flash.smc_config, theirs["config"])

    def test_the_blobs(self):
        for name, theirs, _raw, _board, dump in self.each():
            with self.subTest(name):
                ours = {key: (one["version"], one["offset"], one["length"])
                        for key, one in dump.image.blobs.items()}
                self.assertEqual(ours, theirs["blobs"])

    def test_every_file_of_the_filesystem_in_the_table_s_order(self):
        for name, theirs, _raw, _board, dump in self.each():
            with self.subTest(name):
                ours = [(one.name, one.sector,
                         dump.flash.offset_of(one.sector, dump.image.bigffs),
                         one.size, one.stamp)
                        for one in dump.image.directory.entries]
                self.assertEqual(ours, theirs["files"])

    def test_the_chain_stage_by_stage(self):
        """As far as the original's walk goes: it stops where a stage is not the one
        its places expect, as on an RGH3 console."""
        for name, theirs, _raw, _board, dump in self.each():
            with self.subTest(name):
                walked = dump.chain.walked
                ours = [(one.tag, one.build, one.at, one.length) for one in walked]
                self.assertEqual(ours[:len(theirs["stages"])], theirs["stages"])
                if theirs["end"] is not None:
                    end = walked[-1].at + walked[-1].length
                    self.assertEqual(end + -end % 0x10, theirs["end"])

    def test_what_is_remapped_where(self):
        for name, theirs, raw, board, _dump in self.each():
            with self.subTest(name):
                if board.flash.spare is None:
                    continue
                per = board.flash.spare.pages_a_block * (board.flash.spare.length
                                                         + 0x200)
                ours = order.stand_ins(raw, board.flash, total=len(raw) // per)
                self.assertEqual(ours, theirs["remaps"])


if __name__ == "__main__":
    unittest.main()
