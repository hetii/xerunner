"""Which copy of a firmware file goes in: the console's own, or the one on disk.

Skipped unless `XEBUILD_PROVENANCE` names the recorded choices (`expected.json`, the
original's, measured) and `XEBUILD_UPDATE` and `XEBUILD_ORIGINAL_DIR` are set as for
`e2e_update`. Both copies pass their checksum -- the disk's in `common/` is forged to
the same CRC32 with different bytes -- so only the rule decides, and each file's bytes
in the image show which copy it followed: the dump's in build mode, the one handed
over by cable in update mode, or the disk's.
"""

import os
import json
import zlib
import shutil
import hashlib
import tempfile
import unittest
import functools

from .standin import StandIn
from xebuild.image import Image
from xebuild.boards import for_name
from xebuild.release import Release
from ..test_chain import ONE_BL_KEY
from xebuild.update import run_update
from xebuild.build import Build, Material
from xebuild.config import BuildConfig, UpdateConfig

# Every build and release here is handed the 1BL key, as J-Runner's options.ini
# hands it to the original.
Release = functools.partial(Release, one_bl_key=ONE_BL_KEY)
BuildConfig = functools.partial(BuildConfig, one_bl_key=ONE_BL_KEY)

NAMES = ("xenonclatin.xtt", "xenonjklatin.xtt", "ximedic.xex")
LAUNCH = b"L" * 0x1000
CPU_KEY = "7E5068DBB3FD03F04E367028D475EEC2"


def forged(body: bytes, flip_at: int = 0x100, at: int = 0x200) -> bytes:
    """The same length and CRC32 as `body`, different bytes: one byte changed, then
    four at `at` set so the CRC comes back -- the register run backwards from the end
    to `at`, and forwards from the start."""
    back = {}
    for byte in range(256):
        value = byte
        for _ in range(8):
            value = (value >> 1) ^ (0xEDB88320 if value & 1 else 0)
        # Each entry's top byte is unique, which is what makes a step reversible.
        back[value >> 24] = (byte, value)

    def unstep(register: int, one: int) -> int:
        byte, value = back[register >> 24]
        return (((register ^ value) << 8) & 0xFFFFFFFF) | (byte ^ one)

    out = bytearray(body)
    out[flip_at] ^= 0x5A
    state = zlib.crc32(bytes(out[:at])) ^ 0xFFFFFFFF
    after = zlib.crc32(body) ^ 0xFFFFFFFF
    for one in reversed(out[at + 4:]):
        after = unstep(after, one)
    for _ in range(4):
        after = unstep(after, 0)
    out[at:at + 4] = (after ^ state).to_bytes(4, "little")
    assert zlib.crc32(bytes(out)) == zlib.crc32(body) and bytes(out) != body
    return bytes(out)


def spoiled(raw: bytes, name: str) -> bytes:
    """The dump with one byte of `name` changed and that page's code put right, so the
    file reads back with a wrong CRC32 and nothing else is wrong."""
    flash = for_name("trinity")[0].flash
    probe = Image(raw, flash).read(name)[0x3000:0x3040]
    at = raw.find(probe)
    out = bytearray(raw)
    out[at] ^= 1
    page = at // 0x210 * 0x210
    out[page + 0x200:page + 0x210] = flash.spare.with_ecc(
        bytes(out[page:page + 0x200]), bytes(out[page + 0x200:page + 0x210]))
    return bytes(out)


class EachCopyAsTheOriginalChoseIt(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        where = os.environ.get("XEBUILD_PROVENANCE", "")
        cls.serve = os.path.join(os.environ.get("XEBUILD_UPDATE", ""), "_serve")
        cls.release = os.environ.get("XEBUILD_ORIGINAL_DIR", "")
        if not os.path.isfile(os.path.join(where, "expected.json")) or \
                not os.path.isdir(cls.serve) or not os.path.isdir(cls.release):
            raise unittest.SkipTest("XEBUILD_PROVENANCE, XEBUILD_UPDATE or "
                                    "XEBUILD_ORIGINAL_DIR is not set")
        with open(os.path.join(where, "expected.json")) as handle:
            cls.expected = json.load(handle)

    def lay(self, launch: bool) -> tuple:
        """A directory with the release, `common/` forged, and `launch.xex` beside
        it or not; and the hashes of each copy by where it came from."""
        work = tempfile.mkdtemp(prefix="xebuild-provenance-")
        self.addCleanup(shutil.rmtree, work, ignore_errors=True)
        os.symlink(os.path.join(self.release, "17559"), os.path.join(work, "17559"))
        shutil.copytree(os.path.join(self.release, "common"),
                        os.path.join(work, "common"))
        for one in ("xell-gggggg.bin", "xell-1f.bin", "xell-2f.bin"):
            shutil.copy(os.path.join(self.release, "data", one), work)
        with open(os.path.join(self.serve, "serve_files.json")) as handle:
            served = json.load(handle)["files"]
        copies = {}
        for name in (*NAMES, "launch.xex"):
            with open(os.path.join(self.serve, served["usv:\\" + name]), "rb") as h:
                console = h.read()
            if name == "launch.xex":
                disk = LAUNCH
            else:
                with open(os.path.join(work, "common", name), "rb") as handle:
                    disk = forged(handle.read())
                with open(os.path.join(work, "common", name), "wb") as handle:
                    handle.write(disk)
            copies[name] = {"console": hashlib.sha1(console).digest(),
                            "disk": hashlib.sha1(disk).digest()}
        if launch:
            with open(os.path.join(work, "launch.xex"), "wb") as handle:
                handle.write(LAUNCH)
        return work, copies

    def chosen(self, image: bytes, copies: dict) -> dict:
        read = Image(image, for_name("trinity")[0].flash)
        out = {}
        for name, by in copies.items():
            got = hashlib.sha1(read.read(name)).digest()
            out[name] = next((where for where, one in by.items() if one == got), "?")
        return out

    def test_build_from_a_dump(self):
        with open(os.path.join(self.serve, "flash.bin"), "rb") as handle:
            dump = handle.read()
        for case, raw in (("build-dump", dump),
                          ("build-bad-dump", spoiled(dump, "xenonclatin.xtt"))):
            with self.subTest(case):
                work, copies = self.lay(launch=True)
                # In build mode the console's copy is the dump's own, which for
                # xenonclatin.xtt is not the one the stand-in hands over by cable.
                read = Image(raw, for_name("trinity")[0].flash)
                for name in copies:
                    copies[name]["console"] = hashlib.sha1(read.read(name)).digest()
                data = os.path.join(work, "data")
                os.makedirs(data)
                with open(os.path.join(data, "nanddump.bin"), "wb") as handle:
                    handle.write(raw)
                config = BuildConfig(image_type="glitch2", console="trinity",
                                     cpu_key=CPU_KEY, per_build=data)
                image = Build(config, Material(data),
                              Release(os.path.join(work, "17559"))).image(0x5A123457)
                self.assertEqual(self.chosen(image.raw, copies), self.expected[case])

    def test_update(self):
        for case, launch in (("update-launch-on-disk", True),
                             ("update-no-launch", False)):
            with self.subTest(case):
                work, copies = self.lay(launch)
                serve = os.path.join(work, "serve")
                os.makedirs(serve)
                for one in os.listdir(self.serve):
                    if one != "serve.json":
                        os.symlink(os.path.join(self.serve, one),
                                   os.path.join(serve, one))
                shutil.copy(os.path.join(self.serve, "serve_files.json"),
                            os.path.join(serve, "serve.json"))
                stand_in = StandIn(serve)
                stand_in.start()
                here = os.getcwd()
                os.chdir(work)
                try:
                    kept = run_update(UpdateConfig(address="127.0.0.1", data="17559",
                                                   dump_to="dump", no_write=True),
                                      port=stand_in.port, when=0x5A123457)
                    with open(kept, "rb") as handle:
                        image = handle.read()
                finally:
                    os.chdir(here)
                stand_in.join(30)
                self.assertEqual(self.chosen(image, copies), self.expected[case])


if __name__ == "__main__":
    unittest.main()
