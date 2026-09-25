"""Client mode against the original, action by action, over a stand-in update server.

Skipped unless `XEBUILD_CLIENT` names a directory of recordings: for each action a
directory holding `argv.json` -- the original's command line -- `wire.log`, every
command it sent and every payload's length, `payloads/` and `made/`, the files it
wrote; and `_serve/`, what the stand-in answered with, captured off a real console
(`info.bin` for GTIN, `flash.bin` for GTFL and RBLK, `flash_hdr.bin` for
`GETFflash_hdr`). The original's run is `xeBuild.exe client ... -ip 127.0.0.1` under
wine against the same stand-in; here the same command line runs against it in a thread.
`XEBUILD_ORIGINAL_DIR` is the xeBuild folder the original ran in, whose `17559/bin` the
patch update reads.

`_patches/` holds `-p` over made-up consoles, each with the `info.bin` and the console's
current patches (`slot.bin`) it was served, and the payload it sent.

`_sysdata/` holds `-e` and `-c`: `supd17559/`, the 17559 system update the avatar data
comes from, and a directory a case, each with `case.json` -- the command line, the
answers served and the tree it was run on, which `TREES` below lays again -- the wire,
and each payload's SHA-1 rather than the payload. A recording that sent the system
update keeps its SHA-1s too (`avatar/payloads.sha1.json`).
"""

import os
import json
import shutil
import hashlib
import tempfile
import unittest

from .standin import StandIn
from xebuild.client import run_client
from xebuild.config import ClientConfig
from xebuild.network import ConsoleInfo
from xebuild.cli.command import parse_client
from xebuild.client.client import options_ini, reason


class EachActionAsTheOriginalDidIt(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.where = os.environ.get("XEBUILD_CLIENT", "")
        if not os.path.isdir(os.path.join(cls.where, "_serve")):
            raise unittest.SkipTest("XEBUILD_CLIENT names no recordings of client mode")

    def each(self):
        for name in sorted(os.listdir(self.where)):
            recorded = os.path.join(self.where, name)
            if name.startswith("_") or not os.path.isfile(recorded + "/argv.json"):
                continue
            if name.startswith("patches") and \
                    not os.path.isdir(os.environ.get("XEBUILD_ORIGINAL_DIR", "")):
                continue
            # `-bp` is not implemented: the original's writes block 0 whatever
            # offset it is given and then crashes, so there is nothing to agree with.
            if name == "binary-patch":
                continue
            with open(recorded + "/argv.json") as handle:
                argv = json.load(handle)[1:]
            yield name, recorded, argv

    def run_ours(self, argv, stand_in=None, lay=None) -> tuple:
        """Our client in a directory of its own, with `lay` putting a tree in it
        first; what the stand-in saw and what was left in the directory."""
        work = tempfile.mkdtemp(prefix="xebuild-client-")
        self.addCleanup(shutil.rmtree, work, ignore_errors=True)
        serve = os.path.join(self.where, "_serve")
        for one in ("wb.bin",):
            shutil.copy(os.path.join(serve, one), work)
        shutil.copy(os.path.join(serve, "flash.bin"), os.path.join(work, "in.bin"))
        original = os.environ.get("XEBUILD_ORIGINAL_DIR", "")
        if os.path.isdir(original):
            os.symlink(os.path.join(original, "17559"), os.path.join(work, "17559"))
            shutil.copy(os.path.join(original, "17559", "bin", "patches_g2trinity.bin"),
                        os.path.join(work, "patches.bin"))
        system_update = os.path.join(self.where, "_sysdata", "supd17559")
        if lay is not None:
            lay(work)
        elif os.path.isdir(system_update):
            os.symlink(system_update, os.path.join(work, "su"))
        before = set(os.listdir(work))
        stand_in = stand_in or StandIn(serve)
        stand_in.start()
        settings, _flags = parse_client(argv)
        here = os.getcwd()
        os.chdir(work)
        stand_in.refused = None
        try:
            run_client(ClientConfig(**settings), port=stand_in.port)
        except ValueError as why:
            # Refused as the original refuses -- its log says so, and the wire is
            # held against its wire all the same.
            stand_in.refused = why
        finally:
            os.chdir(here)
        stand_in.join(30)
        made = {}
        for root, dirs, files in os.walk(work):
            dirs[:] = [one for one in dirs
                       if not os.path.islink(os.path.join(root, one))]
            for one in files:
                path = os.path.join(root, one)
                if os.path.relpath(path, work) not in before:
                    made[os.path.relpath(path, work)] = path
        return stand_in, made

    def assertPayloads(self, payloads, recorded):
        """Each payload sent against the recording's, or against its SHA-1 where the
        recording keeps only those."""
        summed = os.path.join(recorded, "payloads.sha1.json")
        if os.path.isfile(summed):
            with open(summed) as handle:
                wanted = json.load(handle)
            self.assertEqual(len(payloads), len(wanted))
            for number, body in enumerate(payloads, 1):
                self.assertEqual(hashlib.sha1(body).hexdigest(),
                                 wanted["payload%02d.bin" % number], number)
            return
        for number, body in enumerate(payloads, 1):
            with open(recorded + "/payloads/payload%02d.bin" % number, "rb") as handle:
                self.assertEqual(body, handle.read())

    def test_the_wire_and_the_files(self):
        for name, recorded, argv in self.each():
            with self.subTest(name):
                stand_in, made = self.run_ours(argv)
                with open(recorded + "/wire.log") as handle:
                    wanted = [one for one in handle.read().splitlines() if one]
                self.assertEqual(stand_in.lines, wanted)
                self.assertPayloads(stand_in.payloads, recorded)
                theirs = {}
                for root, _dirs, files in os.walk(recorded + "/made"):
                    for one in files:
                        if one == "client.log":
                            continue
                        path = os.path.join(root, one)
                        theirs[os.path.relpath(path, recorded + "/made")] = path
                if name == "info-dir":
                    # The original runs the directory's name and the file's together:
                    # `got1BL_pub.bin` beside `got/`. This writes into it.
                    theirs = {("got/" + key[3:] if key.startswith("got")
                               and "/" not in key else key): path
                              for key, path in theirs.items()}
                self.assertEqual(sorted(made), sorted(theirs))
                for key, path in theirs.items():
                    with open(path, "rb") as a, open(made[key], "rb") as b:
                        self.assertEqual(b.read(), a.read(), key)


class ThePatchUpdateOnEachMadeUpConsole(EachActionAsTheOriginalDidIt):
    """`-p` with the original's own choice of file and payload, console by console."""

    def test_the_wire_and_the_files(self):
        where = os.path.join(self.where, "_patches")
        if not os.path.isdir(where) or \
                not os.path.isdir(os.environ.get("XEBUILD_ORIGINAL_DIR", "")):
            self.skipTest("no _patches recordings, or XEBUILD_ORIGINAL_DIR is not set")
        for name in sorted(os.listdir(where)):
            with self.subTest(name):
                one = os.path.join(where, name)
                serve = tempfile.mkdtemp(prefix="xebuild-serve-")
                self.addCleanup(shutil.rmtree, serve, ignore_errors=True)
                shared = os.path.join(self.where, "_serve")
                for part in ("flash.bin", "flash_hdr.bin"):
                    os.symlink(os.path.join(shared, part), os.path.join(serve, part))
                shutil.copy(one + "/info.bin", serve + "/info.bin")
                shutil.copy(one + "/slot.bin", serve + "/patches.bin")
                with open(one + "/argv.json") as handle:
                    argv = json.load(handle)[1:]
                stand_in, _made = self.run_ours(argv, StandIn(serve))
                with open(one + "/original.txt", errors="replace") as handle:
                    self.assertEqual(stand_in.refused is not None,
                                     "ERROR" in handle.read())
                with open(one + "/wire.log") as handle:
                    wanted = [line for line in handle.read().splitlines() if line]
                self.assertEqual(stand_in.lines, wanted)
                for number, body in enumerate(stand_in.payloads, 1):
                    with open(one + "/payloads/payload%02d.bin" % number, "rb") as h:
                        self.assertEqual(body, h.read())

def _put(root, name, body):
    path = os.path.join(root, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(body)


def _compat(work):
    _put(work, "compat/index", b"index body\n")
    _put(work, "compat/alpha.txt", b"a" * 0x123)
    _put(work, "compat/Zeta.txt", b"z" * 0x40)
    _put(work, "compat/empty.bin", b"")
    _put(work, "compat/.dotfile", b"dot")
    _put(work, "compat/.hidden/d.bin", b"d" * 0x10)
    _put(work, "compat/Sub/b.bin", bytes(range(256)) * 3)
    _put(work, "compat/Sub/Deeper/c.bin", b"c" * 0x2001)
    os.makedirs(os.path.join(work, "compat/EmptyDir"))


def _flipped(work, name, at):
    path = os.path.join(work, "su", "$SystemUpdate", name)
    with open(path, "rb") as handle:
        body = bytearray(handle.read())
    body[at if at >= 0 else len(body) + at] ^= 1
    os.remove(path)
    _put(work, "su/$SystemUpdate/" + name, bytes(body))


def _system_update(work, where="su/$SystemUpdate"):
    """The 17559 update laid as links, file by file, so a case can change one."""
    source = os.path.join(os.environ["XEBUILD_CLIENT"], "_sysdata", "supd17559",
                          "$SystemUpdate")
    os.makedirs(os.path.join(work, where))
    for name in os.listdir(source):
        os.symlink(os.path.join(source, name), os.path.join(work, where, name))


def _without_index(work):
    _compat(work)
    os.remove(os.path.join(work, "compat/index"))


def _without(name):
    def lay(work):
        _system_update(work)
        os.remove(os.path.join(work, "su", "$SystemUpdate", name))
    return lay


def _flip(name, at):
    def lay(work):
        _system_update(work)
        _flipped(work, name, at)
    return lay


# The trees each `_sysdata` case was run on, by the name its case.json gives -- the
# recorder's own, laid again. Only the one file a case changes is copied rather than
# linked, so a case costs one container, not the whole update.
TREES = {
    "compat_tree": _compat,
    "compat_noindex": _without_index,
    "su": _system_update,
    "su_flat": lambda work: _system_update(work, "flat"),
    "su_corrupt_container": _flip("FFFE07DF00000001", 0xD000),
    "su_corrupt_file": _flip("nuihud.xex", 0x100),
    "su_missing_file": _without("nuihud.xex"),
    "su_header_hash": _flip("FFFE07DF00000001", 0x32C),
    "flip_0x10": _flip("FFFE07DF00000001", 0x10),
    "flip_0xb6100": _flip("FFFE07DF00000001", 0xB6100),
    "flip_0xb7f00": _flip("FFFE07DF00000001", 0xB7F00),
    "flip_-0x5": _flip("FFFE07DF00000001", -5),
}


class TheHardDiskDataOfEachMadeUpCase(EachActionAsTheOriginalDidIt):
    """`-e` and `-c` on made-up trees and consoles: a system update whole, flat,
    named without its separator, with a file missing, corrupt or flipped in each part
    of a container the check covers and in the one it does not; a directory with
    nested, hidden, empty and unindexed parts; and a console with no hard disk."""

    def test_the_wire_and_the_payloads(self):
        where = os.path.join(self.where, "_sysdata")
        if not os.path.isdir(os.path.join(where, "supd17559")):
            self.skipTest("XEBUILD_CLIENT holds no _sysdata recordings")
        for name in sorted(os.listdir(where)):
            one = os.path.join(where, name)
            if not os.path.isfile(one + "/case.json"):
                continue
            with self.subTest(name):
                with open(one + "/case.json") as handle:
                    case = json.load(handle)
                serve = tempfile.mkdtemp(prefix="xebuild-serve-")
                self.addCleanup(shutil.rmtree, serve, ignore_errors=True)
                shared = os.path.join(self.where, "_serve")
                for part in ("flash.bin", "flash_hdr.bin"):
                    os.symlink(os.path.join(shared, part), os.path.join(serve, part))
                shutil.copy(os.path.join(self.where, case["serve"], "info.bin"), serve)
                stand_in = StandIn(serve)
                stand_in, _made = self.run_ours(case["argv"][1:], stand_in,
                                                TREES[case["tree"]])
                recorded = one
                if name == "avatar-noslash":
                    # The original adds `system.manifest` to `su` with no separator
                    # and finds nothing; this joins them as paths and finds the
                    # update, and sends what `avatar` sent -- a deliberate divergence.
                    recorded = os.path.join(self.where, "avatar")
                with open(recorded + "/wire.log") as handle:
                    wanted = [line for line in handle.read().splitlines() if line]
                self.assertEqual(stand_in.lines, wanted)
                self.assertPayloads(stand_in.payloads, recorded)


class TheReportOfEachMadeUpAnswer(unittest.TestCase):
    """`_info/`: the original's `-i got` over answers changed one field at a time --
    the hack bits, the board, the part's length, each key spoiled, the fuses, the HDD,
    the buttons -- and what it wrote in `got/options.ini`."""

    def test_the_options_ini_byte_for_byte_and_the_report_s_verdicts(self):
        where = os.path.join(os.environ.get("XEBUILD_CLIENT", ""), "_info")
        if not os.path.isdir(where):
            self.skipTest("XEBUILD_CLIENT holds no _info recordings")
        for name in sorted(os.listdir(where)):
            with self.subTest(name):
                one = os.path.join(where, name)
                with open(one + "/info.bin", "rb") as handle:
                    info = ConsoleInfo(handle.read())
                with open(one + "/flash_hdr.bin", "rb") as handle:
                    header = handle.read()
                with open(one + "/options.ini", "rb") as handle:
                    self.assertEqual(options_ini(info, header).encode(), handle.read())
                with open(one + "/original.txt", errors="replace") as handle:
                    said = handle.read()
                board, hack = info.image_type
                self.assertIn("Image Type      : %s (%s)" % (board, hack), said)
                checks = info.key_checks()
                self.assertIn("weight:%#x %s; ecd: %s" % (
                    checks["cpu weight"],
                    "valid" if checks["cpu weight"] == 53 else "error",
                    "valid" if checks["cpu ecd"] else "error"), said)
                self.assertIn("(%s)" % ("good" if checks["1bl"] else "bad"),
                              said.split("1BL key")[1].split("\n")[0])
                for key in ("PIRS", "MASTER"):
                    self.assertRegex(said, r"%s RSA pub\s+: %s" % (
                        key, "good" if checks[key] else "bad"))
                self.assertIn("internal HDD    : %s" % (
                    "present" if info.hdd else "not present"), said)
                xell = reason(header[0x4F], info.fat, True)[1]
                self.assertIn("Xell Reason     : %s" % xell, said)

if __name__ == "__main__":
    unittest.main()
