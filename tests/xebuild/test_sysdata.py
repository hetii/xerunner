"""Avatar and compatibility data: the manifest, the container check, and what is sent.

Everything here is made up, so it runs anywhere; `e2e/e2e_client.py` holds the same
against the original's recordings of the real 17559 system update.
"""

import os
import shutil
import struct
import io
import hashlib
import tempfile
import unittest
import contextlib

from xebuild.network import ServerError
from xebuild.release.container import intact
from xebuild.release.manifest import Manifest
from xebuild.cli.command import parse_client
from xebuild.client.sysdata import avatar_items, send_avatars, send_compatibility

KERNEL = 0x20449700


def manifest(rows, version=KERNEL, schema=3, magic=0x584D4E50, revision=0x7873796D):
    """A manifest: `rows` are `(source, kind, body, version, target)`."""
    strings, table = bytearray(), bytearray()
    start = 0x30 + 0x60 * len(rows)

    def name(text):
        at = start + len(strings)
        encoded = text.encode() + b"\x00"
        strings.extend(struct.pack(">H", len(encoded)) + encoded)
        return at

    for source, kind, body, row_version, target in rows:
        row = bytearray(0x60)
        struct.pack_into(">I", row, 0x00, name(source))
        struct.pack_into(">I", row, 0x08, len(body))
        where = start + len(strings)
        strings.extend(struct.pack(">I", row_version))
        struct.pack_into(">I", row, 0x0C, where)
        struct.pack_into(">I", row, 0x18, kind)
        struct.pack_into(">I", row, 0x20, name(target) if target else 0)
        if kind == 3:
            row[0x38:0x4C] = hashlib.sha1(body).digest()
        else:
            row[0x24:0x38] = body[0x32C:0x340].ljust(0x14, b"\x00")
            struct.pack_into(">II", row, 0x4C, 0x8000, 0xFFFE07DF)
        table.extend(row)
    body = bytearray(0x30)
    struct.pack_into(">I", body, 0x00, revision)
    struct.pack_into(">I", body, 0x10, schema)
    struct.pack_into(">I", body, 0x14, version)
    struct.pack_into(">I", body, 0x2C, len(rows))
    body = bytes(body) + bytes(table) + bytes(strings)
    raw = bytearray(0x138) + body
    struct.pack_into(">I", raw, 0, magic)
    struct.pack_into(">I", raw, 0x13C, len(body))
    raw[0x24:0x38] = hashlib.sha1(bytes(raw[0x138:])).digest()
    return bytes(raw)


def package(blocks=3):
    """A package the original's check passes: a header, one table, `blocks` blocks."""
    head = 0xA000
    raw = bytearray(head + 0x1000 + blocks * 0x1000)
    raw[:4] = b"CON "
    struct.pack_into(">I", raw, 0x340, head - 0x800)
    for number in range(blocks):
        at = head + 0x1000 + number * 0x1000
        raw[at:at + 0x1000] = bytes([number + 1]) * 0x1000
        row = head + number * 0x18
        raw[row:row + 0x14] = hashlib.sha1(raw[at:at + 0x1000]).digest()
        raw[row + 0x14] = 0x80
    raw[0x32C:0x340] = hashlib.sha1(bytes(raw[0x344:head])).digest()
    return bytes(raw)


class AManifest(unittest.TestCase):

    def test_a_good_one_is_read_row_by_row(self):
        raw = manifest([("flash", 2, b"", KERNEL, ""),
                        ("a.xex", 3, b"abc", 0x20417F03, "A.xex")])
        read = Manifest(raw)
        self.assertIsNone(read.refusal())
        self.assertEqual(read.version, KERNEL)
        self.assertEqual([one.source for one in read.entries], ["flash", "a.xex"])
        one = read.entries[1]
        self.assertEqual((one.target, one.size, one.version, one.kind),
                         ("A.xex", 3, 0x20417F03, 3))
        self.assertEqual(one.hash, hashlib.sha1(b"abc").digest())

    def test_a_row_naming_no_target_goes_by_its_source(self):
        self.assertEqual(Manifest(manifest([("b", 3, b"x", KERNEL, "")])).entries[0]
                         .target, "b")

    def test_each_header_check_refuses_in_the_original_s_words(self):
        rows = [("a", 3, b"x", KERNEL, "")]
        self.assertEqual(Manifest(manifest(rows, schema=1)).refusal(),
                         "manifest schema != 3!")
        self.assertIn("revision 0x12345678",
                      Manifest(manifest(rows, revision=0x12345678)).refusal())
        self.assertIn("magic 0x00000000", Manifest(manifest(rows, magic=0)).refusal())
        spoiled = bytearray(manifest(rows))
        spoiled[-1] ^= 1
        self.assertEqual(Manifest(bytes(spoiled)).refusal(),
                         "manifest checksum failed!")
        self.assertEqual(Manifest(b"\x00" * 0x100).refusal(),
                         "manifest size error! len 0x100")


class APackageHoldingTogether(unittest.TestCase):

    def test_a_whole_one_passes_and_its_header_hash_is_the_manifest_s(self):
        raw = package()
        self.assertTrue(intact(raw))
        self.assertTrue(intact(raw, raw[0x32C:0x340]))
        self.assertTrue(intact(raw, bytes(0x14)))
        self.assertFalse(intact(raw, b"\x01" * 0x14))

    def test_a_byte_changed_in_the_header_or_a_block_fails(self):
        for at in (0x400, 0xB000, len(package()) - 1):
            spoiled = bytearray(package())
            spoiled[at] ^= 1
            self.assertFalse(intact(bytes(spoiled)), hex(at))

    def test_the_update_container_s_three_fields_are_asked_only_when_named(self):
        """0x40CB2C asks for the content type, the title and `SUPD`; an avatar
        container is sent with none of them asked."""
        raw = bytearray(package())
        struct.pack_into(">I", raw, 0x344, 0x000B0000)
        struct.pack_into(">I", raw, 0x360, 0xFFFE07D1)
        raw[0x32C:0x340] = hashlib.sha1(bytes(raw[0x344:0xA000])).digest()
        self.assertTrue(intact(bytes(raw), content_type=0x000B0000, title=0xFFFE07D1))
        self.assertFalse(intact(bytes(raw), content_type=0x000C0000))
        self.assertFalse(intact(bytes(raw), title=0xFFFE07D2))
        self.assertFalse(intact(bytes(raw), magic=b"SUPD"))
        self.assertTrue(intact(bytes(raw)))

    def test_the_signature_before_0x344_is_not_checked(self):
        spoiled = bytearray(package())
        spoiled[0x10] ^= 1
        self.assertTrue(intact(bytes(spoiled)))


class Stand:
    """Answers every command, and fails the one named."""

    def __init__(self, failing=""):
        self.sent, self.failing = [], failing

    def __getattr__(self, verb):
        def call(*words):
            self.sent.append((verb, *[w for w in words if isinstance(w, str)]))
            if verb == self.failing:
                raise ServerError("refused")
        return call


class SendingTheHardDiskData(unittest.TestCase):

    def setUp(self):
        self.where = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.where)

    def lay(self, rows, version=KERNEL, inside=True):
        folder = os.path.join(self.where, "$SystemUpdate") if inside else self.where
        os.makedirs(folder, exist_ok=True)
        for source, _kind, body, _version, _target in rows:
            if source != "flash":
                with open(os.path.join(folder, source), "wb") as handle:
                    handle.write(body)
        with open(os.path.join(folder, "system.manifest"), "wb") as handle:
            handle.write(manifest(rows, version))

    def test_directories_are_the_kernel_s_then_each_file_s_then_the_content_tree(self):
        self.lay([("flash", 2, b"", KERNEL, ""),
                  ("c", 2, package(), KERNEL, ""),
                  ("x", 3, b"one", 0x2506FD00, ""),
                  ("y", 3, b"two", KERNEL, ""),
                  ("z", 3, b"three", 0x2506FD00, "")])
        _manifest, directories, items = avatar_items(self.where, KERNEL | 2)
        self.assertEqual(directories[:2], ["SSEP:\\20449700", "SSEP:\\2506FD00"])
        self.assertEqual(directories[-1],
                         "SSEP:\\Content\\0000000000000000\\FFFE07DF\\00008000")
        self.assertEqual([path for path, _ in items], [
            "SSEP:\\Content\\0000000000000000\\FFFE07DF\\00008000\\c",
            "SSEP:\\2506FD00\\x", "SSEP:\\20449700\\y", "SSEP:\\2506FD00\\z"])

    def test_the_first_bad_file_ends_it_before_anything_is_formatted(self):
        self.lay([("a", 3, b"one", KERNEL, "")])
        with open(os.path.join(self.where, "$SystemUpdate", "a"), "wb") as handle:
            handle.write(b"onf")
        stand = Stand()
        with self.assertRaisesRegex(ValueError, "hash check FAILED"):
            send_avatars(stand, self.where, KERNEL)
        self.assertEqual(stand.sent, [])

    def test_another_kernel_s_update_is_refused(self):
        self.lay([("a", 3, b"one", KERNEL, "")], version=0x20417F00)
        with self.assertRaisesRegex(ValueError, "not the correct version"):
            avatar_items(self.where, KERNEL)

    def test_the_manifest_is_found_beside_or_under_the_directory(self):
        self.lay([("a", 3, b"one", KERNEL, "")], inside=False)
        self.assertEqual(len(avatar_items(self.where, KERNEL)[2]), 1)
        with self.assertRaisesRegex(ValueError, "could not find manifest"):
            avatar_items(os.path.join(self.where, "nothing"), KERNEL)

    def test_everything_goes_then_the_manifest_then_the_unmount(self):
        self.lay([("a", 3, b"one", KERNEL, "A")])
        stand = Stand()
        send_avatars(stand, self.where, KERNEL)
        self.assertEqual(stand.sent[:2],
                         [("format_extended",), ("mount", "SSEP", "\\SEP")])
        self.assertEqual(stand.sent[-3:], [("send_file", "SSEP:\\20449700\\A"),
                                           ("send_file", "SSEP:\\system.manifest"),
                                           ("unmount", "SSEP")])

    def test_a_failed_format_or_send_still_unmounts(self):
        self.lay([("a", 3, b"one", KERNEL, "")])
        for failing in ("format_extended", "make_directory", "send_file"):
            stand = Stand(failing)
            with self.assertRaises(ValueError):
                send_avatars(stand, self.where, KERNEL)
            self.assertEqual(stand.sent[-1], ("unmount", "SSEP"), failing)

    def test_compatibility_data_is_the_tree_as_it_stands(self):
        for name, body in (("index", b"i"), ("B.bin", b""), ("a.bin", b"a"),
                           (".hidden/x", b"x"), ("Sub/c", b"c")):
            os.makedirs(os.path.dirname(os.path.join(self.where, name)), exist_ok=True)
            with open(os.path.join(self.where, name), "wb") as handle:
                handle.write(body)
        stand = Stand()
        send_compatibility(stand, self.where)
        self.assertEqual(stand.sent, [
            ("format_compatibility",),
            ("mount", "XCOM", "\\Device\\Harddisk0\\SystemPartition"),
            ("send_file", "XCOM:\\a.bin"), ("send_file", "XCOM:\\B.bin"),
            ("send_file", "XCOM:\\index"), ("make_directory", "XCOM:\\Sub"),
            ("send_file", "XCOM:\\Sub\\c"), ("unmount", "XCOM")])

    def test_compatibility_data_needs_an_index(self):
        with self.assertRaisesRegex(ValueError, "unable to find index"):
            send_compatibility(Stand(), self.where)


class TheClientSwitches(unittest.TestCase):

    def test_e_and_c_take_a_directory(self):
        self.assertEqual(parse_client(["-e", "su/"]),
                         {"action": "avatar", "directory": "su/"})
        self.assertEqual(parse_client(["-c", "compat"]),
                         {"action": "compatibility", "directory": "compat"})

    def test_without_one_or_beside_another_action_they_are_refused(self):
        for argv, said in ((["-e"], "expected one argument"),
                           (["-r", "f.bin", "-c", "compat"], "not allowed with")):
            with (self.subTest(argv=argv),
                  contextlib.redirect_stdout(io.StringIO()) as out,
                  self.assertRaises(SystemExit)):
                parse_client(argv)
            self.assertIn(said, out.getvalue())


if __name__ == "__main__":
    unittest.main()
