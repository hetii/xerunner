"""The patch sets a release ships, and what one of them says.

A patch file is a run of records and nothing else. Each is a word saying where, a word
saying how many words follow, then those words; `0xFFFFFFFF` where a record's offset
would be ends the set, and another set may follow it straight away. Read off the release
here and checked by parsing every patch file it ships from end to end, with nothing left
over and nothing running past the end.

    0000 4df4  0000 0001  6000 0000            at 0x4DF4, one word
    0000 4f50  0000 0003  6000 0000 x3         at 0x4F50, three words
    0000 5660  0000 0001  3860 0000            at 0x5660, one word
    ffff ffff                                  and that set ends

Two kinds of file use the same format. `patches_<something>.bin` is the release's own
set for a console and an image type, which `imagetypes.patch_file` names. The small ones
beside it -- `nofcrt.bin`, `nohdd.bin`, `nolan.bin`, `nowifi.bin`, `nohdmiwait.bin` --
are one option each, and they are how the options a configuration carries actually reach
an image.

Nothing here decides what to patch or which set to use. It reads a file and can lay one
over a run of bytes, and that is all.
"""

from __future__ import annotations

import struct


class Record:
    """One patch: where it goes, and the words that go there."""

    def __init__(self, at: int, words: tuple):
        self.at = at
        self.words = tuple(words)

    @property
    def length(self) -> int:
        """How many bytes this writes."""
        return len(self.words) * 4

    @property
    def data(self) -> bytes:
        return struct.pack(">%dI" % len(self.words), *self.words)

    def __repr__(self) -> str:
        return "Record(%#x, %d words)" % (self.at, len(self.words))


class Patches:
    """One patch file: the sets in it, in order."""

    def __init__(self, raw: bytes):
        self.raw = bytes(raw)
        self.sets = []
        records, at = [], 0
        while at + 4 <= len(self.raw):
            where = struct.unpack_from(">I", self.raw, at)[0]
            if where == 0xFFFFFFFF:
                self.sets.append(tuple(records))
                records, at = [], at + 4
                continue
            if at + 8 > len(self.raw):
                raise ValueError("a patch record at %#x has no length" % at)
            count = struct.unpack_from(">I", self.raw, at + 4)[0]
            end = at + 8 + count * 4
            if end > len(self.raw):
                raise ValueError(
                    "a patch record at %#x wants %d words and the file ends"
                    % (at, count)
                )
            words = struct.unpack_from(">%dI" % count, self.raw, at + 8)
            records.append(Record(where, words))
            at = end
        # A file may simply stop rather than saying so. Both spellings are shipped: the
        # per-option files end at the last record, the release's own sets end with the
        # marker, and one release ships a set with nothing after its marker.
        if records:
            self.sets.append(tuple(records))

    @property
    def records(self) -> tuple:
        """Every record in the file, the sets run together."""
        return tuple(one for group in self.sets for one in group)

    def over(self, body: bytes, base: int = 0) -> bytes:
        """`body` with every record written into it, counting from `base`.

        A record that would write past the end is refused rather than trimmed: a patch
        landing somewhere shorter than it expects means the wrong file is being patched,
        and writing the part that fits would hide it.
        """
        out = bytearray(body)
        for one in self.records:
            at = one.at - base
            if at < 0 or at + one.length > len(out):
                raise ValueError(
                    "a patch at %#x does not fit in %#x bytes from %#x"
                    % (one.at, len(out), base)
                )
            out[at : at + one.length] = one.data
        return bytes(out)

    def __repr__(self) -> str:
        return "Patches(%d sets, %d records)" % (len(self.sets), len(self.records))
