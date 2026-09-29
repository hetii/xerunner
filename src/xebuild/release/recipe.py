"""What a release says it is made of: its file list, which the original calls an ini.

A release is a directory of files nobody here wrote -- bootloaders, a dashboard, patch
sets -- and this is the index to it. One file list per image type, named by the type
(`_glitch2.ini`), holding a section per console plus three the console does not come
into.

Every line is a name and the CRC32 the release states for it, and the checksum may be
missing, which means the release vouches for nothing:

    cba_9188.bin,5a76752d
    ..\\launch.xex,

A `;` ends a line early, as in any ini. It matters for one line in two of the nine
releases here -- `cbb_9188.bin,febb1074;` -- and the original reads straight past it,
reporting `crc: 0xfebb1074`.

**A bootloader section is named after the console, not after the image.** `[trinitybl]`
for a Trinity, from the board's own `section` and nothing else -- confirmed on six
boards against the original's "ini: label [trinitybl] found".

**`-r` lengthens that name rather than replacing it.** `-c corona -r WB` reads
`[coronabl_WB]`, and a variant section is the same list with one bootloader swapped:
`[coronabl_WB]` differs from `[coronabl]` in its CB_B alone, as `[xenonbl_ELPIS]`
differs from `[xenonbl]`.

**A Winchester cannot be built from any release here.** The original looks for
`[winchesterbl]`, no release has one, and it stops: "could not find label [winchesterbl]
in file list ini". Nor does `-r WB` help -- that reads `[winchesterbl_WB]`, which no
release has either. The `WB` sections belong to Corona. Measured across all nine
releases here, and this refuses the same way rather than quietly building something
else.

**A section is not always six files.** A glitch or retail section names six, one per
stage. A JTAG section names nine: an older set the exploit boots through, then the
release's own behind it -- which is the same two CF slots an image turns out to carry.

**Whether the chain is split in two is read from the section**, not decided elsewhere: a
split chain names `cba_` and `cbb_`, a JTAG one names `cb_`. The original prints "ini
dictates dual CB for this model" from exactly this.

**A slot may be empty, and it says `none`.** A glitch section names six slots like any
other and puts `none,00000000` in the second, because that chain has a single CB and
nothing goes where a CB_B would. It appears 194 times across the releases here, so the
list is positional and the holes are part of the shape rather than something to skip.
"""

import struct
import binascii

# What a checksum covers, from the readme every release ships beside its file lists:
# the stage is cut to the size it states at 0x0C, and the fields belonging to this copy
# rather than to the code are filled with zero.
#
#     "note, with bls the following is true (before calculating CRC for an ini):
#      - the file is truncated to the u32 size found at offset 0xC
#      - CB/CB_A/CB_B 0x0 fill: @0x10 for 0x30 bytes
#      - CD 0x0 fill: @0x10 for 0x10
#      - CE 0x0 fill: @0x10 for 0x10
#      - CF 0x0 fill: @0x20 for 0x210
#      - CG 0x0 fill: @0x10 for 0x10"
#
# What is blanked is the nonce, and for a CB the pairing beside it -- which is why two
# copies of one bootloader, sealed for two consoles, still answer to one checksum.
BLANKED = {
    "CB": (0x10, 0x30),
    "CBA": (0x10, 0x30),
    "CBB": (0x10, 0x30),
    "CD": (0x10, 0x10),
    "CE": (0x10, 0x10),
    "CF": (0x20, 0x210),
    "CG": (0x10, 0x10),
    # The readme stops at CG, and four more kinds are named by the recipes: SB, SC, SD
    # and SE. Swept over every bootloader any of the nine releases names, against every
    # checksum any of them states: SC, SD and SE all want the same 0x10 for 0x10, and an
    # SB answers as it stands and wants no blanking at all.
    "SC": (0x10, 0x10),
    "SD": (0x10, 0x10),
    "SE": (0x10, 0x10),
}


def canonical(body: bytes, kind: str = "") -> bytes:
    """A bootloader in the form a checksum is taken over.

    Anything that is not a bootloader comes back cut to its stated size and no more;
    a name that says nothing leaves even that alone.
    """
    body = bytes(body)
    if len(body) >= 0x10:
        stated = struct.unpack_from(">I", body, 0x0C)[0]
        if 0 < stated <= len(body):
            body = body[:stated]
    at, span = BLANKED.get(kind.upper(), (0, 0))
    if span and len(body) >= at + span:
        body = body[:at] + bytes(span) + body[at + span :]
    return body


class Listed:
    """One line of a file list: a name, and the checksum the release states for it."""

    def __init__(self, name: str, crc: str):
        self.name = name.strip()
        crc = crc.strip()
        if not crc:
            self.crc = None
            return
        try:
            self.crc = int(crc, 16)
        except ValueError:
            raise ValueError(
                "%s states %r where a checksum should be" % (self.name, crc)
            ) from None

    @property
    def absent(self) -> bool:
        """Whether this slot holds nothing: the list spells that `none`."""
        return self.plain.lower() == "none"

    @property
    def kind(self) -> str:
        """Which bootloader this name is, or nothing when it is not one.

        `cba_9188.bin` is a CB_A and `cd_9452.bin` a CD -- the stem before the first
        underscore, which is how a release names every one of them. The development
        chains 1838 and 17489 name theirs `SB_14352.bin`, `SD_12611.bin`, `SE_1838.bin`,
        and those are kinds too; what a stage *is* is its magic, which the release's
        own patches may rewrite -- SB comes out a CB.
        """
        stem = self.plain.split("_")[0].split(".")[0].upper()
        return stem if stem in BLANKED or stem in ("SB", "SC", "SD", "SE") else ""

    def vouches_for(self, body: bytes) -> bool:
        """Whether these bytes are what the release says this name holds.

        False when the release states no checksum, which is not the same as a mismatch
        and is why three of the firmware files can never be checked: the release does
        not vouch for them.
        """
        if self.crc is None or self.absent:
            return False
        if binascii.crc32(bytes(body)) & 0xFFFFFFFF == self.crc:
            return True
        found = binascii.crc32(canonical(body, self.kind)) & 0xFFFFFFFF
        return found == self.crc

    @property
    def outside(self) -> bool:
        """Whether this one lives above the release's own directory.

        Three of the firmware files do -- `..\\launch.xex` and the two beside it -- and
        they are the ones the release states no checksum for.
        """
        return self.name.startswith("..\\") or self.name.startswith("../")

    @property
    def plain(self) -> str:
        """The name without whatever says where it lives."""
        return self.name.replace("\\", "/").rsplit("/", 1)[-1]

    def __repr__(self) -> str:
        return "Listed(%s%s)" % (
            self.plain, "" if self.crc is None else ", %#010x" % self.crc
        )


class Recipe:
    """One file list, parsed. Takes the text; opening the file is the caller's."""

    def __init__(self, text: str):
        self.sections = {}
        name = ""
        for line in str(text).splitlines():
            line = line.strip()
            if not line:
                continue
            line = line.split(";", 1)[0].strip()
            if not line:
                continue
            if line.startswith("[") and line.endswith("]"):
                name = line[1:-1].strip().lower()
                self.sections.setdefault(name, [])
                continue
            if name:
                self.sections[name].append(line)

    def _listed(self, section: str) -> tuple:
        out = []
        for line in self.sections.get(section, ()):
            name, _, crc = line.partition(",")
            if name.strip():
                out.append(Listed(name, crc))
        return tuple(out)

    @property
    def version(self) -> str:
        """The release the list belongs to, which is a word rather than a number.

        Every release on this bench spells it as digits, but nothing says it must, and
        it is used as part of a filename rather than counted with.
        """
        lines = self.sections.get("version", ())
        return lines[0].strip() if lines else ""

    def section_for(self, board, ext: str = "") -> str:
        """The section name a console's chain is read from."""
        return "%sbl%s" % (board.section, "_" + ext if ext else "")

    def stages(self, board, ext: str = "") -> tuple:
        """The bootloaders this release names for that console, in order."""
        section = self.section_for(board, ext)
        found = self._listed(section.lower())
        if not found:
            raise ValueError(
                "could not find label [%s] in file list ini" % section
            )
        return found

    def dual_cb(self, board, ext: str = "") -> bool:
        """Whether this console's chain is a split CB, as the section names it."""
        return self.stages(board, ext)[0].plain.lower().startswith("cba")

    @property
    def firmware(self) -> tuple:
        """The files that go into the image's filesystem.

        A name of more than 21 characters stops the build as the list is read, whether
        or not the file is there: "file in [flashfs] has greater than 21 chars in it's
        name!" (0x40A965), measured with 22 and with 34. The name is the file's own,
        without the directory before it: 1838's devkit list names `1838-fs\
        deviceselector.xex`, 26 in all, and builds.
        """
        found = self._listed("flashfs")
        if any(len(one.plain) > 21 for one in found):
            raise ValueError("file in [flashfs] has greater than 21 chars in it's "
                             "name!")
        return found

    @property
    def security(self) -> tuple:
        """The security files, which the list names and states no checksum for.

        They come off the console rather than out of the release, so there would be
        nothing for a release to vouch for.
        """
        return self._listed("security")

    @property
    def raw_patches(self) -> tuple:
        """Patches applied to the image itself, where a release names any, as (name,
        offset) pairs.

        None of the nine releases on this bench does; what is read here was measured
        on made-up lists. The offset is decimal unless it starts `0x`, as `-8`'s is:
        `rp.bin,100000` goes to 0x186A0. The original takes `f0000` as 0 and writes
        over the flash header; that is refused here, as `-8` refuses it.
        """
        out = []
        for line in self.sections.get("rawpatch", ()):
            name, sign, at = line.partition(",")
            at = at.strip()
            if not sign or not at:
                raise ValueError("an entry in [rawpatch] is missing offset info!")
            try:
                out.append((name.strip(), int(at, 16) if at[:2].lower() == "0x"
                            else int(at, 10)))
            except ValueError:
                raise ValueError("[rawpatch] %s states %r where an offset should be"
                                 % (name.strip(), at)) from None
        return tuple(out)

    def __repr__(self) -> str:
        return "Recipe(%s, %d sections)" % (self.version or "no version",
                                            len(self.sections))
