"""A release on disk: the way in to everything a build is made from.

The directory holds a file list per image type, a `bin/` of patch sets, and the signed
package with the dashboard in it. Beside it, not in it, sits `common/`: the bootloaders,
shared by every release, which is why `-f` names one directory and the bootloaders are
found next door.

This is the only thing here that touches the disk. Everything under it takes bytes.
"""

import os
import logging
import binascii

from ..files import beside
from .patches import Patches
from .recipe import Recipe, canonical
from .container import Container, intact

logger = logging.getLogger(__name__)


class Release:
    """One release directory, and `common/` beside it."""

    def __init__(self, where: str, common: str = ""):
        if not os.path.isdir(where):
            raise ValueError("%s is not a directory" % where)
        self.where = where
        self._container = False
        self._files = {}
        self.common = common or os.path.join(os.path.dirname(where.rstrip("/\\")),
                                             "common")

    def _read(self, *parts) -> bytes:
        """One file's bytes, read once and kept, as `Material.bytes_in` keeps what it
        reads: a build asks for the same bootloader and patch file more than once.

        Kept for as long as this object lives; a file changed on disk after it was read
        is not seen again by this object.
        """
        path = os.path.join(*parts)
        if path not in self._files:
            logger.debug("reading %s (%#x bytes)", path, os.path.getsize(path))
            with open(path, "rb") as handle:
                self._files[path] = handle.read()
        return self._files[path]

    def recipe(self, image_type, ext: str = "") -> Recipe:
        """The file list for an image type, which names itself.

        One with no `[version]` label is refused, as the original refuses it: "could
        not find label [version] in file list ini" (0x40952E), measured.
        """
        name = image_type.file_list(ext)
        found = Recipe(self._read(self.where, name).decode("utf-8", "replace"))
        if "version" not in found.sections:
            raise ValueError("could not find label [version] in file list ini")
        return found

    def bootloader(self, listed) -> bytes:
        """One bootloader the recipe names, from wherever that release keeps it.

        `common/` holds the ones every release shares, and a release may keep its own
        beside its file list. **A release's CF and CG are in neither**: they are sealed
        inside the container, and the original says so as it takes them out --
        "decrypting SUPD/xboxupd.bin/CF_17559.bin". So they are looked for there, and
        they come back opened, which is the form the file list's checksum covers.

        Each is checked as the original checks it on loading (0x429B30), and refused
        where it fails -- "could not read cba_9188.bin", then "critical bootloader files
        are missing" -- see `_checked`.
        """
        for where in (self.common, self.where):
            path = beside(where, listed.plain)
            if path:
                return self._checked(listed, self._read(path))
        if listed.kind in ("CF", "CG") and self.container is not None:
            cf, cg = self.container.stages
            return self._checked(listed, cf if listed.kind == "CF" else cg)
        raise ValueError(
            "%s is named by the file list and is in neither %s nor %s"
            % (listed.plain, self.common, self.where)
        )

    @staticmethod
    def _checked(listed, body: bytes) -> bytes:
        """A bootloader as it came, once it passes the original's three checks.

        Its stated length no more than the file holds; its magic a C or an S and then
        the letter of its kind; and its checksum the list's, taken over the form the
        list states it for -- `Listed.vouches_for`. A list's `ffffffff` spares the
        checksum only an SC, SD or SE; for every other kind it is a checksum like any,
        and so is zero. Measured on the original: a byte changed in CB_A, CB_B, CD, CE
        and a JTAG image's two CBs, the checksum of CF and CG changed in the list, each
        of those and CB_A with `ffffffff`, CB_A with `00000000`, CB_A's stated length
        past its end, CD's magic spoilt and CD's made CE's -- all refused.

        The kind is the one the file's name gives. The original checks the magic
        against the slot the list puts the file in, which is the same kind in every
        list a release ships.
        """
        stated = int.from_bytes(body[0x0C:0x10], "big")
        if stated > len(body):
            raise ValueError("BL size (%#x) is bigger than the file (%#x) read in! "
                             "could not read %s" % (stated, len(body), listed.plain))
        if listed.kind and (body[0] & 0x43 != 0x43
                            or body[1:2] != listed.kind[1].encode()):
            raise ValueError("BL magic check %s for %s failed! could not read %s"
                             % (body[:2].decode("latin-1"), listed.kind, listed.plain))
        spared = listed.kind in ("SC", "SD", "SE") and listed.crc == 0xFFFFFFFF
        if not spared and not listed.vouches_for(body):
            raise ValueError("BL crc check failed! calculated: %08x expected: %08x; "
                             "could not read %s"
                             % (binascii.crc32(canonical(body, listed.kind))
                                & 0xFFFFFFFF, listed.crc or 0, listed.plain))
        return body

    def patches(self, image_type, board, ext: str = "") -> Patches | None:
        """The patch set for this image type on this console, where there is one.

        None where the type has none -- a retail image is patched with nothing -- which
        is a real answer and not a missing file.

        `board` is a console, or the name of one as a string. The string is for the one
        case where the file is not named after the console being built for: a `glitch`
        image on a fat console takes its patch slot from `patches_fat.bin` while its
        bootloaders come from `patches_<board>.bin`, which the original's own log shows
        for zephyr, falcon, jaspersb and jasper.
        """
        name = image_type.patch_file(
            board if isinstance(board, str) else board.section, ext
        )
        if name is None:
            return None
        return Patches(self._read(self.where, "bin", name))

    def listed_file(self, name: str) -> bytes | None:
        """A `[flashfs]` file relative to the release, as the list spells it, or None.

        The first place the original looks for any of them (0x427730, called first
        from 0x428040): `17559\\xenonclatin.xtt` in the release's own directory,
        `..\\launch.xex` in the base directory, 1838's `1838-fs\\xam.xex` in a directory
        of its own. Which source a build then takes is `Build`'s -- see
        `Build._firmware_file`.
        """
        found = self._listed_path(name)
        return self._read(found) if found else None

    def listed_meta(self, name: str) -> bytes | None:
        """The `.meta` beside a `[flashfs]` file relative to the release, or None --
        its own stamp, which the original takes over the build's time (0x4282DC)."""
        found = self._listed_path(name + ".meta")
        return self._read(found) if found else None

    def _listed_path(self, name: str) -> str | None:
        path = os.path.normpath(os.path.join(self.where, name.replace("\\", "/")))
        return beside(os.path.dirname(path), os.path.basename(path))

    def container_file(self, name: str) -> bytes | None:
        """A firmware file out of the update container, by its plain name, or None."""
        if self.container is None or self.container.firmware_name(name) is None:
            return None
        return self.container.firmware(name)

    def common_file(self, name: str) -> bytes | None:
        """A firmware file in `common/`, by its plain name, or None -- where every
        release since 1888 keeps `xenonclatin.xtt`, `xenonjklatin.xtt` and
        `ximedic.xex` (0x427CC0: "reading ./common/xenonclatin.xtt")."""
        path = beside(self.common, name)
        return self._read(path) if path else None

    def common_meta(self, name: str) -> bytes | None:
        """The `.meta` beside a firmware file in `common/`, or None (0x427E30)."""
        path = beside(self.common, name + ".meta")
        return self._read(path) if path else None

    def raw_file(self, name: str) -> bytes:
        """A file `-8` names, which the original looks for relative to the release."""
        path = name if os.path.isabs(name) else beside(self.where, name)
        if path is None or not os.path.isfile(path):
            raise ValueError("could not load [rawpatch] file '%s'" % name)
        return self._read(path)

    def in_bin(self, name: str) -> bytes | None:
        """A file in the release's `bin/`, or None when it has none.

        Where the original looks first for the loaders a JTAG image carries --
        `payload.bin` and `freeboot.bin` -- before it falls back to the copies built
        into itself: "could not read 17559/bin/payload.bin, using built in payload".
        """
        path = beside(os.path.join(self.where, "bin"), name)
        return self._read(path) if path else None

    def in_base(self, name: str) -> bytes | None:
        """A file in the base directory -- the one the release's directory is in -- or
        None. Where the original looks last for a loader: "xell not found in firmware
        /bin folder, checking base path"."""
        path = beside(os.path.dirname(os.path.normpath(self.where)), name)
        return self._read(path) if path else None

    def option(self, name: str) -> Patches:
        """The patch set one option carries, as `bin/<name>.bin`, in any case --
        `addon = NOFCRT` reads `nofcrt.bin`, measured."""
        where = os.path.join(self.where, "bin")
        return Patches(self._read(beside(where, "%s.bin" % name)
                                  or os.path.join(where, "%s.bin" % name)))

    @property
    def container(self) -> Container | None:
        """The signed package the firmware files and the CF/CG pair are in, or None.

        Read once. An older release ships none and keeps everything as loose files --
        6717 has its `cf_6717.bin`, its `xam.xex` and the rest beside its file list --
        and the original says so and carries on: "system update container not found
        at 6717/su20076000_00000000 ... skipping load".
        """
        if self._container is False:
            self._container = None
            for name in sorted(os.listdir(self.where)):
                if name.lower().startswith("su") and "_" in name:
                    raw = self._read(self.where, name)
                    # Checked whole before anything is taken from it, and not loaded
                    # at all where any of it fails (0x40CB2C): measured with one byte
                    # changed in a file's data and with one in the padding behind
                    # xboxupd.bin that no file's checksum covers -- both "checks
                    # failed! Container corrupt!", and the build then stops for want
                    # of its CF.
                    if intact(raw, content_type=0x000B0000, title=0xFFFE07D1,
                              magic=b"SUPD"):
                        self._container = Container(raw)
                    else:
                        logger.warning("checks failed! Container corrupt!")
                    break
            else:
                logger.debug("system update container not found in %s, skipping load",
                             self.where)
        return self._container

    def __repr__(self) -> str:
        return "Release(%s)" % self.where
