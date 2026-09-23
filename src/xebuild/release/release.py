"""A release on disk: the way in to everything a build is made from.

The directory holds a file list per image type, a `bin/` of patch sets, and the signed
package with the dashboard in it. Beside it, not in it, sits `common/`: the bootloaders,
shared by every release, which is why `-f` names one directory and the bootloaders are
found next door.

This is the only thing here that touches the disk. Everything under it takes bytes.
"""

from __future__ import annotations

import logging
import os

from .container import Container
from .patches import Patches
from .recipe import Recipe

logger = logging.getLogger(__name__)


class Release:
    """One release directory, and `common/` beside it."""

    def __init__(self, where: str, common: str = ""):
        if not os.path.isdir(where):
            raise ValueError("%s is not a directory" % where)
        self.where = where
        self.common = common or os.path.join(os.path.dirname(where.rstrip("/\\")),
                                             "common")

    def _read(self, *parts) -> bytes:
        path = os.path.join(*parts)
        with open(path, "rb") as handle:
            return handle.read()

    def _beside(self, where: str, name: str) -> str | None:
        """A file in that directory, found whatever case it is spelled in.

        The original runs where case does not count and the file lists are spelled
        inconsistently: release 17559 asks for `sc_17489.bin` and what is there is
        `SC_17489.bin`. Matching exactly loses 54 bootloaders across the nine releases
        here, all of them to that and nothing else.
        """
        exact = os.path.join(where, name)
        if os.path.isfile(exact):
            return exact
        wanted = name.lower()
        try:
            for found in os.listdir(where):
                if found.lower() == wanted:
                    return os.path.join(where, found)
        except OSError:
            return None
        return None

    def recipe(self, image_type, ext: str = "") -> Recipe:
        """The file list for an image type, which names itself."""
        name = image_type.file_list(ext)
        logger.info("reading %s", os.path.join(self.where, name))
        return Recipe(
            self._read(self.where, name).decode("utf-8", "replace")
        )

    def bootloader(self, listed) -> bytes:
        """One bootloader the recipe names, from wherever that release keeps it.

        `common/` holds the ones every release shares, and a release may keep its own
        beside its file list. **A release's CF and CG are in neither**: they are sealed
        inside the container, and the original says so as it takes them out --
        "decrypting SUPD/xboxupd.bin/CF_17559.bin". So they are looked for there, and
        they come back opened, which is the form the file list's checksum covers.
        """
        for where in (self.common, self.where):
            path = self._beside(where, listed.plain)
            if path:
                return self._read(path)
        if listed.kind in ("CF", "CG"):
            cf, cg = self.container.stages
            return cf if listed.kind == "CF" else cg
        raise ValueError(
            "%s is named by the file list and is in neither %s nor %s"
            % (listed.plain, self.common, self.where)
        )

    def patches(self, image_type, board, ext: str = "") -> Patches | None:
        """The patch set for this image type on this console, where there is one.

        None where the type has none -- a retail image is patched with nothing -- which
        is a real answer and not a missing file.
        """
        name = image_type.patch_file(board.section, ext)
        if name is None:
            return None
        return Patches(self._read(self.where, "bin", name))

    def option(self, name: str) -> Patches:
        """The patch set one option carries, as `bin/<name>.bin`."""
        return Patches(self._read(self.where, "bin", "%s.bin" % name))

    @property
    def container(self) -> Container:
        """The signed package the firmware files and the CF/CG pair are in."""
        for name in sorted(os.listdir(self.where)):
            if name.lower().startswith("su") and "_" in name:
                logger.info("reading %s", os.path.join(self.where, name))
                return Container(self._read(self.where, name))
        raise ValueError("%s holds no system update container" % self.where)

    def __repr__(self) -> str:
        return "Release(%s)" % self.where
