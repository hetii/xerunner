"""The parts of the material, in the order each needs the one before it."""

import os
import json
import shutil
import hashlib

from . import sources

# Raised whenever a recipe changes what it makes, so every part made by an older one
# is made again rather than read back.
RECIPES = 6


class Material:
    """Where each part of the material lies, and how to make one only once."""

    def __init__(self, root: str):
        self.root = root
        os.makedirs(root, exist_ok=True)
        self.jrunner = sources.fetched(sources.JRUNNER,
                                       os.path.join(root, "sources", "jrunner"))
        self.xebuild = os.path.join(self.jrunner, "xeBuild")
        self.system_update = sources.fetched(
            sources.SYSTEM_UPDATE, os.path.join(root, "sources", "system-update"))
        self.releases = self._releases()
        self.console = None
        self.foreign = self.foreign_digest = None

    def path(self, *parts) -> str:
        return os.path.join(self.root, *parts)

    def made(self, name: str, inputs: dict, make) -> str:
        """The directory of part `name`, made by `make(directory)` unless one made
        from the same `inputs` is already there.

        A part is made where it stays, because what it holds links to itself, and its
        stamp -- kept apart in `.made/`, so a part holds nothing but itself -- is
        written last: a run that dies half way leaves a part with no stamp, which the
        next run clears and makes again.
        """
        where = self.path(name)
        stamped = self.path(".made", name)
        stamp = json.dumps({"recipes": RECIPES, **inputs}, sort_keys=True)
        try:
            with open(stamped) as handle:
                if handle.read() == stamp:
                    return where
        except OSError:
            pass
        if os.path.isfile(stamped):
            os.remove(stamped)
        shutil.rmtree(where, ignore_errors=True)
        os.makedirs(where)
        make(where)
        os.makedirs(os.path.dirname(stamped), exist_ok=True)
        with open(stamped, "w") as handle:
            handle.write(stamp)
        return where

    def stamp(self, name: str) -> str:
        """What part `name` was last made from, for the stamps of parts made from it."""
        with open(self.path(".made", name)) as handle:
            return handle.read()

    def _releases(self) -> str:
        """Every release, `common` and `data` beside one another and nothing else.

        The xeBuild folder also holds the base `launch.xex` and `lhelper.xex`, which a
        release taken from there would add to its files; the images the tests hold
        against were built from releases without them beside.
        """
        def make(into):
            for name in sorted(os.listdir(self.xebuild)):
                if os.path.isdir(os.path.join(self.xebuild, name)) and (
                        name[:1].isdigit() or name in ("common", "data")):
                    os.symlink(os.path.join(self.xebuild, name),
                               os.path.join(into, name))
        return self.made("releases", {"jrunner": sources.JRUNNER[1]}, make)


def digest(path: str) -> str:
    """A file's SHA-256, for a stamp."""
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def prepare(root: str) -> dict:
    """Every part, and the environment variables naming them."""
    material = Material(root)
    from . import cells, client, console, extract, grid, ini, provenance, refs, update
    material.console = console.make(material)
    raw, board, material.foreign_digest = console.foreign(material)
    material.foreign = (raw, board)
    env = {
        "XEBUILD_ORIGINAL_DIR": material.xebuild,
        "XEBUILD_UPDATE_RELEASE": material.xebuild,
        "XEBUILD_REFERENCE": os.path.join(material.xebuild, "xeBuild.exe"),
        "XEBUILD_SMC_DIR": os.path.join(material.xebuild, "data"),
        "XEBUILD_RELEASE_DIR": os.path.join(material.releases, "17559"),
        "XEBUILD_SYSTEM_UPDATE": material.system_update,
    }
    env.update(material.console.env)
    env.update(refs.make(material))
    env.update(cells.make(material))
    env.update(extract.make(material, {part: material.stamp(part)
                                       for part in ("console", "refs", "cells")}))
    env.update(ini.make(material))
    env.update(client.make(material))
    env.update(update.make(material))
    env.update(provenance.make(material))
    env.update(grid.make(material))
    return env
