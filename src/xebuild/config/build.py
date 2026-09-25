"""The settings build mode understands, and the ini they can come from.

What a property holds is the value the rest of the program wants, not the text that was
typed: `-c jasper256` becomes the console it names, `-p` becomes sixteen bytes, `-8`
becomes pairs of a file and an offset. Each setter checks its own value.

Two of its settings arrive as the thing they name rather than as its name: `-c` becomes
the console from `boards` and `-t` the kind of image from `imagetypes`, so neither list
of names is written down in two places. Both lists came out of the original's binary,
where every accepted name sits beside the message logged when it is given -- its usage
text lists six image types and sixteen console names, and the tables hold eleven and
twenty-one. The thirty-one `-o` settings come from a third table and are declared in
`options.py`, which this class inherits, so a build's configuration is one object.
"""

import logging

from .. import boards, imagetypes
from .options import OptionsConfig
from .release import ReleaseConfig

logger = logging.getLogger(__name__)


class BuildConfig(ReleaseConfig, OptionsConfig):
    """What to build, from what, and for which console.

    `ini` names an `options.ini` to read. What it sets goes in first and what is given
    here goes in second, so the second wins: the file's own first line says the command
    line overrides it, and the usage repeats it -- "command line options take precedence
    over any values set in perbox ini".
    """

    def __init__(self, ini=None, **settings):
        self.image_type = "retail"
        self.console = None
        self.cpu_key = None
        self.one_bl_key = None
        self.per_build = None
        self.sha_file = None
        self.raw_patches = ()
        self.no_random = False
        self.out = None
        if ini is not None:
            logger.info("read %s", ini)
            settings = {**self.settings_in_ini(ini), **settings}
        super().__init__(**settings)

    @staticmethod
    def settings_in_ini(path: str) -> dict:
        """What an `options.ini` sets, as settings this class takes.

        The file is flat -- no sections, `name = value` a line, `;` starts a comment --
        and a blank value means the setting is not made. Four of its thirty-five names
        are settings of their own and are spelled differently there; the rest are
        options and are spelled the same.
        """
        spelled = {"type": "console", "rev": "section_ext",
                   "1blkey": "one_bl_key", "cpukey": "cpu_key"}
        found = {}
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.split(";", 1)[0].strip()
                name, sign, value = line.partition("=")
                name, value = name.strip().lower(), value.strip()
                if not sign or not name or not value:
                    continue
                found[spelled.get(name, name)] = value
        return found

    @property
    def image_type(self):
        """Which kind of image to build, as the kind rather than as its name.

        One of the eleven from `imagetypes`, which is also where the list of names
        lives -- a name is resolved the way `-c` is resolved to a console, so neither
        list is written down twice.
        """
        return self["image_type"]

    @image_type.setter
    def image_type(self, kind):
        if isinstance(kind, imagetypes.ImageType):
            self["image_type"] = kind
            return
        self["image_type"] = imagetypes.for_name(kind)

    @property
    def console(self):
        """The console this image is for, or None until one is named."""
        return self["console"]

    @console.setter
    def console(self, named):
        if named is None:
            self["console"], self["bigffs"], self["console_name"] = None, False, None
            return
        if isinstance(named, boards.Board):
            self["console"], self["bigffs"] = named, False
            self["console_name"] = named.name
            return
        board, bigffs = boards.for_name(named)
        self["console_name"] = str(named).strip().lower()
        if str(named).strip().lower() != board.name:
            logger.info("console %s is a %s", named, board.name)
        if bigffs:
            logger.info("building with the larger filesystem")
        self["console"], self["bigffs"] = board, bigffs

    @property
    def console_name(self) -> str | None:
        """The spelling `-c` was given, which the auto image name carries: a build for
        `-c jasper256` is `17559_gg_jasper256.bin`, not the name of its console."""
        return self["console_name"]

    @property
    def bigffs(self) -> bool:
        """Whether the console was named by the spelling that asks for the larger
        filesystem. It is a property of the request, so the console sets it."""
        return self["bigffs"]

    @property
    def cpu_key(self) -> bytes | None:
        """The console's CPU key, sixteen bytes."""
        return self["cpu_key"]

    @cpu_key.setter
    def cpu_key(self, key):
        self["cpu_key"] = None if key is None else self.check_hex("cpu_key", key, 16)

    @property
    def one_bl_key(self) -> bytes | None:
        """The 1BL key, sixteen bytes, the same on every console."""
        return self["one_bl_key"]

    @one_bl_key.setter
    def one_bl_key(self, key):
        self["one_bl_key"] = (
            None if key is None else self.check_hex("one_bl_key", key, 16)
        )

    @property
    def per_build(self) -> str | None:
        """The directory holding this console's own files -- its dump, its keys."""
        return self["per_build"]

    @per_build.setter
    def per_build(self, where):
        self["per_build"] = (
            None
            if where is None
            else self.check_directory("per_build", where)
        )

    @property
    def sha_file(self):
        """Where to write the image's SHA-1: a name, or True for one made up."""
        return self["sha_file"]

    @sha_file.setter
    def sha_file(self, where):
        if where is None or where is True:
            self["sha_file"] = where
            return
        self["sha_file"] = self.check_name("sha_file", where)

    @property
    def raw_patches(self) -> tuple:
        """Files written straight into the image, as (name, offset) pairs."""
        return self["raw_patches"]

    @raw_patches.setter
    def raw_patches(self, given):
        pairs = []
        if isinstance(given, (tuple, list)):
            for name, at in given:
                pairs.append((str(name).strip(), int(at)))
        else:
            for one in str(given).split(";"):
                one = one.strip()
                if not one:
                    continue
                name, sign, at = one.partition(",")
                if not sign:
                    raise ValueError(
                        "raw_patches is name,offset, and this is %r" % (one,)
                    )
                pairs.append((self.check_name("raw_patches", name),
                              self.check_number("raw_patches", at)))
        for name, at in pairs:
            if at < 0:
                raise ValueError(
                    "raw_patches offset is not negative, and %s has %d" % (name, at)
                )
        self["raw_patches"] = tuple(pairs)

    @property
    def no_random(self) -> bool:
        """`-norandom`: nothing is drawn, and what would be keeps the value the
        original was compiled with -- see `build.security.COMPILED_IN`."""
        return self["no_random"]

    @no_random.setter
    def no_random(self, wanted):
        self["no_random"] = self.check_truth("no_random", wanted)

    @property
    def out(self) -> str | None:
        """The image's name, overriding the one the build would make up."""
        return self["out"]

    @out.setter
    def out(self, given):
        self["out"] = (
            None if given is None else self.check_name("out", given)
        )
