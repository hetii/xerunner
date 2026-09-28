"""Which release an image is built from, and which variant of it.

Four switches, and every mode that builds an image from a release has all four with the
same meaning and the same rule: `-f` the directory, `-a` a file of extra patches, `-i`
an extension put into the ini and patch file names, `-r` one put into the ini's
bootloader section name. Build mode and update mode both have them; extract and client
have none, so those two do not inherit this.

`-d` is deliberately absent. Both modes spell it and they mean different things by it,
so each keeps a property of its own.
"""

from .base import BaseConfig


class ReleaseConfig(BaseConfig):
    """The release to build from."""

    def __init__(self, **settings):
        self.data = None
        self.append = None
        self.firmware_ext = None
        self.section_ext = None
        super().__init__(**settings)

    @property
    def data(self) -> str | None:
        """The directory holding the release: its ini, its bootloaders, its patches."""
        return self["data"]

    @data.setter
    def data(self, where):
        self["data"] = (
            None if where is None else self.check_directory("data", where)
        )

    @property
    def append(self) -> tuple:
        """Patch files, by name, whose entries are added to the image's patch list.

        `-a` may be given more than once and each one counts: measured on the original,
        `-a nofcrt -a hvFixKeys`. So this is a tuple, in the order given, and a single
        name is a tuple of one.
        """
        return self["append"]

    @append.setter
    def append(self, given):
        if given is None:
            self["append"] = ()
            return
        names = [given] if isinstance(given, str) else list(given)
        self["append"] = tuple(self.check_name("append", one) for one in names)

    @property
    def firmware_ext(self) -> str | None:
        """An extension put into the ini and patch file names: `_glitch_<ext>.ini`."""
        return self["firmware_ext"]

    @firmware_ext.setter
    def firmware_ext(self, ext):
        self["firmware_ext"] = (
            None if ext is None else self.check_word("firmware_ext", ext)
        )

    @property
    def section_ext(self) -> str | None:
        """An extension put into the ini's bootloader section: `[jasperbl_<ext>]`."""
        return self["section_ext"]

    @section_ext.setter
    def section_ext(self, ext):
        self["section_ext"] = (
            None if ext is None else self.check_word("section_ext", ext)
        )
