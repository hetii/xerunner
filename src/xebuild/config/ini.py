"""The settings ini mode understands.

A mode the original's usage does not list: `xeBuild ini <path>` writes the file list a
release keeps -- `[version]`, `[bl]`, `[flashfs]` -- for a system update container. It
takes the one path and nothing else, not even `-noenter`: a second word, whatever it
is, gets its usage (0x4189FC), measured.
"""

from .base import BaseConfig


class IniConfig(BaseConfig):
    """Where the system update is."""

    def __init__(self, **settings):
        self.system_update = None
        super().__init__(**settings)

    @property
    def system_update(self) -> str | None:
        """The container, a directory holding it, or one holding `$SystemUpdate`."""
        return self["system_update"]

    @system_update.setter
    def system_update(self, given):
        self["system_update"] = (None if given is None
                                 else self.check_name("system_update", given))
