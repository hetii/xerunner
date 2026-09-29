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
        self.one_bl_key = None
        super().__init__(**settings)
        # Its one source: 1blkey.txt where the tool runs.
        found = self.key_in_file(".", "1blkey.txt")
        if found is not None:
            self.one_bl_key = found[1]

    @property
    def one_bl_key(self) -> bytes | None:
        """The 1BL key, sixteen bytes; its sum is ini mode's own question."""
        return self["one_bl_key"]

    @one_bl_key.setter
    def one_bl_key(self, key):
        self["one_bl_key"] = (None if key is None
                              else self.check_hex("one_bl_key", key, 16))

    @property
    def system_update(self) -> str | None:
        """The container, a directory holding it, or one holding `$SystemUpdate`."""
        return self["system_update"]

    @system_update.setter
    def system_update(self, given):
        self["system_update"] = (None if given is None
                                 else self.check_name("system_update", given))
