"""The settings update mode understands.

Update mode talks to a console over the network instead of writing a file: it reads what
the console has, builds an image from a release and writes it back. So it shares four
switches with build mode -- the release directory and the three names that pick a
variant of it, which is what `ReleaseConfig` holds. Because it reaches a console it also
has `-ip`, which `NetworkConfig` holds and client mode has too. `-d` it shares with
build mode only in spelling: there it is where a console's own files are read from, here
it is where the console's dump is written before anything is flashed. """

from __future__ import annotations

import os

from .network import NetworkConfig
from .release import ReleaseConfig


class UpdateConfig(ReleaseConfig, NetworkConfig):
    """What to update a console to, and how much of it to actually do."""

    def __init__(self, **settings):
        self.dump_to = None
        self.no_write = False
        self.no_avatar = False
        self.clean = False
        self.no_reboot = False
        super().__init__(**settings)

    @property
    def dump_to(self) -> str | None:
        """Where the console's dump and its other data are kept before flashing.

        Without it nothing about the run is kept, which is what makes it worth saying.
        This directory is written rather than read, so it does not have to exist yet.
        """
        return self["dump_to"]

    @dump_to.setter
    def dump_to(self, where):
        if where is None:
            self["dump_to"] = None
            return
        path = self.check_name("dump_to", where).rstrip("/\\")
        if os.path.exists(path) and not os.path.isdir(path):
            raise ValueError("dump_to %r is a file" % (path,))
        self["dump_to"] = path


    @property
    def no_write(self) -> bool:
        """Whether the console's flash and disk are left untouched."""
        return self["no_write"]

    @no_write.setter
    def no_write(self, wanted):
        self["no_write"] = self.check_truth("no_write", wanted)

    @property
    def no_avatar(self) -> bool:
        """Whether avatar data is skipped even when there is a disk to take it."""
        return self["no_avatar"]

    @no_avatar.setter
    def no_avatar(self, wanted):
        self["no_avatar"] = self.check_truth("no_avatar", wanted)

    @property
    def clean(self) -> bool:
        """Whether secdata, extended and statistics are left on the console."""
        return self["clean"]

    @clean.setter
    def clean(self, wanted):
        self["clean"] = self.check_truth("clean", wanted)

    @property
    def no_reboot(self) -> bool:
        """Whether the console is left running after the writes are done."""
        return self["no_reboot"]

    @no_reboot.setter
    def no_reboot(self, wanted):
        self["no_reboot"] = self.check_truth("no_reboot", wanted)
