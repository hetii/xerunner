"""The settings client mode understands.

Client mode is shaped differently from the others: it carries one action and a few
things that go alongside it. Its own notes say so -- "client mode tends to operate on a
single command basis, stacking commands is not possible with the exception of v,
noenter, ip, s and reboot" -- so `action` is one name, and shutting the console down or
rebooting it are separate settings that travel with whatever else is happening.

The numbers it takes are read as hexadecimal whether or not they are written with `0x`,
which its own legend states: "<b> = hexadecimal block number".
"""

from .network import NetworkConfig


class ClientConfig(NetworkConfig):
    """What to ask a running console to do."""

    def __init__(self, **settings):
        self.action = None
        self.file = None
        self.directory = None
        self.block = None
        self.length = None
        self.offset = None
        self.shutdown = False
        self.reboot = False
        super().__init__(**settings)

    @property
    def action(self) -> str | None:
        """The one thing this run asks of the console.

        Eleven of them, named for what they do rather than for the switch that asks:
        `info` is `-i`, `read` and `write` are `-r` and `-w` over the whole system area,
        `read-blocks`, `write-blocks`, `erase-block` and `binary-patch` are `-rb`,
        `-wb`, `-eb` and `-bp`, `avatar` and `compatibility` are `-e` and `-c`,
        `patches` is `-p`, and `keys` is `-keys`.
        """
        return self["action"]

    @action.setter
    def action(self, given):
        if given is None:
            self["action"] = None
            return
        known = ("info", "read", "write", "avatar", "compatibility", "patches",
                 "read-blocks", "write-blocks", "erase-block", "binary-patch", "keys")
        self["action"] = self.check_oneof("action", given, known)

    @property
    def file(self) -> str | None:
        """The file the action reads from or writes to."""
        return self["file"]

    @file.setter
    def file(self, given):
        self["file"] = None if given is None else self.check_name("file", given)

    @property
    def directory(self) -> str | None:
        """The directory the action reads from or collects into."""
        return self["directory"]

    @directory.setter
    def directory(self, given):
        self["directory"] = (
            None if given is None else self.check_name("directory", given)
        )

    @property
    def block(self) -> int | None:
        """The block a read, write or erase starts at, counted in hexadecimal."""
        return self["block"]

    @block.setter
    def block(self, given):
        self["block"] = (
            None if given is None else self.check_number("block", given, base=16)
        )

    @property
    def length(self) -> int | None:
        """How many blocks to read, counted in hexadecimal."""
        return self["length"]

    @length.setter
    def length(self, given):
        self["length"] = (
            None
            if given is None
            else self.check_number("length", given, base=16)
        )

    @property
    def offset(self) -> int | None:
        """Where a binary patch lands, as a logical offset with no spare counted in."""
        return self["offset"]

    @offset.setter
    def offset(self, given):
        self["offset"] = (
            None if given is None else self.check_number("offset", given, base=16)
        )

    @property
    def shutdown(self) -> bool:
        """Whether the console is shut down once whatever else is done is done."""
        return self["shutdown"]

    @shutdown.setter
    def shutdown(self, wanted):
        self["shutdown"] = self.check_truth("shutdown", wanted)

    @property
    def reboot(self) -> bool:
        """Whether the console is made to hard reboot."""
        return self["reboot"]

    @reboot.setter
    def reboot(self, wanted):
        self["reboot"] = self.check_truth("reboot", wanted)
