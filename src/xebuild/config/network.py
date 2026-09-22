"""How a mode that talks to a console reaches it.

One switch, `-ip`, and the same rule in both modes that have it: without it the network
is scanned for the console's own broadcast beacon, and with it that scan is skipped and
the address is used. Build mode writes a file and never reaches a console, so it does
not inherit this.
"""

from __future__ import annotations

from .base import BaseConfig


class NetworkConfig(BaseConfig):
    """Where the console is, when it is not to be searched for."""

    def __init__(self, **settings):
        self.address = None
        super().__init__(**settings)

    @property
    def address(self) -> str | None:
        """The console's address, or None to scan the network for its beacon."""
        return self["address"]

    @address.setter
    def address(self, given):
        if given is None:
            self["address"] = None
            return
        text = str(given).strip()
        parts = text.split(".")
        if len(parts) != 4 or not all(
            one.isdigit() and 0 <= int(one) <= 255 for one in parts
        ):
            raise ValueError(
                "address is an IPv4 address, and this is %r" % (given,)
            )
        self["address"] = text
