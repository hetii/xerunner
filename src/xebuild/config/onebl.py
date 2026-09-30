"""The 1BL key, for the modes that take one: build (and update, through it) and ini.

It is the same on every retail console, and the original has it nowhere inside itself:
it is always handed in, and with none the original cannot open a bootloader. Where it
comes from is each mode's own business; what a value has to be is here, once.
"""

import struct

from .base import BaseConfig
from ..crypto.rc4 import rc4
from ..crypto.keys import hmacsha


class OneBlKeyConfig(BaseConfig):
    """The 1BL key."""

    def __init__(self, **settings):
        self.one_bl_key = None
        super().__init__(**settings)

    @property
    def one_bl_key(self) -> bytes | None:
        """The 1BL key, sixteen bytes; None where none was given."""
        return self["one_bl_key"]

    @one_bl_key.setter
    def one_bl_key(self, key):
        """Sixteen bytes that pass both of the original's checks (0x41B740): their sum
        is 0x983, and 0x800 is the sum of the xex key derived from them (0x41B420) --
        sixteen fixed bytes run through RC4 under HMAC-SHA1 keyed with
        "thisisjustajunky" over the key, which from the real key gives the
        20B185A59D28FDC340583FBB0896BF91 the original prints as "xex Key set to". The
        two together let only the one real key through: one with two bytes swapped has
        the right sum and is refused, measured. "1BL key 0x0011... does not appear to
        be correct!"."""
        if key is None:
            self["one_bl_key"] = None
            return
        given = self.check_hex("one_bl_key", key, 16)
        fixed = struct.pack("<4I", 0xBF722795, 0x98F6C047, 0x50F27D5C, 0xCD554D65)
        xex = rc4(hmacsha(b"thisisjustajunky", given)[:16], fixed)
        if sum(given) != 0x983 or sum(xex) != 0x800:
            raise ValueError("1BL key 0x%s does not appear to be correct!"
                             % given.hex().upper())
        self["one_bl_key"] = given
