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
        is 0x983, and 0x800 is the sum of the xex key derived from them -- see
        `xex_key`. The two together catch a mistyped key: one with two bytes swapped
        has the right sum and is refused, measured. "1BL key 0x0011... does not appear
        to be correct!"."""
        if key is None:
            self["one_bl_key"] = None
            return
        given = self.check_hex("one_bl_key", key, 16)
        previous = self.get("one_bl_key")
        self["one_bl_key"] = given
        if sum(given) != 0x983 or sum(self.xex_key) != 0x800:
            self["one_bl_key"] = previous
            raise ValueError("1BL key 0x%s does not appear to be correct!"
                             % given.hex().upper())

    @property
    def xex_key(self) -> bytes | None:
        """The key the original derives from the 1BL key (0x41B420) and keeps at
        0x47A12C: sixteen fixed bytes run through RC4 under HMAC-SHA1 keyed with
        "thisisjustajunky" over the 1BL key. From the real key it is
        20B185A59D28FDC340583FBB0896BF91, "xex Key set to" in the original's log. It is
        the second key crl.bin and dae.bin are tried under ("Trying alternate key",
        0x402020, 0x402210). None where there is no 1BL key."""
        if self.one_bl_key is None:
            return None
        fixed = struct.pack("<4I", 0xBF722795, 0x98F6C047, 0x50F27D5C, 0xCD554D65)
        return rc4(hmacsha(b"thisisjustajunky", self.one_bl_key)[:16], fixed)
