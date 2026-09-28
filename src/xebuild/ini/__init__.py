"""Ini mode: the file list a release keeps, written from a system update container.

Hidden in the original -- its usage names four modes and not this one -- and found in
its code (0x418830). Given a container it checks it whole, opens its CF and CG with the
1BL key from `1blkey.txt`, and writes `[version]`, `[bl]` and `[flashfs]` with a
checksum for each, which is what a release's `_glitch2.ini` and the rest are made of.
"""

from .ini import write_su_ini
