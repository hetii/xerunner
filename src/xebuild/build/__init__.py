"""Laying an image: the material a console supplies, and the order it goes together in.

`Material` is the directory `-d` names, which is where a console's own things are found,
and the only thing here that touches a disk. `Filesystem` decides which block each file
gets; recording that decision is `image.Directory`'s, beside the code that reads a
table.
"""

from .filesystem import Filesystem
from .material import Material
