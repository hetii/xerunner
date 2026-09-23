"""The bootloader chain: what a console runs before it runs anything of its own.

`Chain` is one image's, and it is the way in -- it hands back the stages, opens them and
reads what belongs to the console. `Fields` is named here only because `Chain` returns
one; nothing outside constructs it. `stage` and `sealing` are the pieces it is built
from and are reached by their own names when something needs to look inside.
"""

from .chain import Chain
from .console import Fields
