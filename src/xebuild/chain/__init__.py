"""The bootloader chain: what a console runs before it runs anything of its own.

`Chain` is one image's, and it is the way in -- it hands back the stages, opens them and
reads what belongs to the console. `Fields` is named here only because `Chain` returns
one; nothing outside constructs it. `stage` and `sealing` are the pieces it is built
from and are reached by their own names when something needs to look inside.

The write side sits beside them: `update` makes a release's CF and CG a console's, and
`fuses` is the copy of a console's fuses a loader hands over in their place.
"""

from .chain import Chain
from .console import Fields
