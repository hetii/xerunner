"""Developer kit software, and the pair that shows what the `16` means.

`devkit` takes a 64 MB image whose filesystem counts from zero whatever board it is
built for; `devkit16` is that not happening, and the board's own shape is used instead.

Neither has ever been built here: no release carries a `_devkit.ini` or a
`_devkit16.ini`, so the original stops at "could not open" before it reaches a layout.
What is known is what it reaches for, which is what these say.
"""

from .imagetype import ImageType


class Devkit(ImageType):
    name = "devkit"
    number = 6
    text = "building devkit image"
    short = "devk"


class Devkit16(ImageType):
    """The same software on the board's own flash shape, and its own file list."""

    name = "devkit16"
    number = 7
    text = "building devkit16 image"
    short = "devk"
