"""Developer software that also carries the glitch.

The two of them are the only types an SMC is not checked for, and they read the
manufacturing glitch's patch file rather than one of their own -- measured: `-t devgl`
reads `patches_g2m<board>.bin`.

`devgl16` is where the naming stops being regular. Its file list is **`_devgl.ini`**,
the same one `devgl` reads, while `devkit16` and `testkit16` each have their own.
Measured by asking the original, for each of the eleven, which file it could not open.
"""

from .imagetype import ImageType


class Devgl(ImageType):
    name = "devgl"
    number = 4
    text = "building devgl image"
    short = "devgl"
    patches = "g2m"


class Devgl16(ImageType):
    name = "devgl16"
    number = 5
    text = "building devgl16 image"
    short = "devgl"
    patches = "g2m"

    @property
    def list_name(self) -> str:
        """`_devgl.ini`, not `_devgl16.ini`. The one irregular name of the eleven."""
        return "devgl"
