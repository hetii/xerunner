"""The image a console left the factory with."""

from .imagetype import ImageType


class Retail(ImageType):
    """No hack at all, and the only type that reads no patch file."""

    name = "retail"
    number = 1
    text = "building retail image"
    short = "retail"
    patches = False
