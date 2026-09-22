"""The three glitches, which share a number and not a patch file."""

from .imagetype import ImageType


class Glitch(ImageType):
    """The first glitch."""

    name = "glitch"
    number = 3
    text = "building glitch image"
    short = "gg"
    patches = ""


class Glitch2(ImageType):
    """The second, which reads its own patch file under a `g2` prefix."""

    name = "glitch2"
    number = 3
    text = "building glitch2 image"
    short = "g2"
    patches = "g2"


class Glitch2Mfg(ImageType):
    """The manufacturing variant of the second.

    Its own file list and its own patch file, and the word it prints is not its name.
    """

    name = "glitch2m"
    number = 3
    text = "building glitch2 mfg image"
    short = "g2m"
    patches = "g2m"
