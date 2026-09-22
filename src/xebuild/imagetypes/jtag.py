"""The oldest exploit, and the one that reaches the console over its own wires."""

from .imagetype import ImageType


class Jtag(ImageType):
    """A JTAG image. It does not ask whether the CB is split."""

    name = "jtag"
    number = 2
    text = "building jtag image"
    short = "jtag"
    patches = ""
