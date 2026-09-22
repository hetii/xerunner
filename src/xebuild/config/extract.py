"""The settings extract mode understands.

The smallest mode there is: it reads an image and says what is in it. Its usage lists
`-v`, `-noenter` and `-?`, so beyond the image itself it has nothing that is not already
in `BaseConfig`. It processes no keys, which is why its own banner warns that most of
what it says about security will be complaints.
"""

from __future__ import annotations

from .base import BaseConfig


class ExtractConfig(BaseConfig):
    """Which image to read."""

    def __init__(self, **settings):
        self.image = None
        super().__init__(**settings)

    @property
    def image(self) -> str | None:
        """The NAND image to read, named after the switches rather than by one."""
        return self["image"]

    @image.setter
    def image(self, given):
        self["image"] = None if given is None else self.check_name("image", given)
