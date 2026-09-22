"""Test kit software. The same pair as the developer kits, one number apart.

Neither has ever been built here either: no release carries their file lists.
"""

from .imagetype import ImageType


class Testkit(ImageType):
    name = "testkit"
    number = 8
    text = "building testkit image"
    short = "testk"


class Testkit16(ImageType):
    name = "testkit16"
    number = 9
    text = "building testkit16 image"
    short = "testk"
