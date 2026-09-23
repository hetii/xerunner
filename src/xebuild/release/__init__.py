"""What a build is made from: bootloaders, a dashboard, patch sets, a file list.

`Release` is a directory of it and the way in. `Recipe` is the list a release keeps of
what it is made of, `Listed` one line of that list, `Patches` one of its patch sets, and
`Container` the signed package its firmware files arrive in. Nothing here reads a flash
image and nothing in `image` reads any of this; they meet where a build lays one into
the other.

`Listed` is named here because it crosses the boundary both ways: a recipe hands them
out and `Release.bootloader` takes one back. `Record` and `Held` are only ever read, so
they stay inside.
"""

from .container import Container
from .patches import Patches
from .recipe import Listed, Recipe
from .release import Release
