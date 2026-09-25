"""Update mode: read what a running console has, build its image, write it back.

`material.ConsoleMaterial` is what the console handed over -- its bootloaders, keyvault
and SMC as it holds them, its security files, settings blobs and settings, and the few
firmware files a release leaves to it. `update.BuildUpdate` is build mode's `Build`
told where the console's own things come from, and that the image's head is the
console's, laid as it stands. Every request was recorded off the original run against
a stand-in server, and the image this builds is held against the one it built from the
same answers.
"""

from .material import ConsoleMaterial
from .update import BuildUpdate, run_update
