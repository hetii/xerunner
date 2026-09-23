"""Tests for the builder.

**Scratch goes on the ramdisk, and that is settled here rather than per file.**
Everything these tests write is thrown away seconds later -- a release copied for one
comparison, an image built and diffed -- and none of it is worth the write wear on a
disk. Setting it once at package import is the point: a per-file `dir=` is the version
that gets forgotten the next time a file is added, and forgetting it once filled a
root filesystem to 99% and killed the run after it with `No space left on device`.

`tempfile.tempdir` is what everything else follows, `mkdtemp` included, so nothing
below has to remember. `XEBUILD_SCRATCH` overrides it; a machine with no `/dev/shm` is
left alone, so the suite still runs there rather than refusing.

The ramdisk is shared with the machine's memory, so a test writes file by file and
clears up after itself. `addClassCleanup` rather than `tearDownClass` for anything
class-scoped: `tearDownClass` does not run when a class dies inside `setUpClass`, and
that is exactly when a big directory gets left behind.
"""

import os
import tempfile

_wanted = os.environ.get("XEBUILD_SCRATCH") or "/dev/shm"
if os.path.isdir(_wanted):
    tempfile.tempdir = _wanted
