"""What a JTAG image runs on: the payload its exploit starts and the core it loads.

xeBuild carries both inside itself and takes a release's own from its `bin/` when there
is one. `loaders` knows what the original does to them on the way into an image.
"""

from .loaders import builtin, core_for, payload_for
