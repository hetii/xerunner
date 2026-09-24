"""`python -m xebuild.cli`: the original's command line."""

import sys

from .command import main

sys.exit(main(sys.argv[1:]))
