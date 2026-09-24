"""The command line, spelled as xeBuild spells it, for build mode.

`command.parse` turns the original's own switches into the settings a
`config.BuildConfig` takes, and `command.main` builds the image with them. Nothing here
decides anything about an image: a switch is read, its value handed to the property of
the same meaning, and every check is the property's.
"""

from .command import main, parse
