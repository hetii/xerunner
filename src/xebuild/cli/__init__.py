"""The command line, spelled as xeBuild spells it, for all four modes.

`command.parse_build` turns build mode's switches into the settings a
`config.BuildConfig` takes; extract, client, update and ini mode each have their own
switches and their own reader beside it. `command.main` picks the mode by the first
word and runs it. Nothing here decides anything about an image or a console: a switch
is read, its value handed to the property of the same meaning, and every check is the
property's.
"""

from .command import main, parse_build
