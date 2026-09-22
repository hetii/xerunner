"""The settings each mode of the tool runs on.

All of them dictionaries, and each class holds exactly what some mode needs.
`BaseConfig` has the two settings every mode shares. `ReleaseConfig` adds the four a
mode reading a release has, `NetworkConfig` the one a mode reaching a console has, and
`OptionsConfig` declares the thirty-one `-o` settings. A mode's class inherits the ones
it needs and nothing else, so a configuration that exists carries no other mode's
switches. Those four are what this package offers; the classes they are built from are
reached by their own modules, because nothing outside constructs one.

Every value goes in through an attribute that checks it, so a configuration that exists
is already valid and the code reading one never checks anything twice.
"""

from .build import BuildConfig
from .client import ClientConfig
from .extract import ExtractConfig
from .update import UpdateConfig
