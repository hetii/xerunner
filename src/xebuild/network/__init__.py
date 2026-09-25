"""Talking to a running console: the update server xeBuild's client and update modes
use.

DashLaunch carries it -- "the built in server dll is also included in dash launch
version 3.08 or greater" -- and it is what lets a console's flash be read and written
over the network with no programmer attached. `updsrv` is the wire and its verbs,
`info` what the console says about itself when asked.
"""

from .info import ConsoleInfo
from .updsrv import Server, ServerError, find
