"""Client mode: one thing asked of a running console over its update server.

"client mode tends to operate on a single command basis, stacking commands is not
possible with the exception of v, noenter, ip, s and reboot" -- so `config.ClientConfig`
carries one `action`, and a shutdown or a reboot rides along with it. Every action was
run on the original against a stand-in server that records the wire, and this sends
the same commands in the same order and writes the same files.
"""

from .client import run_client
