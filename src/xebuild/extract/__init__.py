"""Extract mode: what a console's dump holds, said as it is read.

The original's extract mode takes a dump and nothing else -- no CPU key, no 1BL key,
"most errors/warnings will be due to the fact extract mode does not process 1BL and CPU
keys!" -- and reports how it reads it: the flash it came off, the blocks it moves, where
the keyvault, the SMC and the settings are, the settings blobs, every file of the
filesystem and the bootloader chain. It writes no file but its own log. This does the
same with the readers the build already has, so what it says is what a build from that
dump would take.
"""

from .extract import extract_image
