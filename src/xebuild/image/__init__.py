"""What a flash image is, read or written.

`Image` is one, through the `Flash` that holds it: its header, its settings blobs, its
filesystem table and the bytes of any file in it. `Header` and `Directory` are the two
structures it is made of, and each is useful on its own -- a mode that only wants to say
what is in a dump needs no builder to do it.

`Dump` is an image that came off a console, which is a narrower thing: its blocks are
put back in the order the console reads them, and it answers for the material only that
console has. `Anchor` is how an eMMC image says where its own bookkeeping went, having
no spare bytes to say it in.
"""

from .anchor import Anchor
from .directory import Directory, Entry
from .dump import Dump
from .header import Header
from .image import Image
from .keyvault import Keyvault
from .order import logical
