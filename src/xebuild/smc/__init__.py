"""The system management controller, as material rather than as part of an image.

An SMC has two sides and they live in two places, the same way a bootloader does. Where
it lies in a flash and how long it is belongs to the image: `image.Dump.smc` answers
that, and `crypto.smc` opens the bytes. **What** an image is -- which board, which
version, whether anything vouches for it, whether a glitch is already in it -- is this
package.

It is material, not a structure of an image. One SMC serves every console of its board,
the nineteen shipped ones sit beside the tool rather than inside any release, and every
measurement here was taken on files that had never been in an image at all. That is the
difference from `image.Keyvault`, which is the same shape but is one console's identity
and cannot be anyone else's.
"""

from .smc import CLEAN, MOTHERBOARDS, Smc
