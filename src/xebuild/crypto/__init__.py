"""The ciphers and the one derivation this builder is written on.

Four things, and none of them knows what it is wrapping or unwrapping. `aes` is
AES-128, which the standard library does not carry and which the security files need.
`rc4` is what every bootloader stage is encrypted with. `keys.derive` is how a key is
made from another key, which here is always HMAC-SHA1 cut to sixteen bytes. `smc` is the
one cipher that is nothing like the rest -- a self-feeding byte stream with no key from
outside, under a seed the image carries in the clear -- and the digest the bootloaders
take of a sealed SMC to say which one they were built beside.

SHA-1 itself and HMAC have no module here: `hashlib` and `hmac` already have them, and a
wrapper over a standard function is a place for a mistake to hide.
"""

from . import aes, keys, rc4, smc
