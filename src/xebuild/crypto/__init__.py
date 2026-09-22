"""The ciphers and the one derivation this builder is written on.

Three things, and none of them knows what it is wrapping or unwrapping. `aes` is
AES-128, which the standard library does not carry and which the security files need.
`rc4` is what every bootloader stage is encrypted with. `keys.derive` is how a key is
made from another key, which here is always HMAC-SHA1 cut to sixteen bytes.

SHA-1 itself and HMAC have no module here: `hashlib` and `hmac` already have them, and a
wrapper over a standard function is a place for a mistake to hide.
"""

from . import aes, keys, rc4
