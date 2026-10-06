"""The ciphers this builder is written on, and how each thing an image carries is
sealed with them.

`aes`, `rc4` and `keys` are the primitives, each named for its XeCrypt function:
AES-128, which the standard library does not carry; RC4; and `keys.hmacsha`, how a key
is made from another key, with the two things XeCrypt does to a CPU key itself.
`formats` is every scheme a flash image uses, as `decrypt_*` and `encrypt_*` -- the
keyvault, the five security files, the SMC and the bootloader stages. `smc` is the
digest the bootloaders take of a sealed SMC, and `signature` the check of a stage's
RSA signature under the 1BL public key.

SHA-1 itself and HMAC have no module here: `hashlib` and `hmac` already have them, and a
wrapper over a standard function is a place for a mistake to hide.
"""

from . import aes, formats, keys, rc4, signature, smc
