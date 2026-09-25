"""RC4, which is what every bootloader stage in a flash image is encrypted with.

Twenty lines and no table: the cipher is a permutation of 256 bytes shuffled by the key
and then walked, exclusive-oring the stream over the data. It is its own inverse, so one
function serves both directions and the caller says which by what it passes in.
"""


def rc4(key: bytes, data: bytes) -> bytes:
    """The keystream over `data`. Encrypting and decrypting are the same operation.
    XeCrypt's `XeCryptRc4` -- `XeCryptRc4Key` and `XeCryptRc4Ecb` in one."""
    if not key:
        raise ValueError("rc4 needs a key")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    out = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        out.append(byte ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(out)
