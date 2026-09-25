"""AES-128, because the images this builds are encrypted with it and Python has none.

The standard library carries hashes and HMAC and no block cipher at all, and this
package has no dependencies, so the cipher is here. Only 128-bit keys: that is the one
width the console uses, and a width nothing asks for is a width nothing checks.

Written from FIPS-197 and checked against its own known answers, and against the CBC
vectors in NIST SP 800-38A. The substitution table is computed from the field rather
than typed in, because a 256-byte table copied by hand is 256 chances to be wrong and
none of them would be visible: the tests below only prove the mistake is consistent.

Table driven where it pays. The field multiplications every round needs are worked out
once at import, and a key schedule is expanded once per call rather than once per block,
which is the difference between a build that finishes and one that does not -- the
largest security file here is over eighteen hundred blocks.
"""

BLOCK = 16
KEY_LENGTH = 16
ROUNDS = 10


def _times(a: int, b: int) -> int:
    """Multiply two bytes in the field the cipher is defined over, GF(2^8)."""
    out = 0
    for _ in range(8):
        if b & 1:
            out ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B  # the polynomial x^8 + x^4 + x^3 + x + 1, less its top term
        b >>= 1
    return out


def _inverses() -> list[int]:
    """Each byte's inverse in the field. Zero has none and maps to itself."""
    out = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if _times(a, b) == 1:
                out[a] = b
                break
    return out


def _substitution() -> tuple[list[int], list[int]]:
    """The cipher's substitution table and its inverse, from the definition.

    Each byte becomes its own inverse in the field, then goes through the affine
    transform FIPS-197 states: the value exclusive-ored with four rotations of itself
    and with 0x63.
    """
    inverse = _inverses()
    forward = [0] * 256
    for byte in range(256):
        value = inverse[byte]
        rolled = value
        for _ in range(4):
            rolled = ((rolled << 1) | (rolled >> 7)) & 0xFF
            value ^= rolled
        forward[byte] = value ^ 0x63
    backward = [0] * 256
    for byte, value in enumerate(forward):
        backward[value] = byte
    return forward, backward


SBOX, INVERSE_SBOX = _substitution()
# The six multiplications the rounds need, each as a table: two and three for mixing a
# column, and nine, eleven, thirteen and fourteen for unmixing one.
TIMES = {n: tuple(_times(one, n) for one in range(256)) for n in (2, 3, 9, 11, 13, 14)}
# The round constants, one per round: successive powers of two in the same field, which
# is why they stop looking like powers of two at the ninth.
RCON = []
_power = 1
for _ in range(ROUNDS):
    RCON.append(_power)
    _power = _times(_power, 2)
RCON = tuple(RCON)


def aeskey(key: bytes) -> list[bytes]:
    """The eleven round keys a 128-bit key becomes, which both directions use.
    XeCrypt's `XeCryptAesKey`."""
    if len(key) != KEY_LENGTH:
        raise ValueError("an AES key here is %d bytes, not %d" % (KEY_LENGTH, len(key)))
    words = [list(key[at : at + 4]) for at in range(0, KEY_LENGTH, 4)]
    for index in range(4, 4 * (ROUNDS + 1)):
        word = list(words[index - 1])
        if index % 4 == 0:
            word = word[1:] + word[:1]
            word = [SBOX[one] for one in word]
            word[0] ^= RCON[index // 4 - 1]
        older = words[index - 4]
        words.append([one ^ two for one, two in zip(older, word, strict=True)])
    return [
        bytes(one for word in words[at : at + 4] for one in word)
        for at in range(0, len(words), 4)
    ]


def _shifted(state: list[int]) -> list[int]:
    """Rows one to three moved left by their own row number."""
    return [state[(index + 4 * (index % 4)) % 16] for index in range(16)]


def _unshifted(state: list[int]) -> list[int]:
    """The inverse of `_shifted`: rows moved back to the right."""
    out = [0] * 16
    for index in range(16):
        out[(index + 4 * (index % 4)) % 16] = state[index]
    return out


def encrypt_aesecb(rounds: list[bytes], block: bytes) -> bytes:
    """One block enciphered under an expanded key. XeCrypt's `XeCryptAesEcb`,
    encrypting."""
    state = [one ^ two for one, two in zip(block, rounds[0], strict=True)]
    for number in range(1, ROUNDS + 1):
        state = _shifted([SBOX[one] for one in state])
        if number != ROUNDS:
            mixed = []
            for at in range(0, 16, 4):
                a, b, c, d = state[at : at + 4]
                mixed += [
                    TIMES[2][a] ^ TIMES[3][b] ^ c ^ d,
                    a ^ TIMES[2][b] ^ TIMES[3][c] ^ d,
                    a ^ b ^ TIMES[2][c] ^ TIMES[3][d],
                    TIMES[3][a] ^ b ^ c ^ TIMES[2][d],
                ]
            state = mixed
        state = [one ^ two for one, two in zip(state, rounds[number], strict=True)]
    return bytes(state)


def decrypt_aesecb(rounds: list[bytes], block: bytes) -> bytes:
    """One block deciphered under an expanded key. XeCrypt's `XeCryptAesEcb`,
    decrypting."""
    state = [one ^ two for one, two in zip(block, rounds[ROUNDS], strict=True)]
    for number in range(ROUNDS - 1, -1, -1):
        state = [INVERSE_SBOX[one] for one in _unshifted(state)]
        state = [one ^ two for one, two in zip(state, rounds[number], strict=True)]
        if number:
            mixed = []
            for at in range(0, 16, 4):
                a, b, c, d = state[at : at + 4]
                mixed += [
                    TIMES[14][a] ^ TIMES[11][b] ^ TIMES[13][c] ^ TIMES[9][d],
                    TIMES[9][a] ^ TIMES[14][b] ^ TIMES[11][c] ^ TIMES[13][d],
                    TIMES[13][a] ^ TIMES[9][b] ^ TIMES[14][c] ^ TIMES[11][d],
                    TIMES[11][a] ^ TIMES[13][b] ^ TIMES[9][c] ^ TIMES[14][d],
                ]
            state = mixed
    return bytes(state)


def encrypt_aescbc(key: bytes, data: bytes, iv: bytes) -> bytes:
    """Cipher block chaining: each block exclusive-ored with the one before it.
    XeCrypt's `XeCryptAesCbc`, encrypting.

    Data that is not a whole number of blocks comes back as it was. The library under
    XeCrypt refuses it before touching a byte (`aes_modes.c`, `len & 15` returns
    EXIT_FAILURE) and `XeCryptAesCbc` does not look at the answer, so a buffer
    encrypted in place is left as it stands -- measured with an fcrt.bin whose sealed
    part is not.
    """
    if len(data) % BLOCK:
        return bytes(data)
    rounds = aeskey(key)
    last, out = bytes(iv), bytearray()
    for at in range(0, len(data) - BLOCK + 1, BLOCK):
        plain = data[at : at + BLOCK]
        block = bytes(one ^ two for one, two in zip(plain, last, strict=True))
        last = encrypt_aesecb(rounds, block)
        out += last
    return bytes(out)


def decrypt_aescbc(key: bytes, data: bytes, iv: bytes) -> bytes:
    """The inverse of `encrypt_aescbc`. XeCrypt's `XeCryptAesCbc`, decrypting; data
    that is not a whole number of blocks comes back as it was, as there."""
    if len(data) % BLOCK:
        return bytes(data)
    rounds = aeskey(key)
    last, out = bytes(iv), bytearray()
    for at in range(0, len(data) - BLOCK + 1, BLOCK):
        block = bytes(data[at : at + BLOCK])
        plain = decrypt_aesecb(rounds, block)
        out += bytes(one ^ two for one, two in zip(plain, last, strict=True))
        last = block
    return bytes(out)
