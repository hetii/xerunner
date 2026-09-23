"""The system management controller: the cipher its image is kept under, and the digest
the bootloaders take of it.

Nothing like the other three. It is a byte-at-a-time stream whose key is four 32-bit
accumulators, and each byte that comes out feeds the two accumulators after it, so the
stream depends on everything already written. There is no key material from outside: the
four accumulators start from the same four bytes in every image, and what makes one
image's stream differ from another's is the four bytes at its head.

Those four bytes are a seed. They are stored in the clear and they are **not** the
plaintext's first four bytes: the plaintext's are discarded, and whoever seals an image
chooses what goes there. That is why an SMC's identity is a checksum from byte four
on -- the head is not part of the image, it is how the image was locked.

All of it was measured, in both directions, on five cases that agree byte for byte:

- Three images built by the original from a plaintext of this side's choosing, which
  `smcnocheck` is what lets through. A plaintext of zeros hands back the bare stream.
- Two real consoles' dumps, whose sealed SMC opens to a plaintext that carries the same
  twelve bytes from offset four as every plaintext SMC the release ships,
  `01c641bb01c6212d01c601c6`, and states version 3.1.

The seed is per image and not ours to choose here: the two consoles measured carry
`fbd75a10` and `4552c477`, and the original under `-norandom` writes `cc7ac1e7` every
time. Who draws it is a question for whatever builds an image, so it is an argument.
"""

from __future__ import annotations

KEY = (0x42, 0x75, 0x4E, 0x79)
SEED_LENGTH = 4
U64 = (1 << 64) - 1


def _advanced(keys: list, index: int, cipher: int) -> None:
    """Feed one sealed byte back into the two accumulators after it."""
    mask = 0xFFFFFFFF
    # The byte is multiplied before it is fed in, and the two accumulators take the
    # two halves of that product: the one after this byte's takes the low half, the one
    # after that the high half.
    product = cipher * 0xFB
    keys[(index + 1) & 3] = (keys[(index + 1) & 3] + product) & mask
    keys[(index + 2) & 3] = (keys[(index + 2) & 3] + (product >> 8)) & mask


def opened(sealed: bytes) -> bytes:
    """An SMC image as it runs, out of the bytes flash holds.

    The whole buffer comes back, its own length. **Its first four bytes are not
    plaintext** -- they are what the seed happens to decrypt to, and nothing means
    anything by them. Everything that identifies or patches an SMC counts from four.
    """
    keys, out = list(KEY), bytearray(len(sealed))
    for index, cipher in enumerate(sealed):
        out[index] = cipher ^ (keys[index & 3] & 0xFF)
        _advanced(keys, index, cipher)
    return bytes(out)


def sealed(plain: bytes, seed: bytes) -> bytes:
    """An SMC image as flash holds it, under a seed of the caller's choosing.

    The plaintext's first four bytes go nowhere: the seed takes their place, and the
    accumulators advance over the seed before the first real byte is reached. Which is
    the whole reason two images of the same SMC under different seeds share no bytes.
    """
    if len(seed) != SEED_LENGTH:
        raise ValueError(
            "an SMC's seed is %d bytes and this is %d" % (SEED_LENGTH, len(seed))
        )
    if len(plain) < SEED_LENGTH:
        raise ValueError("an SMC is longer than its seed; this one is %d" % len(plain))
    keys, out = list(KEY), bytearray(len(plain))
    for index in range(SEED_LENGTH):
        out[index] = seed[index]
        _advanced(keys, index, seed[index])
    for index in range(SEED_LENGTH, len(plain)):
        cipher = plain[index] ^ (keys[index & 3] & 0xFF)
        out[index] = cipher
        _advanced(keys, index, cipher)
    return bytes(out)


def _right(value: int, bits: int) -> int:
    """Rotate a 64-bit value right, which is the only rotation the digest uses."""
    bits &= 63
    return ((value >> bits) | (value << (64 - bits))) & U64


def fingerprint(sealed_image: bytes) -> bytes:
    """Sixteen bytes over a sealed SMC -- what the bootloaders call this SMC.

    Every bootloader from CB_B on carries sixteen bytes in its body that are
    `HMAC-SHA1(cpu key, stage key + the console's fields + this)`, so this is what ties
    a chain to the SMC lying beside it. Change one without the other and the pair no
    longer describe each other, which is a state that does occur: a console converted by
    RGH3 is in it.

    Two 64-bit accumulators run over the image a 32-bit big-endian word at a time. One
    adds each word and the other subtracts it, and both are rotated right after every
    word, by 35 bits and by 33. Out comes the adding one first, big-endian.

    **It is taken over the image sealed, as flash holds it.** Opening it first gives a
    different answer, and a wrong one. The seed is therefore part of what is measured,
    which is the mechanism by which two images of the same SMC are told apart.

    **Proved against a console.** The sixteen bytes stored in this bench console's own
    CB_B are `55aa5e9aa6306d1b0286006eba64ee96`, and `HMAC-SHA1(cpu key, the stage's
    key + its console fields + this)` computes exactly them. The comparison lives in
    `chain.console.Fields.agrees`. Nothing here was adjusted to make it come out.

    Two independent readings agree with the arithmetic as well, which is what it stood
    on before the chain existed: a literal transcription of J-Runner's
    `Nand.CalculateSMCHash`, its own spelling of the rotations kept ("rotate left 29"
    and "rotate left 31", which on 64 bits are these two rotations right), over both
    consoles' sealed SMCs and random input of four lengths; and the x360mcp tree, which
    measured it against six images of one console whose digests all differed.

    The sixteen bytes are **not** serialised J-Runner's way. It renders each
    accumulator with `ToString("X")`, which drops leading zero nibbles and then copies
    eight bytes out of a shorter string; for an accumulator of zero that string is one
    character. Fixed-width big-endian is what the stored fields agree with.

    **This is not XeCryptRotSum, although the rotations are the same 35 and 33.**
    XeCrypt's reads 64-bit quads and keeps four accumulators, two of them carry
    counters; this reads 32-bit words and keeps two. On a real SMC they give different
    answers, and the console's own bootloaders agree with this one. Noted so the
    resemblance does not tempt anyone into correcting it.
    """
    adds = subtracts = 0
    add_rotation, subtract_rotation = 35, 33
    for at in range(0, len(sealed_image) - 3, 4):
        word = int.from_bytes(sealed_image[at : at + 4], "big")
        adds = _right((adds + word) & U64, add_rotation)
        subtracts = _right((subtracts - word) & U64, subtract_rotation)
    return adds.to_bytes(8, "big") + subtracts.to_bytes(8, "big")
