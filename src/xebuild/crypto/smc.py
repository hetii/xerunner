"""The digest the bootloaders take of a sealed SMC, to say which one they were built
beside. The SMC's cipher itself is `formats.decrypt_smc` and `formats.encrypt_smc`.
"""

U64 = (1 << 64) - 1


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
