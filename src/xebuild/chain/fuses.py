"""The fuses a loader hands a console in place of its own: twelve lines of eight bytes.

A console's real fuses are burnt into its CPU. A manufacturing chain and a JTAG image's
reboot core cannot rely on them, so the image carries a copy -- 0x60 bytes -- and the
loader hands that over instead. Each line was read out of the original's own code by
x360mcp -- the template at 0x44A700 and the routines that fill it -- and every
manufacturing and JTAG reference image agrees to the byte:

    line 0     C0FFFFFFFFFFFFFF
    line 1     six of 0x0F, then two bytes naming the console type
    line 2     one nibble of 0xF for each bit set in the CB's allow word, counted from
               the top of the line
    lines 3-6  the CPU key, each half written twice
    lines 7-8  the lockdown value in 0xF nibbles, sixteen to a line
    lines 9-11 zero

The type and the allow word come from the word a CB carries at 0x3B0 -- `cb_word` --
type in the top byte, allow in the low sixteen bits. The original prints the type's
line with a name: devkit, retail, testkit, "retail slim".
"""

# The two bytes that end line 1, by console type.
TYPES = {0: b"\x0f\x0f", 1: b"\x0f\xf0", 2: b"\xf0\x0f", 3: b"\xf0\xf0"}


def cb_word(cb: bytes) -> int:
    """The type and allow word a CB states at 0x3B0."""
    return int.from_bytes(bytes(cb[0x3B0:0x3B4]), "big")


def virtual(word: int, cpu_key: bytes, ldv: int) -> bytes:
    """The twelve lines for a console with this CB word, CPU key and lockdown value."""
    kind, allow = word >> 24, word & 0xFFFF
    if kind not in TYPES:
        raise ValueError("console type %#x is not one the original knows" % kind)
    sequence = 0
    for bit in range(16):
        if allow & (1 << bit):
            sequence |= 0xF << ((15 - bit) * 4)

    def unary(count: int) -> bytes:
        count = max(0, min(16, count))
        return int("F" * count + "0" * (16 - count), 16).to_bytes(8, "big")

    key = bytes(cpu_key)
    return (bytes.fromhex("C0FFFFFFFFFFFFFF") + b"\x0f" * 6 + TYPES[kind]
            + sequence.to_bytes(8, "big") + key[:8] * 2 + key[8:] * 2
            + unary(ldv) + unary(ldv - 16) + bytes(24))
