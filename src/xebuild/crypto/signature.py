"""The signature a bootloader stage carries, and the check the original makes of it.

A stage is signed over its own body. Sixty of the release's `CB_*`, `cba_*` and `SB_*`
files in `common/` pass here -- every one a release's file list names among them -- and
`cba_9188.bin` with one byte of its signature changed, which the original refuses, does
not. `cb_4540.bin` fails as well, and no file list names it. The rest of `common/` fails
too, and is meant to. `cbb_*`, `cd_*`, `ce_*`, `cf_*`
and `cg_*` are signed with another key over this same scheme, and lifting one with this
one's modulus gives a block that is not even shaped like a signature. `SC_*`, `SD_*` and
`sd_*` are signed over a body at 0x120 under one of the other two salts, so this check
is not the one that reads them.

**The modulus is read a quad at a time with the first quad the least significant**, and
so is the signature. `int.from_bytes(key[16:272], "big")` is 2048 bits wide with its
last bit clear, so it is not the modulus, and read that way the whole check falls over.

The exponentiation is scaled as well: `s**e % n` on a valid signature reproduces none of
the original's bytes, while `s**e * 2**(2048 * (1 - e)) % n` reproduces all of them.
That factor is what the sixty passing stages and the one refused stage agree on.
"""

import hashlib

from .rc4 import rc4
from .formats import BODY_AT


def _rotsum(state: bytearray, data: bytes) -> None:
    """Four 64-bit accumulators over `data`, added into the 32 bytes of `state`.

    A quad at a time, big-endian, and the state carried from call to call. Two of the
    four are carry and borrow counters rather than sums; the other two are rotated by 29
    and 31 as they go. XeCrypt's `XeCryptRotSum` -- which is not the rotation `smc`
    performs, that one reading words and keeping two of them.
    """
    mask = (1 << 64) - 1
    carries = int.from_bytes(state[0:8], "big")
    sums = int.from_bytes(state[8:16], "big")
    borrows = int.from_bytes(state[16:24], "big")
    differences = int.from_bytes(state[24:32], "big")
    for at in range(0, len(data) - len(data) % 8, 8):
        quad = int.from_bytes(data[at:at + 8], "big")
        carried = (quad + sums) & mask
        sums = 1 if carried < quad else 0
        differences = (mask - quad + differences + 1) & mask
        carries = (sums + carries) & mask
        sums = (carried << 29 | carried >> 35) & mask
        borrows = (mask - (1 if differences > quad else 0) + borrows + 1) & mask
        differences = (differences << 31 | differences >> 33) & mask
    state[0:8] = carries.to_bytes(8, "big")
    state[8:16] = sums.to_bytes(8, "big")
    state[16:24] = borrows.to_bytes(8, "big")
    state[24:32] = differences.to_bytes(8, "big")


def _rotsum_sha(first: bytes, second: bytes) -> bytes:
    """Twenty bytes over two buffers. XeCrypt's `XeCryptRotSumSha`.

    The state goes into SHA-1 twice as it stands, both buffers go in whole, and the
    state goes in twice more with every bit of it turned over.
    """
    state = bytearray(32)
    _rotsum(state, first)
    _rotsum(state, second)
    inverted = bytes(byte ^ 0xFF for byte in state)
    return hashlib.sha1(
        bytes(state) + bytes(state) + bytes(first) + bytes(second)
        + inverted + inverted).digest()


def verify_stage(stage: bytes, key: bytes) -> bool:
    """Whether a bootloader stage's signature is what its own header and body say.

    What the original does at 0x40E5A0 when it loads one: `RotSumSha` over the header's
    first sixteen bytes and the body from `formats.BODY_AT` as far as the stage's own
    length at 0x0C rounded up to sixteen; SHA-1 over that with eight zero bytes in front
    and the salt in behind; then the twenty bytes that come out compared, through the
    RSA, with the same scheme laid out again and RC4'd over its first 0xEB bytes.

    The length is read out of the stage and nothing checks that it belongs there, which
    is what the original does as well: a body cut short hashes over what is there.

    `key` is the 0x110 bytes of `1BL_pub.bin`, already found good by its sum -- see
    `BuildConfig.one_bl_pub`. Saying so is the caller's: only it knows the stage's name.
    """
    length = int.from_bytes(stage[0x0C:0x10], "big")
    hashed = _rotsum_sha(stage[0x00:0x10], stage[BODY_AT:(length + 15) & ~15])

    # The salt a stage is signed under, one of three globals in the original. This is
    # `XBOX_ROM_B` at 0x44A558. The other two are at 0x44A540 and 0x44A54C, and the
    # loader at 0x40E8A0 chooses between them on the first two bytes of the file being
    # "SD" -- read at 0x420AB0 as the big-endian word and compared with 0x5344. It goes
    # on to 0x40E620, which signs a body at 0x120 rather than 0x140.
    salt = b"XBOX_ROM_B"
    hashed = hashlib.sha1(bytes(8) + hashed + salt).digest()

    expected = bytearray(0x100)
    expected[0xE0] = 1
    expected[0xE1:0xEB] = salt
    expected[0xEB:0xFF] = hashed
    expected[0xFF] = 0xBC
    expected[0x00:0xEB] = rc4(hashed, bytes(expected[0x00:0xEB]))
    expected[0x00] &= 0x7F

    modulus = 0
    for at in range(32):
        modulus |= int.from_bytes(key[16 + 8 * at:24 + 8 * at], "big") << (64 * at)
    exponent = int.from_bytes(key[4:8], "big")

    signature = stage[0x40:BODY_AT]
    signature = b"".join(
        signature[at * 8:at * 8 + 8] for at in range(31, -1, -1))
    lifted = pow(int.from_bytes(signature, "big"), exponent, modulus)
    scale = pow(pow(2, 2048, modulus), 1 - exponent, modulus)
    return (lifted * scale % modulus).to_bytes(0x100, "big") == bytes(expected)
