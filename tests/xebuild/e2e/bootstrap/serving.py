"""The console a stand-in plays: what it answers, made from the console's dump.

The client and update recordings were made against a stand-in update server -- the
original on one side, `server.py` on the other, in one container -- which answers
`GTIN` with `info.bin`, `GTFL` with the whole flash, `GTBL` with the bootloaders and
`GETF` with a console's files by name. A console answers all of that from what its
flash holds, so here it is all made from the dump and its key:

- the flash itself, and its first 0xB0000 bytes as the bootloaders, its first 0x200 as
  `flash_hdr`;
- the files the update reads by name out of the dump's filesystem and areas -- the
  security files, the sealed keyvault and SMC, the blobs, the settings;
- `info.bin`, laid out as `xebuild.network.info` reads one: the server's and the
  kernel's versions, the board and the hack, the flash's size, the lockdown value, the
  keys, the fuses as a console burns them for its key and lockdown value, the three
  public keys every console carries, and the nonce of the chain's first stage.

The three public keys are the ones the console's ROM and hypervisor carry, the same on
every console, as one answered with them; nothing in J-Runner's or Microsoft's
downloads holds them in the clear.
"""

import struct

from xebuild.image import Image, Keyvault
from xebuild.boards import for_name

PUBLIC_KEYS = (
    # ONE_BL
    bytes.fromhex(
        "00000020000100010000000000000000e98db5dcaf388ef1389e28cb4a11c82252e11f53455660"
        "a252d4d1684ecc8099d75c40c5af730ccf4406b06d16910838b3002dbceb1d0c1dc5c6680b804c"
        "620b7ee8720ccf1db4bdee4b1136d1c9921fe9aec0515251f723d6bcf4e9588740b102665a43eb"
        "675f509432347aa750d9b4144eb002318ba7009a12c83b8f76e48f33b5cd0c246d2ae557a04476"
        "7841f48fcb3ab50ea1a2566d17db32ccb85a5faeed9a62315d887f6d9a5380b034c742512d944d"
        "8609328f71a7ba166ce6dc6b64617d16b52051d0b11ffe1e35569a764d627f5df4b87dc4182c81"
        "b7afe47d135df40f63053f1aeded4beefd6d74e6a592a799817395d8c7a5a1c77b0905854104"),
    # PIRS
    bytes.fromhex(
        "00000020000000030000000000000000e63b32b28d9e9ee79dfc5c7241945847de0d184072d6e3"
        "468eba8ebc1a90ac20ba0385b51a3e25f9a658ebb6a3c4a3eeb2b0ae9769ebfe71fc02ab77bac8"
        "e674e67c630eaf4cf7e7114a802472057a63d0f89102a6e77d77c5a79b08112ea064456046bc36"
        "e11771be66492fae20a4769c2751cf4b347a35bca4aa1c474bf497224e1324d3c157df4d84b918"
        "9799ac00b33d032560c87a59fe48ff283d10bb9e09062a61202cf872eb87e6d1fbb366fc4a02ae"
        "d4d837cfa6322579360ef4ed19a21027962f9fa93da43730115183bdf7c7e5ceaaecde48a084f7"
        "b0f64b8ef089bd477c90dd88121740d24ea6c611041b57a868b461f41bc68be8d920f205e070"),
    # MASTER
    bytes.fromhex(
        "00000020000000030000000000000000dd5f496f994d37bbe45b98f25da6b843bed310fd3ca4d4"
        "ace6923a79db3b63af38cda0e5857201f90e5f5a5b084bade2a02a4233853453831ee55b8fbf35"
        "8e63d8288cff03dcc43502e40d1ac1369fbb90edde4eec86103fe41ffd96d93a782538e1d38b1f"
        "96bd84f65e2a56bad0a824e5028f3ca19aeb9359d71b99dac4df7bd0c19a12cc3a17bf6e4d7887"
        "d42a7f6b9e2fcd8d4ef5cec2a05aa30f9fadfe126574206ff25c52e4b0c13c250daed1827c60d7"
        "44e5cd8bea6c80b51b7a0c02ce0c24513d39364a3fd312cf838d815600b4647986eaecb6de8a35"
        "7bab354ebb87ea1d478ce1f390132797558207f2f3aaf953478f74a38e7baeb8fc77cbfbab8a"),
)

# The server version the recordings' console ran: 3.2.
SERVER = 0x302
# The bits of the hardware word every console measured carries besides its board
# and its hard disk.
HARDWARE = 0x207
# What a hack type sets in the top bits of the bootstrap word.
HACKS = {"retail": 0, "glitch2m": 0x10000000, "glitch2": 0x20000000,
         "glitch": 0x40000000, "rgh3": 0x40000000, "jtag": 0x80000000}
BOARDS = ("xenon", "zephyr", "falcon", "jasper", "trinity", "corona", "winchester")


def info(raw: bytes, board: str, cpu_key: bytes, hack: str, ldv: int,
         kernel: str = "2.0.17559.0", hdd: bool = True) -> bytes:
    """The answer to GTIN of a console whose flash is `raw`."""
    flash = for_name(board)[0].flash
    image = Image(raw, flash)
    index = next(at for at, name in enumerate(BOARDS) if board.startswith(name))
    major, minor, build, qfe = (int(part) for part in kernel.split("."))
    words = (SERVER, (major << 28) | (minor << 24) | (build << 8) | qfe, 0,
             HACKS[hack] | index, (index << 28) | HARDWARE | (0x20 if hdd else 0),
             len(raw), (0x200 + flash.spare.length) * flash.spare.pages_a_block
             if flash.spare else 0, ldv)
    keyvault = Keyvault.opened(bytes(image.flat[0x4000:0x8000]), cpu_key)
    first = struct.unpack_from(">I", image.flat, 0x08)[0]
    out = bytearray(struct.pack(">8I", *words))
    out += cpu_key + keyvault.dvd_key + fuses(cpu_key, ldv) + bytes(0x60)
    out += bytes.fromhex("DD88AD0C9ED669E7B56794FB68563EFA")
    for key in PUBLIC_KEYS:
        out += key
    out += bytes(image.flat[first + 0x10:first + 0x20]) + bytes(0x50)
    return bytes(out)


def fuses(cpu_key: bytes, ldv: int) -> bytes:
    """Twelve fuse lines: the three every retail console burns, the key twice over
    two lines each, and a nibble a lockdown step from line 7 on."""
    lines = [bytes.fromhex("c0ffffffffffffff"), bytes.fromhex("0f0f0f0f0f0ff0f0"),
             bytes.fromhex("f0ff000000000000"), cpu_key[:8], cpu_key[:8],
             cpu_key[8:], cpu_key[8:]]
    nibbles = "f" * ldv + "0" * (16 * 5 - ldv)
    lines += [bytes.fromhex(nibbles[at:at + 16]) for at in range(0, 80, 16)]
    return b"".join(lines)


# One record of a slot and the two the console these were recorded on had in its place
# once an addon was kept: the same routine left by a branch instead of returning one.
_KEPT = (bytes.fromhex("0015d9d800000002386000014e800020"),
         bytes.fromhex("0015da1800000001480000f00015db080000000138600001"))


def with_addon(slot: bytes, addon: bytes) -> bytes:
    """A patch slot as a console holds it with an addon kept: its own records up to
    the end mark, the addon's behind them, the end mark and the addon's length, and
    zeros to the slot's end. Records start 0x10 in, each an address, a count and that
    many words; an address of 0xFFFFFFFF ends them."""
    at = 0x10
    while struct.unpack_from(">I", slot, at)[0] != 0xFFFFFFFF:
        at += 8 + 4 * struct.unpack_from(">I", slot, at + 4)[0]
    records = slot[:at].replace(*_KEPT)
    out = records + addon + b"\xff" * 4 + struct.pack(">I", len(addon))
    return out + bytes(len(slot) - len(out))
