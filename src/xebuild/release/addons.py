"""`addon.idx`: which of a release's optional patch files a console already carries.

`-a nofcrt` puts `bin/nofcrt.bin` into the patch slot. Update mode puts back what a
console already carries, and a console cannot name its patches -- it hands over the
patches themselves, `addons.bin`. The index in a release's `bin/` turns them back into
names; the original says "addon patch from console: nofcrt" for each one it finds.

The index as the original reads it (0x4034F0) and as it parses to the byte in 17559's,
eight entries in 0x11C bytes::

    be32   how many entries
    per entry:
      be32   how many records
      per record:  eight bytes, as the console hands them over
      16     the name, NUL padded, no extension
"""

NAME_LENGTH = 16


def index(body: bytes) -> list:
    """Every entry of an `addon.idx` as `(name, records)`, or a refusal where the file
    does not add up to its own count."""
    body = bytes(body)
    if len(body) < 4:
        raise ValueError("an addon.idx starts with its count, and this is %d bytes"
                         % len(body))
    count, at, out = int.from_bytes(body[:4], "big"), 4, []
    for _ in range(count):
        records = int.from_bytes(body[at:at + 4], "big")
        at += 4
        held = [body[at + 8 * one:at + 8 * one + 8] for one in range(records)]
        at += 8 * records
        name = body[at:at + NAME_LENGTH].split(b"\x00")[0].decode("latin-1")
        at += NAME_LENGTH
        out.append((name, held))
    if at != len(body):
        raise ValueError("this addon.idx names %d entries and they end at %#x of %#x"
                         % (count, at, len(body)))
    return out


def named(entries: list, addons: bytes) -> list:
    """The names of the entries a console's `addons.bin` carries, in the index's order.

    An entry is carried when every one of its records is somewhere in the console's
    bytes, looked for a byte at a time (0x421170). Measured on the original against a
    stand-in console: one entry, two, all eight and the last three, the records in the
    reverse order -- the names still come in the index's -- and at an offset of four,
    all found; half of `nofcrt`'s records, not.
    """
    return [name for name, records in entries
            if all(record in addons for record in records)]
