"""The values in a stage that belong to one console rather than to a release.

Almost nothing in a chain is a console's own. The stages are files the release ships,
laid into the image and sealed; what makes an image belong to one machine is a handful
of bytes in two places, and this reads them.

Both places begin the same way, which is why one class serves both:

    0x00   3  the pairing, three bytes binding a bootloader to one console
    0x03   1  the lockdown value
    0x04  12  the rest of the console block

**Only a CF fills that lockdown byte.** In a CB_B it is zero: measured on a console's
own CB_B and on two reference images the original built, where the pairing is written
and the byte after it is not, while the same console's CF states 14 and 13. So a CB_B
carries the pairing and the sixteen bytes that bind it, and the lockdown value is read
from the CF.

**CF carries them at the source, at 0x21C of the opened stage.** The original reads them
off CF and says so: "CF slot 0 decrypted ok LDV 0x0e Pairing: 0x780227", then "setting
LDV from image to 14" and "setting pairing data from image to 0x780227". Reproduced to
the byte on that console -- `in_cf` is that offset.

**CB_B repeats them and binds them**, with sixteen further bytes at 0x10 of its body:

    HMAC-SHA1(cpu key, the stage's key + these first sixteen bytes + the SMC's digest)

so that a CB_B and the SMC beside it describe each other. `expected` computes it, and
comparing it with `digest` is what proves `crypto.smc.fingerprint` -- until this existed
there was nothing a fingerprint could be checked against.

A glitched console does not need that field to be right, because the exploit patches the
check out rather than recomputing it; a retail image does.
"""

from ..crypto.keys import hmacsha


class Fields:
    """The head of a console block, out of an opened stage's body."""

    LENGTH = 0x10

    def __init__(self, body: bytes):
        self.body = bytes(body)

    @classmethod
    def in_cf(cls, plain: bytes) -> Fields:
        """The block a CF keeps, counted from the opened stage rather than its body.

        Measured at 0x21C on a console whose own CF the original reports as pairing
        0x780227 and lockdown 0x0E, which is what comes out here.
        """
        return cls(plain[0x21C:])

    @property
    def pairing(self) -> bytes:
        return self.body[0x00:0x03]

    @property
    def ldv(self) -> int:
        """The lockdown value: how many of the fuse rows have been burnt."""
        return self.body[0x03]

    @property
    def head(self) -> bytes:
        """The sixteen bytes the binding is computed over, pairing included."""
        return self.body[: self.LENGTH]

    @property
    def digest(self) -> bytes:
        """The sixteen bytes a CB_B carries to say which SMC it was built beside.

        Sixteen zeros on a manufacturing chain, where the original does not compute it.
        """
        return self.body[self.LENGTH : self.LENGTH * 2]

    def expected(self, cpu_key: bytes, stage_key: bytes, fingerprint: bytes) -> bytes:
        """What `digest` should hold, from the console's key and the SMC's digest."""
        return hmacsha(cpu_key, bytes(stage_key) + self.head + bytes(fingerprint))

    def agrees(self, cpu_key: bytes, stage_key: bytes, fingerprint: bytes) -> bool:
        """Whether this stage and that SMC describe each other."""
        return self.digest == self.expected(cpu_key, stage_key, fingerprint)

    @classmethod
    def write(cls, pairing: bytes, cpu_key=None, stage_key: bytes = b"",
              fingerprint: bytes = b"", ldv: int = 0) -> bytes:
        """The 0x20 bytes a stage carries for one console, ready to be laid in its body.

        `ldv` is left at zero because that is what a CB_B carries, and a CF is the one
        place it is filled.

        **A `cpu_key` of None leaves the sixteen bytes that bind this zero**, which is
        not a shortcut: under the manufacturing regime the original does not compute
        them either, and an image it built that way carries zeros there. See `sealing`.
        """
        pairing = bytes(pairing)
        if len(pairing) != 3:
            raise ValueError("a pairing is 3 bytes and this is %d" % len(pairing))
        head = bytearray(cls.LENGTH)
        head[0x00:0x03] = pairing
        head[0x03] = ldv
        if cpu_key is None:
            return bytes(head) + bytes(cls.LENGTH)
        return bytes(head) + cls(bytes(head)).expected(cpu_key, stage_key, fingerprint)

    def __repr__(self) -> str:
        return "Fields(pairing %s, ldv %d)" % (self.pairing.hex(), self.ldv)
