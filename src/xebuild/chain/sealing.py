"""Which secret opens which stage, and that is the whole of what the kinds differ by.

Every stage is RC4 under a key of sixteen bytes derived from a secret and that stage's
own nonce. What changes down the chain is the secret, and almost always it is the key
the previous stage was opened with -- which makes this a chain rather than a list.

Four exceptions, and no others were found -- the fourth, a development chain's SC
starting over from sixteen zero bytes, is noted where it happens in `keys`:

**The first CB opens with the 1BL key.** It is burned into every retail console ever
made, so nothing about one console is needed to read its first stage; like the original,
this takes it from the configuration -- see `OneBlKeyConfig` -- rather than holding it.

**The stage that binds the chain to one console** folds that console's key into the
message. Which stage that is depends on the chain rather than on a kind: a split CB
binds on the second half, and a chain with a single CB -- a JTAG chain is `cb_5770.bin`,
`cd_5770.bin`, `ce_1888.bin` with flags of zero -- binds nowhere and keys every stage
from its nonce alone. Asking for a CPU key there would be asking for something the chain
does not use.

**One chain in one image type keys its CD twice**, the second pass under the console's
own key. The original's own test says when, at 0x41C760: the two words read just before
the call are `[0x479EB8]`, zero when the chain has no CB_B, and `[0x479EA8]`, one when
the image is retail. Both, or the pass does not happen -- a fat glitch image keys its CD
from the nonce alone and a split chain binds on CB_B instead.

Which stage takes it is the caller's to say, because nothing in a chain states the image
type: `second_pass_at`. Reading an image the other way round, `Chain.keys` finds out by
trying, since a stage that opens under the ordinary key was not sealed with the pass.
This was got wrong once, as "a fat board keys its CD twice", and it made every chain on
a fat board unreadable from CD down -- six chains measured, every one of them opening
under the ordinary key.

Under the manufacturing regime the binding message carries sixteen zero bytes where the
console's key would go -- this is the "zeropair" the original's log talks about -- and
under the later regime it carries CB_A's own head as well, with the flag word blanked.
"""

import math
import struct
import collections

from ..crypto.keys import hmacsha

KEY_LENGTH = 0x10


def binding_at(stages) -> int:
    """Which stage carries the console binding, or -1 when the chain has none.

    A split CB binds on its second half. Nothing else does, and a chain of one CB does
    not bind at all.
    """
    if len(stages) < 2 or stages[0].tag != "CB" or stages[1].tag != "CB":
        return -1
    return 1


def message_for(stage, cpu_key: bytes, first) -> bytes:
    """What this stage's key is derived over, given the CB_A that sets the regime."""
    if first.manufacturing:
        return stage.nonce + bytes(KEY_LENGTH)
    if first.late:
        head = bytearray(first.image[first.at : first.at + KEY_LENGTH])
        head[0x06:0x08] = bytes(2)
        return stage.nonce + bytes(cpu_key) + bytes(head)
    return stage.nonce + bytes(cpu_key)


def keys(stages, one_bl_key: bytes, cpu_key: bytes = b"",
         second_pass_at: int = -1) -> tuple:
    """One key per stage, in order, each following from the one before it, the first
    from the 1BL key.

    `stages` is the chain with any inserted payload already dropped -- keying through
    one gets everything after it wrong. A stage whose secret needs a CPU key that was
    not given comes back as `None`, and so does everything behind it, because there is
    nothing to carry forward.

    `second_pass_at` is the index of the stage whose derived key is run through the
    console's key a second time; -1, the default, is no such stage. A retail image on a
    chain with no CB_B is the one case, and the key that comes out is also the secret
    the stage behind it derives from.
    """
    binds = binding_at(stages)
    out, secret = [], bytes(one_bl_key)
    for index, stage in enumerate(stages):
        if stage.tag == "SC":
            # A development chain starts over at its SC, from sixteen zeros: measured
            # on a 17489 devkit image, whose SC opens under HMAC(zeros, nonce) and whose
            # SD and SE follow from it as every stage follows from the one before.
            secret = bytes(KEY_LENGTH)
        if secret is None:
            out.append(None)
            continue
        if index == binds:
            if not cpu_key:
                out.append(None)
                secret = None
                continue
            message = message_for(stage, cpu_key, stages[0])
        else:
            message = stage.nonce
        key = hmacsha(secret, message)
        if index == second_pass_at:
            if not cpu_key:
                raise ValueError(
                    "the stage at %d takes a second pass under the console's key and "
                    "none was given" % index
                )
            key = hmacsha(cpu_key, key)
        out.append(key)
        secret = key
    return tuple(out)


def entropy(data: bytes) -> float:
    """Bits per byte. Sealed bytes sit near 8, code well under 7."""
    if not data:
        return 0.0
    counts = collections.Counter(data)
    return -sum(
        n / len(data) * math.log2(n / len(data)) for n in counts.values()
    )


def looks_open(tag: str, body: bytes) -> bool:
    """Whether this body is already in the clear, so opening it would spoil it.

    It happens: an exploited console keeps some of its chain unsealed. Measured on this
    bench, an RGH3 console's CB_B and CD sit at entropies of 5.92 and 4.01 where a
    retail console's are 7.97 and 7.98, and running the cipher over them turns readable
    code into noise at 7.98.

    **Which question to ask depends on the kind.** For CB and CD it is entropy, because
    they are code. For CE it says nothing: CE carries the compressed kernel, so its
    plaintext is near 8 as well, and asking entropy of it calls a correct key wrong. A
    CE is judged on its header instead: an opened one states a sane length at 0x08 with
    zero beside it, measured at 0x120000 on this console, where the sealed bytes give
    0xDF59448 and a padding word that is not zero.
    """
    if tag == "CE":
        if len(body) < 0x10:
            return False
        length, padding = struct.unpack_from(">II", body, 8)
        return padding == 0 and 0 < length <= 0x2000000
    return entropy(body[:0x2000]) < 7.0
