"""Which secret opens which stage, and that is the whole of what the kinds differ by.

Every stage is RC4 under a key of sixteen bytes derived from a secret and that stage's
own nonce. What changes down the chain is the secret, and almost always it is the key
the previous stage was opened with -- which makes this a chain rather than a list.

Three exceptions, and no others were found:

**The first CB opens with a key that is public.** It is burned into every console ever
made, so nothing about one console is needed to read its first stage. The original
says it with a checksum beside it -- "1BL Key set to : 0xDD88... sum: 0x983 (expects:
0x983)" -- which `key_sum` reproduces.

**The stage that binds the chain to one console** folds that console's key into the
message. Which stage that is depends on the chain rather than on a kind: a split CB
binds on the second half, and a chain with a single CB -- a JTAG chain is `cb_5770.bin`,
`cd_5770.bin`, `ce_1888.bin` with flags of zero -- binds nowhere and keys every stage
from its nonce alone. Asking for a CPU key there would be asking for something the chain
does not use.

**A fat retail chain keys its CD twice**, the second pass under the console's own key.
That was found by sweeping boards, and it is worth knowing why it hid: most of what was
"known" about a chain had only ever been measured on one slim console.

Under the manufacturing regime the binding message carries sixteen zero bytes where the
console's key would go -- this is the "zeropair" the original's log talks about -- and
under the later regime it carries CB_A's own head as well, with the flag word blanked.
"""

from __future__ import annotations

import collections
import math
import struct

from ..crypto.keys import derive
from ..crypto.rc4 import rc4

ONE_BL_KEY = bytes.fromhex("DD88AD0C9ED669E7B56794FB68563EFA")
KEY_LENGTH = 0x10


def key_sum(key: bytes) -> int:
    """The checksum the original states beside the 1BL key: its bytes added up.

    Measured against the number the original prints for the key above, 0x983. Nothing
    is masked, because nothing needs to be at sixteen bytes.
    """
    return sum(bytes(key))


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


def keys(stages, cpu_key: bytes = b"", fat: bool = False) -> tuple:
    """One key per stage, in order, each following from the one before it.

    `stages` is the chain with any inserted payload already dropped -- keying through
    one gets everything after it wrong. A stage whose secret needs a CPU key that was
    not given comes back as `None`, and so does everything behind it, because there is
    nothing to carry forward.
    """
    binds = binding_at(stages)
    out, secret = [], ONE_BL_KEY
    for index, stage in enumerate(stages):
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
        key = derive(secret, message)
        # A fat retail chain runs CD's key through the console's key a second time.
        if fat and stage.tag == "CD" and cpu_key:
            key = derive(cpu_key, key)
        out.append(key)
        secret = key
    return tuple(out)


def under(stage, secret: bytes) -> bytes:
    """A stage opened under a secret, deriving the key from the stage's own nonce.

    The whole of it, header included, because a stage's header is not encrypted and
    everything that reads one counts from its start.
    """
    return stage.head + rc4(derive(secret, stage.nonce), stage.body)


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
