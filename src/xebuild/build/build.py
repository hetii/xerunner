"""What goes into an image, region by region, decided from the material and the release.

`layout` says where each region goes and `image.Image` knows how to hold it; this
decides **what** the bytes are. Every rule here came off the original: either out of an
image it built, or out of what it printed while building one, and the docstring says
which.

Nothing here writes into an image. A region is produced and handed back, so each one can
be held against the same region of a reference image on its own -- which is how they
were measured, and what a mistake in one of them looks like.
"""

from __future__ import annotations

import logging
import os
import time

from .. import boards
from ..boards.flash import PAGE
from ..chain import Fields, sealing
from ..chain.stage import LENGTH as STAGE_HEADER
from ..chain.stage import Stage
from ..crypto import smc as cipher
from ..crypto.keys import derive
from ..crypto.rc4 import rc4
from ..image import Dump, Header, Image
from ..image import anchor as anchors
from ..smc import Smc
from . import layout, security
from .filesystem import Filesystem

# The copyright line every image carries, with the year a build replaces. Read off the
# sixteen reference images, which carry two different years and nothing else different.
NOTICE = b"\xa9 2004-2010 Microsoft Corporation. All rights reserved."

# The kinds of stage that make up the chain proper. CF and CG are named by the same list
# and are not in it: they go in the slot behind the chain.
CHAIN_KINDS = ("CB", "CBA", "CBB", "CD", "CE")

# What a stage is sealed in multiples of. Measured: under the manufacturing patch set a
# patched CD ends at 0x52A8, the image says 0x52B0, and the next stage begins there.
# CE is not patched, keeps the length its own file states, and the region runs the few
# bytes further that its padding takes.
SEAL_ALIGN = 0x10

logger = logging.getLogger(__name__)


class Build:
    """One build: the console's own material on one side, a release on the other.

    `config` is a `config.BuildConfig`, which already resolves the console and the image
    type from what `-c` and `-t` were given, so neither is passed again here. `material`
    is the directory `-d` names and `release` the one `-f` names.
    """

    def __init__(self, config, material, release):
        self.config = config
        self.material = material
        self.release = release
        self._dump = None

    @property
    def console(self):
        return self.config.console

    @property
    def image_type(self):
        return self.config.image_type

    @property
    def dump(self) -> Dump | None:
        """The console's own flash, or None when the material holds no dump.

        Read once: it is seventeen megabytes and nearly every region asks it something.
        **Read with its own geometry**, which `boards.for_dump` works out from the dump,
        and not with the geometry of the console being built for: a trinity dump builds
        a falcon image, and read as a falcon's its settings blobs are scanned at the
        wrong offsets.
        """
        if self._dump is None and self.material.dump is not None:
            raw = self.material.dump
            own = boards.for_dump(raw, self.console)
            bigffs = self.config.bigffs if own is self.console else False
            self._dump = Dump(raw, own, bigffs)
        return self._dump

    @property
    def cpu_key(self) -> bytes | None:
        """This console's CPU key, from wherever the original looks first.

        The command line wins and the file is then not even opened -- "CPU key
        overridden from command line, not looking for cpukey.txt" -- and `config` is
        where the command line and the ini have already been settled against each
        other.
        """
        if self.config.cpu_key is not None:
            return self.config.cpu_key
        return self.material.key_in_file("cpukey.txt")

    @property
    def one_bl_key(self) -> bytes | None:
        """The 1BL key, the same way."""
        if self.config.one_bl_key is not None:
            return self.config.one_bl_key
        return self.material.key_in_file("1blkey.txt")

    def smc(self, seed: bytes = b"") -> bytes:
        """The SMC as the image carries it: sealed, and patched if the options ask.

        **The original chooses no image of its own.** It takes `smc.bin` from the
        per-build directory, and where there is none it keeps the console's --
        "reading data/smc.bin failed, using smc.bin from nand dump". Measured three
        ways: with the nineteen shipped images sitting in the per-build directory, in
        the base path's `data/`, and nowhere at all. Forty-six builds over every board
        spelling and three hack types wrote the dump's own SMC, byte for byte, without
        one exception. Which shipped image belongs to a console
        is J-Runner's decision, and it hands it over as this file; the names are
        recorded on the boards for whoever plays that part.

        **`patchsmc` lifts the reset limit and does nothing else**, and the ini
        shipped beside the original says where it does not apply: "will patch clean smc
        to remove 5 reset limit, ignored for retail". Measured both ways -- a JTAG build
        of
        `SMCfzj.bin`, which still has a limit, came out with the two bytes at its
        signature zeroed and nothing else changed; a retail build of
        `TRINITY_CLEAN.bin` kept its limit although the same option was set.

        **The seal takes the console's own seed**, which is the first four bytes of the
        SMC the dump carries. Where nothing patches and nothing replaces it, that means
        the dump's bytes come out unchanged; where an image was replaced or patched, it
        is sealed again under that same seed. Measured on seven images built from a
        plaintext `smc.bin`, all of which carry the dump's seed `fbd75a10`.

        The one reading that looked like an exception was not one: a `xenon` build whose
        image carried a different seed turned out to be a build that never ran -- the
        original stopped at "could not find label [xenonbl] in file list ini" and what
        was read back was the previous build's image, left in the directory. Every build
        that really ran carries the dump's.

        **Two more SMC patches exist and neither is reproduced here.** `smcnoeject` and
        `smcnoblink` each replace a signature, measured in x360mcp along with what the
        original says when the signature is not there. A build that asks for either is
        refused rather than handed an SMC that quietly does not do what was asked.
        """
        plain = self.material.smc
        carried = None
        if plain is None:
            if self.dump is None:
                raise ValueError("this build has neither an smc.bin nor a dump to take "
                                 "an SMC from")
            carried = self.dump.smc
            plain = cipher.opened(carried)
        asked = [name for name in ("smcnoeject", "smcnoblink")
                 if getattr(self.config, name)]
        if asked:
            raise ValueError(
                "%s each patch the SMC at a signature of its own, and neither is "
                "reproduced here yet" % " and ".join(asked)
            )
        if self.config.patchsmc and self.image_type.name != "retail":
            patched = Smc(plain).patched()
            if patched != plain:
                logger.info("patching smc to remove the reset limit")
                plain, carried = patched, None
        if carried is not None:
            return carried
        if not seed:
            if self.dump is None:
                raise ValueError("sealing an SMC needs a seed, and there is no dump to "
                                 "take the console's own from")
            seed = self.dump.smc[:4]
        return cipher.sealed(plain, seed)

    def keyvault(self) -> bytes:
        """The console's keyvault, as the image carries it: sealed under its CPU key.

        `kv.bin` from the per-build directory when there is one, and the dump's own
        otherwise -- "reading data/kv.bin failed, using kv.bin from nand dump". A
        dump's keyvault is already sealed for this console, so it is carried as it
        stands rather than opened and closed again; the derivation is deterministic
        either way, and carrying it means a console whose keyvault this build cannot
        open still gets its own back.

        The original takes a plaintext `kv.bin` as well as a sealed one and says which
        it got; telling them apart is not measured here, so a file is passed through as
        it
        stands, and a build handing over the wrong shape is refused by the console
        rather than by this.
        """
        given = self.material.keyvault
        if given is not None:
            return given
        if self.dump is None:
            raise ValueError("this build has neither a kv.bin nor a dump to take a "
                             "keyvault from")
        return self.dump.sealed_keyvault

    def xell(self) -> bytes | None:
        """The loader, or None for an image type that carries none.

        `xell-gggggg.bin`, verbatim and exactly 0x40000 bytes, which is what every
        image measured carries at 0x70000. The material ships two others --
        `xell-1f.bin` and `xell-2f.bin` -- and which option reaches for them has not
        been measured, so nothing here pretends to choose between them.
        """
        if self.image_type.name == "retail":
            return None
        return self.material.xell("xell-gggggg.bin")

    def patch_slot(self) -> bytes:
        """What goes in the patch slot: one block, and a retail image leaves it erased.

        Sixteen bytes of 0xFF, then the **last** set of the release's patch file as it
        stands, sentinel included, then zeros to the end of the block. Byte-exact on six
        images the original built.

        Two things about which file that set comes from. A `glitch` image on a fat
        console takes it from `patches_fat.bin` while its bootloaders are patched from
        `patches_<board>.bin`: the original's own log says `patches_fat.bin` for every
        fat spelling that builds one -- zephyr, falcon and all six jaspers -- and
        `patches_<board>.bin` for the slim ones, and the bytes agree. A `glitch2`
        image reads the file named after the **family**, so all six jasper spellings
        read `patches_g2jasper.bin`, which is what `Board.section` is.

        And a `glitch2m` image puts a 0x60 prologue in front of the set: twelve fuse
        lines, the console's CPU key with
        each half written twice -- which is measured but not yet understood well enough
        to be produced here, so this refuses that type rather than writing a guess.
        """
        block = layout.BLOCK
        if self.image_type.patches is False:
            return b"\xff" * block
        if self.image_type.name == "glitch2m":
            raise ValueError(
                "a glitch2m patch slot begins with twelve fuse lines, and what fills "
                "two of them is not yet measured for every board"
            )
        patches = self.patches
        if patches is None:
            raise ValueError("this release ships no patch file for a %s %s image"
                             % (self.console.name, self.image_type.name))
        last = patches.set_raw(len(patches.sets) - 1)
        return (b"\xff" * 0x10 + last).ljust(block, b"\x00")

    def chain(self) -> bytes:
        """The bootloader region: the release's stages, patched, bound and sealed.

        The stages ship **in the clear** -- `cbb_9188.bin` and its neighbours are
        plaintext bodies behind a 0x20 header -- and the original seals them itself.
        Held against the chain of every reference image, opened again with its own keys:
        what this lays is what the original laid, byte for byte.

        Five things happen to them, and each was measured by taking a reference image's
        chain apart and putting it back:

        * **The list says which.** `CB` alone, or `CBA` and `CBB` where the chain is
          split, then `CD` and `CE`. CF and CG are on the same list and are not here.
        * **Two patch sets go on**: the first on `CB_B`, the second on `CD`, at offsets
          counted from the start of the stage, header included. A set may make a stage
          longer -- the release's CD is 0x4F20 and comes out 0x5290 -- and then the
          header says the new length, rounded up to `SEAL_ALIGN`, which is where the
          stage behind it begins. A chain with no CB_B takes the second set only, and a
          JTAG chain takes neither: measured, its CB, CD and CE are the release's files
          untouched.
        * **Each nonce is the console's own**, stage for stage, read off the dump's
          chain. Every reference image carries the nonces of the dump it was built from.
          Where there is no dump to read there is nothing to carry, and the original
          draws them -- "initializing random nonces" -- so this draws them too.
        * **CB_B carries the console's block**: the pairing, and the sixteen bytes
          binding it to this SMC, at the start of its body. `chain.Fields` writes them.
        * **Each stage is sealed under its own key**, `chain.sealing` deciding the order
          and, for a retail image on a chain with no CB_B, the second pass under the
          console's key.
        """
        listed = self._chain_files()
        if not listed:
            raise ValueError("this release names no bootloaders for a %s %s image"
                             % (self.console.name, self.image_type.name))
        out, offsets = bytearray(), []
        for index, one in enumerate(listed):
            offsets.append(len(out))
            out += self._stage_body(one, index, len(listed))
        stages = [Stage(out, at) for at in offsets]
        for stage, nonce in zip(stages, self._nonces(stages), strict=True):
            stage.nonce = nonce
        keys = sealing.keys(stages, self.cpu_key or b"", self._second_pass_at(stages))
        binds = sealing.binding_at(stages)
        if binds >= 0:
            # Under the manufacturing regime the original computes no binding, and the
            # CB_B of an image it built that way carries sixteen zeros where the digest
            # would be. The switch is a bit in CB_A rather than the image type or the
            # file's name, which `Stage.manufacturing` reads.
            bound_to = None if stages[0].manufacturing else self.cpu_key
            at = offsets[binds] + STAGE_HEADER
            out[at:at + Fields.LENGTH * 2] = Fields.write(
                self.dump.pairing, bound_to, keys[binds],
                cipher.fingerprint(self.smc()),
            )
        for stage, key in zip(stages, keys, strict=True):
            if key is None:
                raise ValueError(
                    "%s at %#x has no key: the CPU key this chain binds to was not "
                    "given" % (stage.tag, stage.at)
                )
            # Sealed over the padding as well as the body: the stream simply carries
            # on. Measured on the last stage, whose header states less than it fills --
            # the six bytes after CE are that continuation, and x360mcp saw it on a
            # manufacturing image, where CE had moved by 0x20 and the dump's bytes at
            # the same place were something else entirely.
            padded = stage.length + -stage.length % SEAL_ALIGN
            body = bytes(out[stage.at + len(stage.head):stage.at + padded])
            out[stage.at:stage.at + padded] = stage.head + rc4(key, body)
        return bytes(out)

    def _chain_files(self) -> list:
        """The stages of the chain, out of the file list, in the order it names them.

        The list is positional and its slots may be empty: a fat `glitch` image reads
        `[CB, none, CD, CE, CF, CG]`, where `none` is the CB_B such a chain does not
        have. **It runs past the chain, too.** A JTAG list names nine files -- its own
        CB, CD and CE, then a CF/CG pair, then another CB and CD, then the release's own
        CF and CG -- and the chain of the image the original built is the first three:
        CB 5770, CD 5770, CE 1888, while both CF pairs end up in slots. So this keeps
        the chain kinds until CE and stops there, which gives every reference image's
        chain exactly.
        """
        out = []
        for one in self.release.recipe(self.image_type).stages(self.console):
            if one.absent or one.kind not in CHAIN_KINDS:
                continue
            out.append(one)
            if one.kind == "CE":
                break
        return out

    def _stage_body(self, listed, index: int, of: int) -> bytes:
        """One stage in the clear, patched, and as long as its header will say.

        Padding to `SEAL_ALIGN` is part of what is sealed, so it is part of the stage
        rather than a gap between stages.
        """
        body = bytearray(self.release.bootloader(listed))
        which = self._patch_set_for(listed.kind, of)
        if which is not None:
            patches = self.patches
            if patches is not None and which < len(patches.sets):
                ends = max(one.at + one.length for one in patches.sets[which])
                if ends > len(body):
                    body += bytes(ends - len(body))
                body = bytearray(patches.over(bytes(body), which=which))
                Stage(body, 0).length = len(body) + -len(body) % SEAL_ALIGN
        return bytes(body) + bytes(-len(body) % SEAL_ALIGN)

    def _patch_set_for(self, kind: str, of: int):
        """Which set of the release's patch file this kind of stage takes, if any.

        The first set is CB_B's and the second is CD's. A JTAG image patches no stage of
        its chain, which is measured rather than assumed: its CB, CD and CE come out of
        the reference image as the release's files with nothing laid over them.
        """
        if self.image_type.name == "jtag":
            return None
        if kind == "CBB":
            return 0
        return 1 if kind == "CD" else None

    def _second_pass_at(self, stages) -> int:
        """Which stage runs its key through the console's key a second time.

        The original's own test, at 0x41C760: the chain has no CB_B and the image is
        retail. That is the stage behind the single CB, which is its CD.
        """
        if sealing.binding_at(stages) >= 0 or self.image_type.name != "retail":
            return -1
        return 1 if len(stages) > 1 else -1

    def _nonces(self, stages) -> list:
        """One nonce a stage, the console's own where there is a dump to read.

        **Matched by kind and not by position.** A chain with a single CB takes the
        dump's CB, CD and CE nonces and leaves the dump's CB_B out; taking them in order
        instead hands its CD the nonce of a CB_B, which reads as a chain and is not one.
        Measured on a fat glitch image and a JTAG one, both of which carry exactly the
        dump's CB_A, CD and CE nonces.

        A dump with nothing of that kind left to give, and a build with no dump at all,
        leave the original drawing one -- "initializing random nonces" -- so this draws
        one too.
        """
        left = {}
        if self.dump is not None:
            for stage in self.dump.chain.walked:
                left.setdefault(stage.tag, []).append(stage.nonce)
        out = []
        for stage in stages:
            own = left.get(stage.tag) or []
            if own:
                out.append(own.pop(0))
                continue
            logger.info("this dump has no %s nonce left to carry; drawing one",
                        stage.tag)
            out.append(os.urandom(0x10))
        return out

    def slot(self, tail_at: int) -> bytes:
        """The update the console runs after the chain: CF, then CG, both sealed.

        One run of bytes, because CG does not fit and simply carries on: the first
        `layout.SLOT_SPAN` of it are the slot, and the rest is the tail, which lands at
        `tail_at`. The CF has to say where that is, so the caller passes it.

        Taken apart on every reference image and put back, the release's CF and CG come
        out changed in these places and nowhere else:

        * **Both nonces are the console's own**, taken from the dump's CF and the CG
          behind it -- the slot the console's values come from, the one with the
          largest lockdown value. Carried across releases: the dump's CF is 17502, the
          image's is 17559, and they share a nonce.
        * **CF says where the rest of CG is**: a count at 0x30 and then that many
          block numbers, one up from the other. The number is the block's place in the
          flash, not in the filesystem -- 0x34 on a 16 MB image and 0xAE0 on a 64 MB
          one, whose filesystem starts there. x360mcp read the routine that writes it,
          at 0x41C910, after first taking the numbers for versions.
        * **CF carries the console's pairing and lockdown value** at 0x21C, which is
          what `chain.Fields.in_cf` reads -- the pairing only where the chain has a CB_B
          to bind with, zeros otherwise -- and the byte before them says which update
          slot this is: zero, since only a JTAG image has two.
        * **CF carries sixteen bytes binding it to the console**, at 0x220: an HMAC
          under the CPU key over everything before them, with the nonce replaced by the
          key it derives, so the CF is hashed as it will be read. Not the construction
          CB_B's binding uses; J-Runner's `Nand.calcCFhash` spells out the same one.

        Nothing else. CG's plaintext is the release's, byte for byte.
        """
        if self.image_type.name == "jtag":
            raise ValueError(
                "a jtag image carries two update slots and `layout` does not place them"
            )
        if self.dump is None:
            raise ValueError("an update slot carries the console's own values, and "
                             "there is no dump to take them from")
        if not self.cpu_key:
            raise ValueError("a CF binds itself to the console's CPU key, and none was "
                             "given")
        cf_listed, cg_listed = self._update_files()
        cf = bytearray(self.release.bootloader(cf_listed))
        cg = bytearray(self.release.bootloader(cg_listed))
        own_cf = self.dump.chain.slot
        own_cg = Stage(own_cf.image, own_cf.at + own_cf.length)
        Stage(cf, 0).nonce = own_cf.nonce
        Stage(cg, 0).nonce = own_cg.nonce

        spill = len(cf) + len(cg) - layout.SLOT_SPAN
        count = max(0, -(-spill // layout.BLOCK))
        blocks = count.to_bytes(2, "big") + b"".join(
            (tail_at // layout.BLOCK + step).to_bytes(2, "big") for step in range(count)
        )
        cf[0x30:0x68] = blocks.ljust(0x68 - 0x30, b"\x00")
        cf[0x21B] = 0
        # The pairing goes in only where the chain binds to the console. A chain with
        # no CB_B binds nowhere, and its CF carries three zeros there and the lockdown
        # value all the same -- measured on a fat glitch image, the one such chain this
        # release builds beside a slot.
        binds = any(one.kind == "CBB" for one in self._chain_files())
        cf[0x21C:0x21F] = self.dump.pairing if binds else bytes(3)
        cf[0x21F] = self.dump.ldv
        message = bytearray(cf[:0x220])
        message[0x20:0x30] = derive(sealing.ONE_BL_KEY, own_cf.nonce)
        cf[0x220:0x230] = derive(self.cpu_key, bytes(message))

        sealed_cf = sealing.under(Stage(bytes(cf), 0), sealing.ONE_BL_KEY)
        # CG is sealed over its padding too, as every stage is: its tail file is ten
        # bytes longer than CG says it is, and those ten are the stream carrying on.
        cg += bytes(-len(cg) % SEAL_ALIGN)
        head = len(Stage(cg, 0).head)
        key = derive(bytes(cf[0x330:0x340]), own_cg.nonce)
        return sealed_cf + bytes(cg[:head]) + rc4(key, bytes(cg[head:]))

    def _update_files(self) -> tuple:
        """The CF and the CG the file list names, the first of each."""
        found = {}
        for one in self.release.recipe(self.image_type).stages(self.console):
            if one.kind in ("CF", "CG") and one.kind not in found:
                found[one.kind] = one
        if set(found) != {"CF", "CG"}:
            raise ValueError("this release names no CF and CG for a %s %s image"
                             % (self.console.name, self.image_type.name))
        return found["CF"], found["CG"]

    def files(self, when: int) -> list:
        """The files the filesystem holds after the CG's tail, as `(name, bytes)`.

        The release's `[flashfs]` list and then its `[security]` list, each in the
        order it names them -- which is the order of every reference image's table.

        A patch file is written under its name with a `1` after it: `aac.xexp` goes in
        as `aac.xexp1` and `xenonclatin.xttp` as `xenonclatin.xttp1`, all seven of them
        on every image measured. A file the list names outside the release that is not
        there -- `..\\launch.xex` and its two neighbours -- is left out, as the original
        leaves it; its list states a checksum of zero, which is how it says the file is
        optional.
        """
        recipe = self.release.recipe(self.image_type)
        out = []
        for listed in recipe.firmware:
            body = self.release.firmware(listed)
            if body is None:
                if listed.outside:
                    logger.info("%s is not there and is optional", listed.plain)
                    continue
                raise ValueError("%s is named by the file list and the release does "
                                 "not have it" % listed.plain)
            name = listed.plain
            if name.lower().endswith(("xexp", "xttp")):
                name += "1"
            out.append((name, body))
        for listed in recipe.security:
            out.append((listed.plain, self.security_file(listed.plain, when)))
        return out

    def security_file(self, name: str, when: int) -> bytes:
        """One of the five security files, sealed for this console. See `security`."""
        if self.config.nosecurity or self.config.nosusecurity:
            raise ValueError("nosecurity and nosusecurity change where the security "
                             "files come from, and neither is reproduced here yet")
        if self.dump is None or not self.cpu_key:
            raise ValueError("the security files are sealed for a console, and this "
                             "build has no dump or no CPU key to seal them for")
        own = self.dump.image.read(name)
        ldv = self.ldv
        if name in ("crl.bin", "dae.bin"):
            content = own
            if name in self.release.container.held:
                content = self.release.container.read(name)
            sealed = security.crl if name == "crl.bin" else security.dae
            return sealed(content, own, self.cpu_key, when, ldv)
        if name == "extended.bin":
            vault = self.dump.keyvault(self.cpu_key).plain
            return security.extended(own, vault[0x10:0x18], self.cpu_key)
        if name == "secdata.bin":
            return security.secdata(own, self.cpu_key, when, ldv)
        if name == "fcrt.bin":
            given = self.material.fcrt
            return security.fcrt(given if given is not None else own, self.cpu_key)
        raise ValueError("%s is not one of the five security files" % name)

    @property
    def ldv(self) -> int:
        """The lockdown value written into the chain's CF and three security files.

        `cfldv` when it is given, the console's own -- read off its CF -- otherwise.
        """
        if self.config.cfldv is not None:
            return self.config.cfldv
        return self.dump.ldv

    def image(self, when: int | None = None) -> Image:
        """The whole image, every region in its place and every page's spare written.

        `when` is the build's time, which the directory's stamps and three security
        files carry: the clock when nothing says, and a reference build's own when one
        is being reproduced.

        Which pages carry spare follows the rule x360mcp measured over every page of a
        reference build: a page gets it exactly when the build wrote something there.
        Content decides for the regions below the filesystem, since what nothing wrote
        is erased; the files, the settings blobs, the table and the console's settings
        are marked by their spans, because their pages may hold 0xFF all the same.
        """
        when = int(time.time()) if when is None else when
        flash, bigffs = self.console.flash, self.config.bigffs
        out = Image.blank(flash, bigffs)
        base = flash.base_of(bigffs) * layout.BLOCK

        chain = self.chain()
        chain_end = layout.CHAIN_AT + len(chain)
        where = layout.for_type(self.image_type, flash, chain_end, bigffs)
        slots, tail_at = where["slot"][0], where["tail"][0]
        smc = self.smc()
        smc_at = layout.smc_at(len(smc))
        page = self.header(slots, self.ce_version, len(smc))
        # Zeros from the page to the SMC, on every reference image.
        out.put(0, page + bytes(smc_at - len(page)))
        out.put(smc_at, smc)
        out.put(layout.KEYVAULT_AT, self.keyvault())
        # The chain's last block is filled out with zeros, as a file's is.
        out.put(layout.CHAIN_AT, chain + bytes(-chain_end % layout.BLOCK))
        xell = self.xell()
        if xell is not None:
            out.put(layout.XELL_AT, xell)
        run = self.slot(tail_at)
        out.put(slots, run[:layout.SLOT_SPAN])
        spill = run[layout.SLOT_SPAN:]
        out.put(tail_at, spill + bytes(-len(spill) % layout.BLOCK))
        out.put(where["patches"][0], self.patch_slot())
        out.mark_written(0, tail_at)

        first = (tail_at - base) // layout.BLOCK
        fs = Filesystem(flash, first, bigffs)
        stamp = self._fat(when)
        if layout.tail_is_a_file(tail_at, base):
            fs.add("sysupdate.xexp1", spill, stamp=stamp)
        else:
            fs.first = first + -(-len(spill) // layout.BLOCK)
        for name, body in self.files(when):
            fs.add(name, body, stamp=stamp)
        fs.over(out)
        start = flash.offset_of(fs.after, bigffs)
        out.mark(tail_at, start - tail_at)

        per = flash.spare.pages_a_block if flash.spare is not None else 1
        blobs = {} if self.config.nomobile else self._mobiles()
        for index, name in enumerate(sorted(blobs)):
            at = start + index * flash.mobile_stride
            body = blobs[name]
            pages = max(1, len(body) // PAGE)
            free = per - (at // PAGE) % per - pages
            out.put(at, body)
            out.mark(at, pages * PAGE, 1, 0x31 + "BCDE".index(name[6]),
                     bytes([len(body) // 0x100, free, 0, 0]))
        table_at = start + flash.mobile_region
        fs.table_at = (table_at - base) // layout.BLOCK
        table = fs.table()
        out.put(table_at, table)
        out.mark(table_at, len(table), 1, 0x30)

        for at, body, span in self._settings():
            out.put(at, body)
            out.mark(at, span)
        if flash.anchors:
            anchors.lay(out, fs.table_at, {})
        return out

    @staticmethod
    def _fat(when: int) -> int:
        """The build's time as a directory entry keeps it: a FAT date and time.

        In UTC and two seconds on, the same two seconds the security files' stamp
        carries -- the reference images' entries say 15:17:50 where the build began at
        15:17:48 UTC. FAT counts seconds in twos.
        """
        at = time.gmtime(when + 2)
        date = ((at.tm_year - 1980) << 9) | (at.tm_mon << 5) | at.tm_mday
        clock = (at.tm_hour << 11) | (at.tm_min << 5) | (at.tm_sec // 2)
        return (date << 16) | clock

    def _mobiles(self) -> dict:
        """The settings blobs this console carries, by name: the material's first."""
        out = dict(self.material.mobiles)
        if self.dump is not None:
            for name in self.dump.image.blobs:
                if name.startswith("Mobile") and name not in out:
                    out[name] = self.dump.image.blob(name)
        return out

    def _settings(self) -> list:
        """The console's statistics, manufacturing data and settings block, placed.

        As `(where, bytes, how much is marked written)`. Each is given eight pages of
        spare whatever its bytes hold -- measured by x360mcp: the statistics' block at
        0xF78000 carries spare on all eight pages although most of it is 0xFF. With
        `nomobile` the statistics are not written at all, spare included, and
        manufacturing data only when the console has any.
        """
        if self.dump is None:
            return []
        flash = self.console.flash
        span = 0x1000
        stats_at = flash.smc_config - flash.round_to
        out = []
        if self.dump.manufacturing_written:
            out.append((stats_at - flash.round_to, self.dump.manufacturing, span))
        if not self.config.nomobile:
            out.append((stats_at, self.dump.statistics, span))
        config = self.material.smc_config
        if config is None:
            # Where the dump keeps it is the dump's own flash's business, not the one
            # being built for: a 16 MB dump builds a 64 MB image.
            own = self.dump.flash.smc_config
            config = bytes(self.dump.image.flat[own:own + span])
        out.append((flash.smc_config, config, span))
        return out

    @property
    def ce_version(self) -> int:
        """The version word the image's page states, which is CE's own.

        0x0760 for the release measured, and the page of every reference image says the
        same as the CE the release ships.
        """
        for one in self.release.recipe(self.image_type).stages(self.console):
            if one.kind == "CE":
                return Stage(self.release.bootloader(one), 0).build
        raise ValueError("this release names no CE for a %s %s image"
                         % (self.console.name, self.image_type.name))

    @property
    def patches(self):
        """The patch file this build reads, or None for a type that reads none.

        One choice for the whole build, because the chain and the patch slot take their
        sets from the same file. A `glitch` image on a fat console reads
        `patches_fat.bin` rather than the file named after the console -- the original's
        log says so for every fat spelling, and the bytes of both the chain and the slot
        agree.
        """
        fat = self.console.fat and self.image_type.name == "glitch"
        return self.release.patches(self.image_type, "fat" if fat else self.console)

    def header(self, slots: int, ce_version: int, smc_length: int) -> bytes:
        """The image's first page, built from named fields rather than copied.

        Every byte of it is held against the pages of **sixteen images the original
        built**, and all sixteen agree, so a build with no dump to copy a page from
        produces the same page as one with a dump.

        What the caller says is what the page states about things it cannot see from
        here: where the slots begin, the version word -- which is CE's, 0x0760 for the
        release measured -- and how long the SMC is. Where the SMC goes follows from
        that length, because it ends where the keyvault begins; `layout.smc_at` is the
        rule, and a page stating a place that disagrees with the length is what it
        prevents.

        The rest follows from the console and the type:

        * the magic, and the entry point, which is 0x8000 on every image measured
        * the slot offset, **twice**: at 0x0C and again at 0x64
        * the copyright line, whose year is the board's, and a JTAG image carries the
          other year the board has
        * the word at 0x48: one for every hack measured and zero for retail
        * the boot flags at 0x4C -- see `boot_flags`
        * the keyvault, at 0x4000 and 0x4000 long on all sixteen, the two patch slots
          the page counts, and the keyvault's version word
        * the erase block at 0x70, which is the console's own: a falcon image says zero
          where a trinity one says 0x10000
        * nothing at 0x74, which is where a settings block's address would go; every
          image built leaves it zero and the original then goes looking -- "seeking smc
          config in dump...found at offset 0xf7c000"
        """
        head = Header.blank()
        head.version = ce_version
        head.entrypoint = layout.CHAIN_AT
        head.size = slots
        head.cf_at = slots
        year = self.console.notice_year(self.image_type.name)
        head.notice = NOTICE.replace(b"2010", b"%d" % year)
        head.before_flags = 0 if self.image_type.name == "retail" else 1
        head.boot_flags = self.boot_flags()
        head.keyvault_at = layout.KEYVAULT_AT
        head.keyvault_size = layout.KEYVAULT_AT
        head.patch_slots = 2
        head.keyvault_version = 0x0712
        head.block_size = (
            self.console.flash.block_size if self.console.flash.states_block_size else 0
        )
        head.smc_size = smc_length
        head.smc_at = layout.smc_at(smc_length)
        return bytes(head.image)

    def boot_flags(self) -> int:
        """The word at 0x4C, as far as this has measured it.

        Three readings over sixteen images, with every option that reaches these bytes
        left alone: zero for a retail image, 0x12 for a glitch of any kind -- the eject
        button, which is what a console starts XeLL on when nothing says otherwise --
        and 0x40012 for a JTAG one, whose extra bit is a tray-status check.

        Seven options land in these same bytes and none is reproduced here: `xellbutton`
        and `xellbutton2` name the button, `dualboot` is a byte of its own, and `nodvd`,
        `olddvd`, `cygnos` and `demon` each set or clear a bit. What each is worth was
        measured in x360mcp, a build at a time, and reading it across is its own step.
        Until then a build that sets any of them is refused rather than handed an image
        whose start-up is not what was asked for.
        """
        asked = [
            name for name in ("xellbutton2", "dualboot", "nodvd", "olddvd", "cygnos",
                              "demon")
            if getattr(self.config, name)
        ]
        if self.config.xellbutton != "eject":
            asked.append("xellbutton")
        if asked:
            raise ValueError(
                "%s reach the header's boot flags, and which byte each one writes has "
                "not been measured here yet" % ", ".join(sorted(asked))
            )
        if self.image_type.name == "retail":
            return 0
        return 0x40012 if self.image_type.name == "jtag" else 0x12

    def __repr__(self) -> str:
        return "Build(%s, %s)" % (self.image_type.name, self.console.name)
