"""Collecting a console's own things over its update server, and the update itself."""

import os
import logging

from ..chain import Chain
from ..crypto import formats
from ..config import BuildConfig
from ..build import Build, layout
from ..network.updsrv import PORT
from types import SimpleNamespace
from ..build.build import SEAL_ALIGN
from ..release import Release, addons
from .material import ConsoleMaterial
from ..network.info import PUBLIC_KEYS
from ..crypto.formats import decrypt_smc
from ..client.sysdata import send_avatars
from ..image import Header, Image, Keyvault
from ..image.settings import SmcConfig, sums
from ..network import ConsoleInfo, Server, find
from ..client.client import fuses_txt, options_ini

logger = logging.getLogger(__name__)

# The security files, in the order the original asks for them.
SECURITY = ("crl.bin", "dae.bin", "extended.bin", "fcrt.bin", "secdata.bin")


class BuildUpdate(Build):
    """A build as update mode makes it, from a `ConsoleMaterial`: what the console
    itself holds comes from what it handed over rather than from a dump, and the
    image's head is the console's own, laid as it stands.
    """

    @property
    def _console_keyvault(self) -> bytes:
        """Out of the bootloaders it handed over; its extended.bin head is this one's,
        measured on an update image, as a dump's is."""
        return self.material.keyvault

    @property
    def _walk(self) -> tuple:
        """The nonces the console's info names, and nothing drawn: update mode clears
        the original's random flag (0x4318E0) and fills the stage buffers from the
        info, where a build reads them off a dump."""
        return self.material.nonces, False

    @property
    def pairing(self) -> bytes:
        """The pairing the console's info names (0x41ADE0) -- "pairing set to: 5a 7c
        31" -- and a build's where it names none, which with no dump is the static one:
        measured on the original against a stand-in console saying JTAG, both ways."""
        if self.zero_paired or not self.material.pairing:
            return super().pairing
        return self.material.pairing.to_bytes(3, "big")

    @property
    def _console_smc(self) -> bytes:
        """As it handed it over, which `collect` has made sure opens; the seal takes
        its four as a dump's are taken (0x4042C9) -- measured on a JTAG update, whose
        head is a build's."""
        return self.material.smc

    def _console_file(self, name: str) -> bytes | None:
        """Its copy, read over its update server -- "retrieving USVR\\crl.bin...OK"."""
        return self.material.files.get(name.lower())

    def _console_firmware(self, name: str, crc: int) -> bytes | None:
        """Its copy, asked for over `usv:` only now -- where a build would read the
        dump, after the release's directory and its container had no copy that fits
        (0x428194, 0x404600) -- so a release that holds its own files, as 6717 does,
        asks the console for none of them: measured, the original's wire with 6717
        has no firmware on it at all.

        It counts with no checksum too, where a dump's does not: the original takes
        the console's (0x42875F) -- measured, `launch.xex` off the console when the
        base directory has none, and the base directory's when it has one."""
        body = self.server.file("usv:\\%s" % name)
        return body if self._firmware_fits(body, name, crc) else None

    @property
    def _console_statistics(self) -> bytes | None:
        """0x400 bytes, laid at the head of its 0x1000 block, the rest left erased.

        A deliberate divergence. The original copies the file into a 0x1000 buffer it
        never clears and writes the whole buffer, so the rest of the block is whatever
        its heap last held: across eight recorded runs, eight different tails, among
        them a run of 0x36 -- an HMAC pad -- and pointers and sizes; 0xFF where
        `-clean` left the file unfetched. Nothing a console handed over, nothing it
        reads, and not reproducible; the console keeps more of its own there, which
        update mode is never given, so erased flash is what this can honestly write.
        """
        return self.material.statistics or None

    @property
    def _console_manufacturing(self) -> bytes | None:
        """0x80 bytes, laid the same way and for the same reason: the original's tail
        here held the text of the release's file list it had read earlier -- "[zephyrbl]
        cb_4578.bin,7dce10bf" and on -- and every console dump here has 0xFF there."""
        return self.material.manufacturing or None

    def _head_extent(self) -> tuple:
        """The console's own head ends at its CE, rounded up to 0x10 -- "final
        truncated bootloader size 0x6c5c0" -- and there is no chain of the release's.
        Refused where the stages are not a chain a build can carry: "bootloaders
        retrieved from console are inconsistent, cannot proceed!" (0x42EC6C), which an
        RGH3 console gets.

        A JTAG console hands over no bootloaders, and its head is a build's."""
        if self.material.bootloaders is None:
            return super()._head_extent()
        console = self.material.bootloaders
        found = Chain(SimpleNamespace(flat=console, header=Header(console[:0x200])),
                      self.console)
        if not found.positional()[1]:
            raise ValueError("bootloaders retrieved from console are inconsistent, "
                             "cannot proceed!")
        last = found.walked[-1]
        end = last.at + last.length
        end += -end % SEAL_ALIGN
        return None, end, b"", end

    def _head_lay(self, out: Image, slots: int, chain, chain_end: int) -> None:
        """The console's first bytes as it holds them -- header, SMC, keyvault and
        chain to the end of its CE; measured, the original's image carries GTBL's bytes
        to 0x6C5C0 exactly, even the sixteen this console keeps at 0x6D0 -- and zeros
        behind them to the end of the block. A JTAG console's head is a build's."""
        if self.material.bootloaders is None:
            super()._head_lay(out, slots, chain, chain_end)
            return
        out.put(0, self.material.bootloaders[:chain_end]
                + bytes(-chain_end % layout.BLOCK))


def collect(server, info: ConsoleInfo, recipe, base: str,
            clean: bool = False, append: tuple = ()) -> ConsoleMaterial:
    """Everything a build takes from the console, asked for in the original's order:
    the flash header, the bad blocks, the system partition mounted as `usv:`, the
    bootloaders, the security files, the settings blobs B to J, the statistics,
    manufacturing data and settings. `usv:` is left mounted: the firmware files are
    asked for by the build, one at a time as it needs them -- see
    `BuildUpdate._console_firmware` -- and the partition is unmounted after it.
    `clean` leaves secdata, extended and the statistics on the console, as `-clean`
    says.

    **Only a glitch console hands over its bootloaders** (0x404357): a JTAG one is not
    asked -- "Skipping getting bootloaders on non-glitch machine!" -- and its image is
    laid from the release's chain as build mode lays one. Its keyvault and SMC are
    asked for on their own instead, `kv_enc` and `smc_enc` behind the security files,
    and the security files are the ones its type's list names, which for JTAG leaves
    out fcrt.bin. Measured on the original against a stand-in console saying JTAG.
    """
    header = server.file("flash_hdr")
    server.bad_blocks()
    server.mount("usv", "\\SystemRoot")
    jtag = info.image_type[1] == "JTAG"
    if jtag:
        logger.debug("Skipping getting bootloaders on non-glitch machine!")
    found = ConsoleMaterial(base, None if jtag else server.bootloaders())
    found.flash_header = header
    found.nonces = info.nonces
    found.pairing = info.pairing
    if found.pairing:
        logger.debug("pairing set to: %s", found.pairing.to_bytes(3, "big").hex(" "))
    for name in (one.plain for one in recipe.security):
        if clean and name in ("extended.bin", "secdata.bin"):
            continue
        body = server.file("usv:\\%s" % name)
        if body:
            found.files[name] = body
    if jtag:
        found.sealed_keyvault = server.file("kv_enc")
        if not found.sealed_keyvault:
            raise ValueError("could not retrieve keyvault from console!")
        found.sealed_smc = server.file("smc_enc")
        if not found.sealed_smc:
            raise ValueError("could not retrieve smc.bin from console!")
    for letter in "BCDEFGHIJ":
        body = server.file("usv:\\Mobile%s.dat" % letter)
        if body:
            found.blobs["Mobile%s.dat" % letter] = body
    if not clean:
        found.statistics = server.file("usv:\\Statistics.settings")
    found.manufacturing = server.file("usv:\\Manufacturing.data")
    # Then what only a server that offers them hands over, each asked for where the
    # original asks (0x4039BA, 0x403BE4) -- measured on a stand-in console with the
    # two bits set in its answer to GTIN.
    if not info.offers_blmod:
        logger.debug("console has no available blmod")
    elif server.file("blmod") is None:
        logger.warning("Unable to retrieve blmod.bin data from console!")
    # Asked for and not used: it goes on a chain a build lays, and an update lays none
    # of its own but puts the console's bootloaders back as they came, which the
    # original does too -- measured, "Adding ... blmod.bin data" is never said.
    if not info.offers_addons:
        logger.debug("console has no available addons")
    elif append:
        logger.info("skipping USVR\\addons, addons have been specified on command "
                    "line")
    else:
        body = server.file("addons")
        if body is None:
            logger.warning("Unable to retrieve addons.bin from console!")
        elif len(body) % 4:
            logger.warning("addons.bin from console is not a multiple of 4 bytes! "
                           "Skipping!")
        else:
            # The index of the release the console runs, beside the base directory
            # (0x403772: ".\\%d\\bin\\addon.idx"), not of the one being built.
            path = os.path.join(base, info.kernel.split(".")[2], "bin", "addon.idx")
            try:
                with open(path, "rb") as handle:
                    table = handle.read()
            except OSError:
                logger.warning("unable to open %s to parse addons.bin from console!",
                               path)
            else:
                found.addons = tuple(addons.named(addons.index(table), body))
                for name in found.addons:
                    logger.info("addon patch from console: %s", name)
    found.settings = server.file("usv:\\Static.settings")
    # What the original asks of the two before it goes on, and neither is waived by
    # `smcnocheck` -- read out of it (0x403B2F, 0x40426B), not measured: no console
    # here hands over a broken one. The SMC at least 0x3000 and opening to the four
    # zeros every SMC ends with; the settings block at least 0x400 and sound where it
    # starts, of which the 0x400 are kept.
    smc = found.smc
    if len(smc) < 0x3000:
        raise ValueError("could not retrieve smc.bin from console")
    if decrypt_smc(smc)[-4:] != bytes(4):
        raise ValueError("could not decrypt smc.bin from console")
    if found.settings is None or len(found.settings) < 0x400 \
            or not sums(found.settings):
        raise ValueError("could not retrieve smc_config from console")
    found.settings = found.settings[:0x400]
    return found


def run_update(config, port: int = PORT, when: int | None = None) -> str | None:
    """The whole update: collect, build, and unless `no_write` send the image, the
    avatar data where there is some and a hard disk to put it on, and reboot. Returns
    where the image was kept, which is only with a `dump_to`. `when` is the build's
    clock, as build mode's is, for reproducing one."""
    address = config.address or find()
    with Server(address, port) as server:
        # The original hangs up without a QUIT in update mode, whether it finishes or
        # stops -- measured with `-nowrite -noreeb`, where the stand-in saw the
        # connection close after GTFL, and on a refusal after GTIN.
        server.hung_up = True
        info = ConsoleInfo(server.info())
        # Checked before anything else is asked (0x431A9E), the peek version first --
        # measured on the original against a stand-in console saying older ones.
        version, peek = info.server_version
        if peek <= 1:
            raise ValueError("console hv patches are not recent enough to support "
                             "update mode! update console patches and reboot before "
                             "trying again.")
        if version < 3:
            raise ValueError("updsvr on console needs to be updated!")
        board, hack = info.image_type
        kind = {"JTAG": "jtag", "Glitch2": "glitch2", "Glitch": "glitch",
                "Glitch-FAT": "glitch", "Glitch2M": "glitch2m", "": "retail"}[hack]
        # The stages are checked under the console's own 1BL public key, where it is
        # good: "1BL RSA pub : good", then "loaded cb_5770.bin, signature check
        # passed!" in a recording with no 1BL_pub.bin anywhere.
        _name, _file, at, _wanted = PUBLIC_KEYS[0]
        settings = BuildConfig(
            image_type=kind, console=board.lower(), no_random=True, cfldv=info.ldv,
            cpu_key=info.cpu_key.hex(), one_bl_key=info.one_bl_key.hex(),
            one_bl_pub=info.public_key(at) if info.key_checks()["1BL"] else None,
            firmware_ext=config.firmware_ext, section_ext=config.section_ext,
            append=config.append)
        release = Release(config.data or "data", one_bl_key=settings.one_bl_key,
                          one_bl_pub=settings.one_bl_pub)
        build = BuildUpdate(settings, None, release)
        material = collect(server, info, build.recipe,
                           os.path.dirname(os.path.abspath(config.data or "data")),
                           config.clean, config.append)
        build.material = material
        build.server = server
        # The console's own addons go back in as `-a` would put them (0x428CBD):
        # "patches now 0x948 bytes total with addon byte count appended".
        if material.addons:
            build.config.append = material.addons
        image = build.image(when)
        server.unmount("usv")
        name = build.auto_name()
        kept = None
        if config.dump_to:
            os.makedirs(config.dump_to, exist_ok=True)
            flash = server.flash()
            kept = os.path.join(config.dump_to, name)
            _keep(config.dump_to, info, material, flash, image.raw, name,
                  settings.xex_key)
        if not config.no_write:
            server.write_flash(image.raw)
        if config.no_write or config.no_avatar:
            logger.debug("avatar data skipped, -noava or -nowrite used")
        elif not info.hdd:
            logger.info("avatar data skipped, no HDD detected")
        else:
            # From a system update in the release's directory, as `client -e` sends
            # one; one that is not there, or not whole, is passed over and the update
            # goes on to its reboot, as the original's does (0x404E05).
            try:
                send_avatars(server, config.data or "data", info.word(4))
            except ValueError as why:
                logger.error("%s", why)
        if not config.no_write and not config.no_reboot:
            server.reboot()
    return kept


def decrypt_securityfile(name: str, blob: bytes, cpu_key: bytes,
                         xex_key: bytes) -> bytes:
    """A console's security file in the clear, headers as they were, as `-d` keeps it
    for build mode to take up later -- each measured against the original's copy:
    crl.bin with its file key unwrapped at 0x130, each dae.bin record opened,
    extended.bin and secdata.bin behind their nonce, fcrt.bin behind its 0x140 bytes of
    header."""
    if name == "crl.bin":
        body, _master, file_key = formats.decrypt_crl(blob, cpu_key, xex_key)
        return blob[:formats.WRAPPED_KEY_AT] + file_key + body
    if name == "dae.bin":
        records = formats.decrypt_dae(blob, cpu_key, xex_key)
        return b"".join(header + body for header, body, _master in records)
    if name == "extended.bin":
        return blob[:formats.NONCE_LENGTH] + formats.decrypt_extended(blob, cpu_key)
    if name == "secdata.bin":
        return blob[:formats.NONCE_LENGTH] + formats.decrypt_secdata(blob, cpu_key)
    if name == "fcrt.bin":
        return blob[:formats.fcrt_body_at(blob)] + formats.decrypt_fcrt(blob, cpu_key)
    return blob


def _keep(where: str, info: ConsoleInfo, material: ConsoleMaterial, flash: bytes,
          image: bytes, name: str, xex_key: bytes) -> None:
    """What `-d` keeps, as the original keeps it: the image, the console's flash and
    bootloaders as read, its keyvault and SMC opened, its security files opened, its
    settings blobs and settings, the fuses, the public keys and an options.ini --
    enough for build mode to build from later."""
    cpu = info.cpu_key
    out = {name: image, "nanddump.bin": flash,
           "kv.bin": Keyvault.opened(material.keyvault, cpu).plain,
           "smc.bin": decrypt_smc(material.smc)}
    # A JTAG console handed over no bootloaders, and none are kept -- measured.
    if material.bootloaders is not None:
        out["fbldrs.bin"] = material.bootloaders
    for file in SECURITY:
        if file in material.files:
            out[file] = decrypt_securityfile(file, material.files[file], cpu,
                                             xex_key)
    out.update(material.mobiles)
    if material.statistics is not None:
        out["Statistics.settings"] = material.statistics
    if material.manufacturing is not None:
        out["Manufacturing.data"] = material.manufacturing
    found = SmcConfig.found_in(material.smc_config or b"")
    if found is not None:
        out["smc_config.bin"] = bytes(found.block)
    for _name, file, at, _wanted in PUBLIC_KEYS:
        out[file] = info.public_key(at)
    for file, body in out.items():
        with open(os.path.join(where, file), "wb") as handle:
            handle.write(body)
    with open(os.path.join(where, "fuses.txt"), "w", newline="\n") as handle:
        handle.write(fuses_txt(info))
    header = material.flash_header[:0x200]
    with open(os.path.join(where, "options.ini"), "w", newline="\n") as handle:
        handle.write(options_ini(info, header))
