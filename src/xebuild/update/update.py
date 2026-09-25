"""Collecting a console's own things over its update server, and the update itself."""

from __future__ import annotations

import logging
import os
from types import SimpleNamespace

from ..build import Build, layout, security
from ..build.build import SEAL_ALIGN
from ..chain import Chain
from ..client.client import fuses_txt, options_ini
from ..client.sysdata import send_avatars
from ..config import BuildConfig
from ..crypto import smc as cipher
from ..image import Header, Image, Keyvault
from ..image.settings import SmcConfig
from ..network import ConsoleInfo, Server, find
from ..network.info import PUBLIC_KEYS
from ..network.updsrv import PORT
from ..release import Release
from .material import ConsoleMaterial

logger = logging.getLogger(__name__)

# The security files, in the order the original asks for them.
SECURITY = ("crl.bin", "dae.bin", "extended.bin", "fcrt.bin", "secdata.bin")


class BuildUpdate(Build):
    """A build as update mode makes it, from a `ConsoleMaterial`: what the console
    itself holds comes from what it handed over rather than from a dump, and the
    image's head is the console's own, laid as it stands.
    """

    @property
    def console_keyvault(self) -> bytes:
        """Out of the bootloaders it handed over; its extended.bin head is this one's,
        measured on an update image, as a dump's is."""
        return self.material.keyvault

    def console_file(self, name: str) -> bytes | None:
        """Its copy, read over its update server -- "retrieving USVR\\crl.bin...OK"."""
        return self.material.files.get(name.lower())

    def console_firmware(self, name: str, crc: int) -> bytes | None:
        """Its copy counts with no checksum too, where a dump's does not: the original
        takes the console's (0x42875F) -- measured, `launch.xex` off the console when
        the base directory has none, and the base directory's when it has one."""
        body = self.console_file(name)
        return body if self._firmware_fits(body, name, crc) else None

    @property
    def console_statistics(self) -> bytes | None:
        """0x400 bytes, laid at the head of its block. What the original leaves in the
        rest of the block is not 0xFF and not anything it was handed -- repeatable, but
        its source is not found (see update's notes); this leaves it erased."""
        return self.material.statistics or None

    @property
    def console_manufacturing(self) -> bytes | None:
        """0x80 bytes, laid the same way."""
        return self.material.manufacturing or None

    def _head_extent(self) -> tuple:
        """The console's own head ends at its CE, rounded up to 0x10 -- "final
        truncated bootloader size 0x6c5c0" -- and there is no chain of the release's.
        Refused where the stages are not a chain a build can carry: "bootloaders
        retrieved from console are inconsistent, cannot proceed!" (0x42EC6C), which an
        RGH3 console gets."""
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
        behind them to the end of the block."""
        out.put(0, self.material.bootloaders[:chain_end]
                + bytes(-chain_end % layout.BLOCK))


def collect(server, info: ConsoleInfo, recipe, base: str,
            clean: bool = False) -> ConsoleMaterial:
    """Everything a build takes from the console, asked for in the original's order:
    the flash header, the bad blocks, the system partition mounted as `usv:`, the
    bootloaders, the security files, the settings blobs B to J, the statistics,
    manufacturing data and settings, then each firmware file the release leaves to the
    console -- a base file whose patch the list names, and the ones outside the
    release -- and the partition unmounted. `clean` leaves secdata, extended and the
    statistics on the console, as `-clean` says.
    """
    server.file("flash_hdr")
    server.bad_blocks()
    server.mount("usv", "\\SystemRoot")
    found = ConsoleMaterial(base, server.bootloaders())
    for name in SECURITY:
        if clean and name in ("extended.bin", "secdata.bin"):
            continue
        body = server.file("usv:\\%s" % name)
        if body:
            found.files[name] = body
    for letter in "BCDEFGHIJ":
        body = server.file("usv:\\Mobile%s.dat" % letter)
        if body:
            found.blobs["Mobile%s.dat" % letter] = body
    if not clean:
        found.statistics = server.file("usv:\\Statistics.settings")
    found.manufacturing = server.file("usv:\\Manufacturing.data")
    found.settings = server.file("usv:\\Static.settings")
    names = {one.plain.lower() for one in recipe.firmware}
    for listed in recipe.firmware:
        if listed.outside or listed.plain.lower() + "p" in names:
            body = server.file("usv:\\%s" % listed.plain)
            if body:
                found.files[listed.plain.lower()] = body
    server.unmount("usv")
    return found


def run_update(config, port: int = PORT, when: int | None = None) -> str | None:
    """The whole update: collect, build, and unless `no_write` send the image, the
    avatar data where there is some and a hard disk to put it on, and reboot. Returns
    where the image was kept, which is only with a `dump_to`. `when` is the build's
    clock, as build mode's is, for reproducing one."""
    address = config.address or find()
    release = Release(config.data or "data")
    with Server(address, port) as server:
        info = ConsoleInfo(server.info())
        board, hack = info.image_type
        kind = {"JTAG": "jtag", "Glitch2": "glitch2", "Glitch": "glitch",
                "Glitch-FAT": "glitch", "Glitch2M": "glitch2m", "": "retail"}[hack]
        settings = BuildConfig(
            image_type=kind, console=board.lower(), no_random=True, cfldv=info.ldv,
            cpu_key=info.cpu_key.hex(), one_bl_key=info.one_bl_key.hex(),
            firmware_ext=config.firmware_ext, section_ext=config.section_ext,
            append=config.append)
        build = BuildUpdate(settings, None, release)
        material = collect(server, info, build.recipe,
                           os.path.dirname(os.path.abspath(config.data or "data")),
                           config.clean)
        build.material = material
        image = build.image(when)
        name = build.auto_name()
        kept = None
        if config.dump_to:
            os.makedirs(config.dump_to, exist_ok=True)
            flash = server.flash()
            kept = os.path.join(config.dump_to, name)
            _keep(config.dump_to, info, material, flash, image.raw, name)
        if not config.no_write:
            server.write_flash(image.raw)
        if config.no_write or config.no_avatar:
            logger.info("avatar data skipped, -noava or -nowrite used")
        elif not info.hdd:
            logger.info("avatar data skipped, no HDD detected")
        else:
            # From a system update in the release's directory, as `client -e` sends
            # one; one that is not there, or not whole, is passed over and the update
            # goes on to its reboot, as the original's does (0x404E05).
            try:
                send_avatars(server, config.data or "data", info.word(4))
            except ValueError as why:
                logger.warning("%s", why)
        if not config.no_write and not config.no_reboot:
            server.reboot()
        else:
            # The original hangs up without a QUIT in update mode -- measured with
            # `-nowrite -noreeb`: the stand-in saw the connection close after GTFL.
            server.hung_up = True
    return kept


def _keep(where: str, info: ConsoleInfo, material: ConsoleMaterial, flash: bytes,
          image: bytes, name: str) -> None:
    """What `-d` keeps, as the original keeps it: the image, the console's flash and
    bootloaders as read, its keyvault and SMC opened, its security files opened, its
    settings blobs and settings, the fuses, the public keys and an options.ini --
    enough for build mode to build from later."""
    cpu = info.cpu_key
    out = {name: image, "nanddump.bin": flash, "fbldrs.bin": material.bootloaders,
           "kv.bin": Keyvault.opened(material.keyvault, cpu).plain,
           "smc.bin": cipher.opened(material.smc)}
    for file in SECURITY:
        if file in material.files:
            out[file] = security.opened_copy(file, material.files[file], cpu)
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
    header = material.bootloaders[:0x200]
    with open(os.path.join(where, "options.ini"), "w", newline="\n") as handle:
        handle.write(options_ini(info, header))
