"""The directory a build is told to look in for this console's own material.

`-f` names a release, which `release.Release` reads. `-d` names this one, and what is in
it belongs to the machine being built for rather than to any release: its dump, its
keyvault, its SMC, its settings block. The original reads nine kinds of file from here
and nothing from anywhere else -- the base directory is not searched and neither is the
release's:

    cpukey.txt  1blkey.txt      the two keys, as text
    options.ini                 settings, which `config.BuildConfig` reads, not this
    nanddump.bin                the console's own flash
    smc.bin  smc_config.bin     an SMC and a settings block to use instead of the dump's
    kv.bin  fcrt.bin            likewise a keyvault and an FCRT
    Mobile*.dat                 settings blobs, four of them
    xell-*.bin                  the loader, chosen by which button starts it

Every one of them is optional. What a build does when one is missing is the build's
business: mostly it falls back to the dump, and the original says so -- "reading
data/kv.bin failed, using kv.bin from nand dump".

**This is the only thing in the package that touches a disk.** Everything above it is
handed bytes, which is what makes the rest testable without a directory to point at.

The two keys have four sources in the order the original states, and only the last is a
refusal: the command line, after which it does not even open the file ("CPU key
overridden from command line, not looking for cpukey.txt"), then the file here, then
`options.ini`, then "you need to specify CPU key!". This reads the file; the command
line and the ini are `config`'s, so putting them in order is the caller's --
`key_in_file` is the middle step and says plainly when there is nothing in it.
"""

import os
import logging

logger = logging.getLogger(__name__)

# The four settings blobs a console keeps, by the name this directory spells them with.
MOBILES = ("MobileB.dat", "MobileC.dat", "MobileD.dat", "MobileE.dat")


class Material:
    """One per-build directory."""

    def __init__(self, where: str):
        if not os.path.isdir(where):
            raise ValueError("%s is not a directory" % where)
        self.where = where
        self._files = {}

    def _beside(self, name: str) -> str | None:
        """That file, found whatever case it is spelled in.

        The original runs where case does not count, and the names in a directory a
        person assembled by hand are not consistent. `release.Release` does the same for
        the same reason, and there it cost 54 bootloaders to find out.
        """
        exact = os.path.join(self.where, name)
        if os.path.isfile(exact):
            return exact
        wanted = name.lower()
        for found in sorted(os.listdir(self.where)):
            if found.lower() == wanted:
                return os.path.join(self.where, found)
        return None

    def bytes_in(self, name: str) -> bytes | None:
        """One file's bytes, or None when this directory does not hold it.

        Read once and kept. A dump here is seventeen megabytes and the things above this
        ask for it more than once, so a property that went to the disk every time would
        be a cost nobody asked for and would say so in the log each time as well.

        An empty file is one this directory does not hold: the original skips it in
        every one of its loaders -- "'data/crl.bin' is a 0 byte file, loading skipped!"
        -- and goes on to the next place, measured with crl.bin, dae.bin and
        extended.bin.
        """
        if name in self._files:
            return self._files[name]
        path = self._beside(name)
        body = None
        if path is not None:
            size = os.path.getsize(path)
            if size:
                logger.info("reading %s (%#x bytes)", path, size)
                with open(path, "rb") as handle:
                    body = handle.read()
            else:
                logger.warning("'%s' is a 0 byte file, loading skipped!", path)
        self._files[name] = body
        return body

    def key_in_file(self, name: str) -> bytes | None:
        """A key from `cpukey.txt` or `1blkey.txt`, or None when there is none to have.

        Sixteen bytes written as hexadecimal, and whitespace around them is ignored: the
        files on this bench end in a newline. Anything else is a refusal rather than a
        shrug -- a key read wrong is a key that seals an image nobody can open.
        """
        if ("key", name) in self._files:
            return self._files[("key", name)]
        path = self._beside(name)
        if path is None:
            self._files[("key", name)] = None
            return None
        logger.info("loading %s from %s", name, path)
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            said = handle.read().split()
        if not said:
            raise ValueError("%s is empty" % path)
        try:
            key = bytes.fromhex(said[0])
        except ValueError:
            raise ValueError(
                "%s holds %r where a key should be" % (path, said[0])
            ) from None
        if len(key) != 16:
            raise ValueError("%s holds %d bytes, and a key is 16" % (path, len(key)))
        # Kept, since a build asks for its key at every step that seals something --
        # and kept as the sixteen bytes read out of the file, not the file's text:
        # the one thing `_files` holds that is not a file's body as it is on disk.
        self._files[("key", name)] = key
        return key

    @property
    def ini(self) -> str | None:
        """Where the settings file is, for whoever reads settings. Not read here."""
        return self._beside("options.ini")

    @property
    def dump(self) -> bytes | None:
        return self.bytes_in("nanddump.bin")

    @property
    def smc(self) -> bytes | None:
        """A plaintext SMC to use instead of the one in the dump."""
        return self.bytes_in("smc.bin")

    @property
    def smc_config(self) -> bytes | None:
        """A settings block, or the slice of a flash tail that holds one.

        The donor files a release ships are the second kind: `Donor Files/Trinity.bin`
        is 0x10000 long and is the last of a real flash from 0xF70000, so the block
        itself is 0xC000 into it. Which is why this hands back what is there and lets
        whatever needs a settings block find it.
        """
        return self.bytes_in("smc_config.bin")

    @property
    def keyvault(self) -> bytes | None:
        """A keyvault, in the clear. The original takes a sealed one too and says so."""
        return self.bytes_in("kv.bin")

    @property
    def fcrt(self) -> bytes | None:
        return self.bytes_in("fcrt.bin")

    @property
    def mobiles(self) -> dict:
        """The settings blobs this directory holds, by name."""
        out = {}
        for name in MOBILES:
            body = self.bytes_in(name)
            if body is not None:
                out[name] = body
        return out

    def xell(self, name: str) -> bytes | None:
        """One loader by name, since which one is a build's choice rather than this
        one's.

        Three are shipped -- `xell-1f.bin`, `xell-2f.bin`, `xell-gggggg.bin` -- and the
        one a build uses follows the button it is to start on.
        """
        return self.bytes_in(name)

    def __repr__(self) -> str:
        return "Material(%s)" % self.where
