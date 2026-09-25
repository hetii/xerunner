"""What a running console hands over, as a build's material."""

from ..build.material import Material


class ConsoleMaterial(Material):
    """A running console as a build's material: what a directory answers, answered
    from what the console handed over.

    `bootloaders` is its first 0xB0000 bytes, `GTBL` -- header, SMC, keyvault and the
    chain. `files` are its own copies of the security and firmware files, by name in
    lower case; `blobs` its settings blobs; `settings`, `statistics` and
    `manufacturing` its three settings files. The directory underneath is the one
    beside the release, where the original looks for the loader in this mode --
    "could not read xell-gggggg.bin" otherwise -- and nothing else is read from it: no
    dump, no keys, no files handed in beside the build.
    """

    def __init__(self, base: str, bootloaders: bytes):
        super().__init__(base)
        self.bootloaders = bootloaders
        self.files = {}
        self.blobs = {}
        self.settings = None
        self.statistics = None
        self.manufacturing = None

    def bytes_in(self, _name: str) -> None:
        """Nothing is handed over beside the build."""
        return None

    def key_in_file(self, _name: str) -> None:
        """The keys come from the console's info, not a file."""
        return None

    @property
    def ini(self) -> None:
        return None

    @property
    def keyvault(self) -> bytes:
        """Sealed, where the header says -- "extracting BLDR\\kv_enc"."""
        at = int.from_bytes(self.bootloaders[0x6C:0x70], "big")
        return self.bootloaders[at:at + 0x4000]

    @property
    def smc(self) -> bytes:
        """Sealed, where the header says -- "extracting BLDR\\smc_enc"."""
        at = int.from_bytes(self.bootloaders[0x7C:0x80], "big")
        length = int.from_bytes(self.bootloaders[0x78:0x7C], "big")
        return self.bootloaders[at:at + length]

    @property
    def smc_config(self) -> bytes | None:
        """`Static.settings` off the console."""
        return self.settings

    @property
    def mobiles(self) -> dict:
        return dict(self.blobs)

    def xell(self, name: str) -> bytes | None:
        # Read through the directory underneath, which `bytes_in` here does not do.
        return super().bytes_in(name)
