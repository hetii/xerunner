"""What kind of image is being built.

Eleven of them, and they are three sorts of thing wearing one switch. `retail` is no
hack at all, the image a console left the factory with. `jtag`, `glitch`, `glitch2` and
`glitch2m` are exploits, differing in how they get a console to run unsigned code.
`devkit` and `testkit` are developer software rather than a hack, and `devgl` is
developer software that also carries the glitch -- which is why it sits on the
development bootloaders and skips the check a retail SMC gets.

The original numbers them internally, and the numbering is the mechanism rather than a
label: its layout routine tests the number, not the name, and three of the eleven share
one number. So what varies between types is derived from the number where the original
derives it, and declared where the original has a table.

Everything here was measured by running the original for each of the eleven and reading
what it reached for.
"""

from ..boards.flash import FlatBigNand


class ImageType:
    """One kind of image, and what a build of it reaches for."""

    name = ""  # what `-t` takes
    number = 0  # the original's own numbering; nine numbers for eleven names
    text = ""  # what the original prints when it starts building one
    short = ""  # the middle of an automatic name: <release>_<short>_<board>.bin
    patches = None  # the prefix in patches_<prefix><board>.bin; False for none at all

    @property
    def list_name(self) -> str:
        """The stem of the file list this type reads: `_<stem>.ini`.

        The type's own name for ten of the eleven. `devgl16` is the exception and says
        so at its own site.
        """
        return self.name

    def file_list(self, ext: str = "") -> str:
        """The file list to read, with the extension `-i` asks for worked in."""
        return "_%s%s.ini" % (self.list_name, "_" + ext if ext else "")

    def patch_file(self, board: str, ext: str = "") -> str | None:
        """The patch file for this type on this board, or None where there is none.

        Measured on the original: `jtag` and `glitch` read `patches_<board>.bin`,
        `glitch2` reads `patches_g2<board>.bin`, and `glitch2m` and `devgl` both read
        `patches_g2m<board>.bin`. `retail` reads none.
        """
        if self.patches is False:
            return None
        if self.patches is None:
            raise ValueError(
                "which patch file %s reads has never been measured: no release carries "
                "a %s, so the original stops before it looks" % (self.name,
                                                                 self.file_list())
            )
        return "patches_%s%s%s.bin" % (self.patches, board.lower(),
                                       "_" + ext if ext else "")

    def image_name(self, release: str, board: str) -> str:
        """The name a build takes when the command line gives none."""
        return "%s_%s_%s.bin" % (release, self.short, str(board).lower())

    @property
    def asks_dual_cb(self) -> bool:
        """Whether the build asks the chain whether its CB is split in two.

        Numbers 1, 3, 4 and 5 ask -- retail, the glitches and both devgl. A JTAG image
        and the developer kits do not.
        """
        return self.number in (1, 3, 4, 5)

    @property
    def checks_smc(self) -> bool:
        """Whether an SMC is held to the checks a build otherwise makes of it.

        Both devgl types are exempt, which is the original's own test on 4 and 5.
        """
        return self.number not in (4, 5)

    def shape(self, console, bigffs: bool = False) -> tuple:
        """The flash an image of this type is laid on, and whether with the larger
        filesystem.

        The board's own for every type but `devkit` and `testkit` -- numbers 6 and 8 --
        which take 64 MB whatever board they are built for: `FlatBigNand` on a small
        block console, and a big block console's own shape with the larger filesystem.
        Measured on 17489 devkit images: falcon, xenon and jasper come out 64 MB with
        their files from 0xF4000, and jasperbb's says "extended size FFS". The `16` in
        `devkit16` and `testkit16` is exactly this not happening.
        """
        flash = console.flash
        if self.number not in (6, 8) or flash.spare is None:
            return flash, bigffs
        if flash.bigffs_base is not None:
            return flash, True
        return FlatBigNand(flash.spare), False

    def __repr__(self) -> str:
        return "%s(%r)" % (type(self).__name__, self.name)
