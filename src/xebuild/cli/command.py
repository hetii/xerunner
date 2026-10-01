"""xeBuild's command line, and what each switch sets: build mode's here, and the other
three modes' further down, each with its own switches.

Every mode's switches are read by argparse, which also prints each mode's help for `-?`
and refuses a switch it does not know, or one short of its words. The descriptions of
the switches, the examples and the legends are the original's words; the layout around
them is argparse's.

    xeBuild [mode] -t <type> [<switch> [<switch>...]] <out.bin>

The mode is optional and build is the default. `-s` is the one switch whose word is
optional. `-o`, `-a` and `-8` may be given more than once, and one `-o` may carry
several settings separated by `;`, each `name` alone meaning true. The first word
without a switch names the image; a later one is passed over with a warning. `-v1`,
`-v2` and `-v0` are taken for `-v`, so a J-Runner that asks for a level still runs.

The per-build directory's `options.ini` is read first and the command line goes over it,
which is the order `BuildConfig` keeps; with no `-d` that directory is `./data/`, as
the original warns.
"""

import os
import sys
import time
import logging
import argparse

from ..ini import write_su_ini
from ..client import run_client
from ..update import run_update
from ..network import ServerError
from ..extract import extract_image
from ..build import Material, build_image
from ..config.options import OptionsConfig
from ..config import BuildConfig, ClientConfig, ExtractConfig, IniConfig, \
    UpdateConfig

logger = logging.getLogger(__name__)


class LogFormatter(logging.Formatter):
    """Every line as `[ 15:45:28 ] (w): message`, the level by its first letter. On a
    terminal the brackets and parentheses are light yellow, the time light green, and
    the letter and the message the level's own colour; in a file or a pipe there is no
    colour at all."""

    def __init__(self, colour: bool):
        super().__init__("%(stamp)s %(text)s")
        self.colour = colour

    def format(self, record) -> str:
        when = self.formatTime(record, "%H:%M:%S")
        letter, said = record.levelname[0].lower(), record.getMessage()
        if self.colour:
            shade = {"DEBUG": "\033[2m", "INFO": "\033[32m", "WARNING": "\033[33m",
                     "ERROR": "\033[31m", "CRITICAL": "\033[1;31m"}
            level = shade.get(record.levelname, "")
            record.stamp = ("\033[93m[\033[0m \033[92m%s\033[0m \033[93m] (\033[0m"
                            "%s%s\033[0m\033[93m):\033[0m" % (when, level, letter))
            record.text = "%s%s\033[0m" % (level, said)
        else:
            record.stamp, record.text = "[ %s ] (%s):" % (when, letter), said
        return super().format(record)


def main(argv=None) -> int:
    """Any mode from a command line; the exit status the shell gets back."""
    # The tool runs from where it is, not from where it was called: the original takes
    # every relative name against the directory its own file is in, measured on the
    # original under wine with the caller in a directory of its own, handed `-d data`
    # and `-f 17559` as bare names, and finding the release and the data directory
    # beside the exe. Nothing else anchors a path here, so this is where it happens.
    os.chdir(os.path.dirname(os.path.abspath(sys.argv[0])))
    argv = sys.argv[1:] if argv is None else argv
    # INFO for every mode, before any switch is read -- some say things themselves;
    # `-v` then takes it a level down, to what the original shows only with it.
    handler = logging.StreamHandler()
    handler.setFormatter(LogFormatter(handler.stream.isatty()))
    logging.basicConfig(level=logging.INFO, handlers=[handler])
    mode = argv[0] if argv[:1] and argv[0] in ("build", "extract", "client", "update",
                                                "ini") else "build"
    rest = argv[1:] if argv[:1] == [mode] else argv
    parse_mode = {"build": parse_build, "client": parse_client, "update": parse_update,
                  "extract": parse_extract, "ini": parse_ini}[mode]
    # Help, and a line argparse refuses, end the program inside the parse; from here
    # on it is a run.
    settings = parse_mode(rest)
    logger.info("started %s", time.strftime("%Y-%m-%d %H:%M:%S"))
    logger.info("cmd: %s", " ".join([os.path.basename(sys.argv[0]), *argv]))
    run = {"build": _build, "client": _client, "update": _update, "extract": _extract,
           "ini": _ini}[mode]
    return run(settings)


def _parser(prog: str, example: str, legend: str = "") -> argparse.ArgumentParser:
    """A mode's argparse: its own `-?` for help, the original's examples above the
    switches and its legend below them, both as written, and no abbreviated switches,
    which the original does not take."""
    parser = argparse.ArgumentParser(
        prog=prog, description=example, epilog=legend or None, add_help=False,
        allow_abbrev=False, formatter_class=argparse.RawTextHelpFormatter)
    return parser


def _verbose(parser: argparse.ArgumentParser, process: str) -> None:
    """`-v`, and `-v0`, `-v1`, `-v2` taken for it without being listed."""
    parser.add_argument("-v", dest="verbose", action="store_true",
                        help="shows more info during %s process" % process)
    parser.add_argument("-v0", "-v1", "-v2", dest="verbose", action="store_true",
                        help=argparse.SUPPRESS)


def _options(text: str) -> dict:
    """One `-o`'s settings: `name` or `name=value`, several separated by `;`.

    Only the thirty-one options are reachable this way; a switch's own setting is not
    an option, and a name that is not one is refused.
    """
    known = {name for name, door in vars(OptionsConfig).items()
             if isinstance(door, property)}
    out = {}
    for piece in text.split(";"):
        name, sign, value = piece.strip().partition("=")
        name = name.strip().lower()
        if not name:
            continue
        if name not in known:
            raise ValueError("%s is not an option" % name)
        out[name] = value.strip() if sign else True
    return out


def parse_build(argv) -> dict:
    """`BuildConfig`'s settings, by its own names, from build mode's switches."""
    parser = _parser("xeBuild", """\
examples:
   xeBuild [mode] -t <type> [<switch> [<switch>...]] <out.bin>
   xeBuild -t retail -c trinity -d files -b 0102...0f -p 0102...0f out.bin""", """\
legend:
[mode]      : build, extract, client, update - defaults to build if not present
<con>       = xenon, zephyr, falcon, jasper, jaspersb, jasper256,
              jasper512, jasperbb, jasperbigffs, trinity, trinitybb, trinitybigffs
              corona, corona4g, winchester, winchester4g
<dir>       = path, absolute or relative, to a directory - do not terminate with /
<key>       = 128 bit key in hexadecimal representation
<name>      = name.bin contents will be appended to hv/kernel patches

<out.bin>   = optional, overrides auto built output image name
<ext>       = using this option would cause the builder to look for _glitch_<ext>.ini instead of _glitch.ini
              and patches_jasper_<ext>.bin instead of patches_jasper.bin
<opt> various options can be specified on the command line, see perbox sample ini for descriptions
      listed below, ALL are available to all image types
      the others can be specified but are only used for that specific image type
ALL         = nomobile noremap noecdremap nosecurity nosusecurity nandmu smcnocheck cputemp=
ALL         = gputemp= edramtemp= overcputemp= overgputemp= overedramtemp= cpufan= gpufan=
ALL         = avregion= gameregion= dvdregion= macid= cfldv=
JTAG/GLITCH = smcnoeject smcnoblink cygnos demon xellbutton= xellbutton2= dvdkey=
JTAG only   = nodvd olddvd dualboot=
GLITCH only = patchsmc
      options noted above with an = are expected to be followed with a value
      specifying one of the options without an = is the same as setting TRUE in the ini
         any value assigned to it will be ignored.
      note that command line options take precedence over any values set in perbox ini
      and that only values preceded with 0x will be interpreted as hex, MAC is the only exception
      example: -o macid=00:22:48:F1:01:02;gameregion=0x00FF;nomobile
      example: -o macid=00:22:48:F1:01:02 -o gameregion=0x00FF -o nomobile
      example: -o macid=002248F10102 -o gameregion=255 -o nomobile
<pat>       = optional, <pat> consists of filename.ext,offset
      patches NAND image with file contents just before combining spare and finalizing ecc
      offset is the raw offset without spare data
      file will load based from the -f directory, or absolute path if drive letter is found
      add 0x to offset to specify hexadecimal, otherwise it will be read as decimal
      example: -8 myfile.bin,0x12345
      example: -8 myfile.bin,0x12345;myotherfile.bin,0x54321""")  # noqa: E501
    add = parser.add_argument
    add("-t", dest="image_type", metavar="<type>",
        help="retail, jtag, glitch, glitch2, glitch2m, devkit (defaults to retail)")
    add("-p", dest="cpu_key", metavar="<key>",
        help="32 character CPU hex key (override, can be elsewhere)")
    add("-b", dest="one_bl_key", metavar="<key>",
        help="32 character 1BL hex key (override, can be elsewhere)")
    add("-c", dest="console", metavar="<con>", help="console type")
    add("-d", dest="per_build", metavar="<dir>", help="per build files directory")
    add("-f", dest="data", metavar="<dir>",
        help="use different data dir and file lists")
    add("-s", dest="sha_file", metavar="<file>", nargs="?", const=True,
        help="outputs SHA-1 of final image to <file>, if <file> is not provided an "
             "auto generated name is used")
    add("-o", dest="options", metavar="<opt>", action="append", default=[],
        help="set xeBuild options")
    add("-a", dest="append", metavar="<name>", action="append", default=[],
        help="append patches")
    add("-i", dest="firmware_ext", metavar="<ext>",
        help="adds _<ext> into firmware ini and patches file names")
    add("-r", dest="section_ext", metavar="<ext>",
        help="adds _<ext> into ini bl section name and patches file names")
    add("-8", dest="raw_patches", metavar="<pat>", action="append", default=[],
        help="adds raw patch to NAND just before finalizing")
    _verbose(parser, "build")
    add("-noenter", dest="no_enter", action="store_true",
        help="suppresses prompt for enter key when finished")
    add("-norandom", dest="no_random", action="store_true",
        help="draws nothing, keeping the values the original was compiled with")
    add("-?", "-h", action="help", help="shows this info")
    add("out", metavar="<out.bin>", nargs="*",
        help="optional, overrides auto built output image name")
    if not argv:
        parser.print_help()
        parser.exit(2, "%s: error: invalid command line, you need to specify "
                       "parameters!\n" % parser.prog)
    found = vars(parser.parse_intermixed_args(argv))
    options = {}
    for text in found.pop("options"):
        try:
            options.update(_options(text))
        except ValueError as why:
            parser.error(str(why))
    append, raw, out = found.pop("append"), found.pop("raw_patches"), found.pop("out")
    settings = {name: value for name, value in found.items()
                if value is not None and value is not False}
    if settings.pop("verbose", False):
        settings["verbose"] = 1
    # The first word without a switch names the image; a later one is passed over
    # (0x41A981).
    for _excess in out[1:]:
        logger.warning("command line has excess parameters without switches!")
    settings.update(options)
    if append:
        settings["append"] = tuple(append)
    if raw:
        settings["raw_patches"] = ";".join(raw)
    if out:
        settings["out"] = out[0]
    return settings


def parse_extract(argv) -> dict:
    """`config.ExtractConfig`'s settings from extract mode's switches: `-v`,
    `-noenter` and the image, which is all its usage names."""
    parser = _parser("xeBuild extract", """\
examples:
   xeBuild extract -v nanddump.bin""", """\
legend:
<dir>       = path, absolute or relative, to a directory - do not terminate with /""")
    parser.add_argument("-noenter", dest="no_enter", action="store_true",
                        help="suppresses prompt for enter key when finished")
    _verbose(parser, "extract")
    parser.add_argument("-?", "-h", action="help", help="shows this help")
    parser.add_argument("image", metavar="<input NAND image>")
    found = parser.parse_args(argv)
    return {"image": found.image, "verbose": int(found.verbose),
            "no_enter": found.no_enter}


def parse_client(argv) -> dict:
    """`config.ClientConfig`'s settings from client mode's switches.

    One action and what rides with it, as the original's own note has it: "stacking
    commands is not possible with the exception of v, noenter, ip, s and reboot" -- the
    actions are one mutually exclusive group. A reboot supersedes a shutdown.
    """
    parser = _parser("xeBuild client", """\
examples:
   xeBuild client -r nanddump.bin
   xeBuild client -w nandflash.bin -ip 192.168.2.100""", """\
legend:
<add>    = without this option network will be scanned for server broadcast beacon
           If provided the correct format is an IPv4 address like 192.168.0.100
<f>      = path, absolute or relative, to a file
<d>      = path, absolute or relative, to a directory - do not terminate with /
<b>      = hexadecimal block number
<l>      = hexadecimal number of blocks
<o>      = hexadecimal logical offset (spare data not considered) in flash
notes:
* functions not fully supported with older patch versions, use with caution.
- client mode tends to operate on a single command basis, stacking commands.
  is not possible with the exception of v, noenter, ip, s and reboot.
- patch update (-p) will retain any addon patches already on the console.""")
    one = parser.add_mutually_exclusive_group()
    one.add_argument("-i", dest="info", metavar="<d>", nargs="?", const=True,
                     help="connects to console and shows some info about it\n"
                          "* <d>: collects console information into folder <d>, "
                          "usually enough for build mode")
    one.add_argument("-r", dest="read", metavar="<f>",
                     help="dumps system area of NAND to <f>")
    one.add_argument("-w", dest="write", metavar="<f>",
                     help="writes system area of NAND from <f>")
    one.add_argument("-e", dest="avatar", metavar="<d>",
                     help="format partition and send avatar/kinect data to HDD from "
                          "<d>, must match running kernel")
    one.add_argument("-c", dest="compatibility", metavar="<d>",
                     help="format partition and send xbox compatibility data to HDD "
                          "from <d>")
    one.add_argument("-p", dest="patches", metavar="<f>", nargs="?", const=True,
                     help="will attempt to automatically update patches based on "
                          "running kernel version\n<f>: update patches with <f>")
    one.add_argument("-rb", dest="read_blocks", metavar=("<f>", "<b>", "<l>"), nargs=3,
                     help="read series of blocks starting at <b> for <l>")
    one.add_argument("-wb", dest="write_blocks", metavar=("<f>", "<b>"), nargs=2,
                     help="write series of blocks starting at <b> for the number of "
                          "blocks in <f>")
    one.add_argument("-eb", dest="erase_block", metavar="<b>",
                     help="attempt to erase a single block, even if marked bad on "
                          "console")
    one.add_argument("-bp", dest="binary_patch", metavar=("<f>", "<o>"), nargs=2,
                     help="binary patch NAND with contents of <f> to logical offset "
                          "<o>")
    one.add_argument("-keys", dest="keys", action="store_true",
                     help="* will attempt to dump RSA and 1BL keys from console")
    parser.add_argument("-s", dest="shutdown", action="store_true",
                        help="shutdown console")
    parser.add_argument("-ip", dest="address", metavar="<add>",
                        help="force attempt to connect to addr (ie: -i 192.168.0.100)")
    parser.add_argument("-noenter", dest="no_enter", action="store_true",
                        help="suppresses prompt for enter key when finished")
    parser.add_argument("-reboot", dest="reboot", action="store_true",
                        help="causes the console to hard reboot")
    _verbose(parser, "client")
    parser.add_argument("-?", "-h", action="help", help="shows this help")
    found = vars(parser.parse_args(argv))
    # Each action by its name, and the words it takes after it.
    takes = {"info": ("directory",), "read": ("file",), "write": ("file",),
             "avatar": ("directory",), "compatibility": ("directory",),
             "patches": ("file",), "read_blocks": ("file", "block", "length"),
             "write_blocks": ("file", "block"), "erase_block": ("block",),
             "binary_patch": ("file", "offset"), "keys": ()}
    settings = {}
    for name, words in takes.items():
        given = found.pop(name)
        if given is None or given is False:
            continue
        settings["action"] = name.replace("_", "-")
        values = given if isinstance(given, list) else [given]
        paired = zip(words, values, strict=False)
        settings.update((word, value) for word, value in paired if value is not True)
    if found["shutdown"] and found["reboot"]:
        logger.warning("shutdown superseded by reboot, ignoring -s in favor of "
                       "-reboot")
        found["shutdown"] = False
    settings.update((name, value) for name, value in found.items()
                    if value is not None and value is not False)
    if settings.pop("verbose", False):
        settings["verbose"] = 1
    return settings


def parse_update(argv) -> dict:
    """`config.UpdateConfig`'s settings from update mode's switches.

    `-nowrite` implies `-noava` and `-noreeb`, as the original sets all three for it
    (0x404F13). Each of `-nowrite`, `-noava`, `-noreeb` and `-clean` stands alone
    here, which is what the usage says; the original's handlers also skip the word
    after them (`add ebx, 1` at 0x404F10, 0x404FA8, 0x405005, 0x40526C), so
    `-noava -noreeb` reboots and `-noreeb -clean` fetches what `-clean` should leave --
    both measured. A deliberate divergence: a switch that eats its neighbour is a
    fault, not a behaviour anyone asks for.
    """
    parser = _parser("xeBuild update", """\
examples:
   xeBuild update -f 16197 -a nofcrt
   xeBuild update -f 16203 -d myflash -ip 192.168.2.100""", """\
legend:
<name>      = name.bin contents will be appended to hv/kernel patches

<dir>       = path, absolute or relative, to a directory - do not terminate with \\
<ext>       = using this option would cause the builder to look for _glitch_<ext>.ini instead of _glitch.ini
              and patches_jasper_<ext>.bin instead of patches_jasper.bin
<add>       = without this option network will be scanned for server broadcast beacon
              If provided the correct format is an IPv4 address like 192.168.0.100""")  # noqa: E501
    add = parser.add_argument
    add("-f", dest="data", metavar="<dir>",
        help="use different data dir and file lists")
    add("-d", dest="dump_to", metavar="<dir>",
        help="dumps NAND and other data to <dir> before flashing")
    add("-a", dest="append", metavar="<name>", action="append", default=[],
        help="append patches")
    add("-ip", dest="address", metavar="<add>", help="force attempt to connect to addr")
    add("-i", dest="firmware_ext", metavar="<ext>",
        help="adds _<ext> into firmware ini and patches file names")
    add("-r", dest="section_ext", metavar="<ext>",
        help="adds _<ext> into ini bl section name and patches file names")
    add("-nowrite", dest="no_write", action="store_true",
        help="will not write anything to console flash or HDD\n"
             "without -d results of update are not kept anywhere")
    add("-noava", dest="no_avatar", action="store_true",
        help="will not send avatar data if available and HDD present")
    add("-clean", dest="clean", action="store_true",
        help="secdata, extended and statistics will not be retrieved from console")
    add("-noreeb", dest="no_reboot", action="store_true",
        help="do not automatically reboot console after writes are completed")
    add("-noenter", dest="no_enter", action="store_true",
        help="suppresses prompt for enter key when finished")
    _verbose(parser, "update")
    add("-?", "-h", action="help", help="shows this help")
    found = vars(parser.parse_args(argv))
    if found["no_write"]:
        found.update(no_avatar=True, no_reboot=True)
    append = found.pop("append")
    settings = {name: value for name, value in found.items()
                if value is not None and value is not False}
    if settings.pop("verbose", False):
        settings["verbose"] = 1
    if append:
        settings["append"] = tuple(append)
    return settings


def parse_ini(argv) -> dict:
    """`config.IniConfig`'s settings from ini mode's one path."""
    parser = _parser("xeBuild ini", """\
examples:
   xeBuild ini ./16547/
   xeBuild ini c:\\16547\\$SystemUpdate
   xeBuild ini z:\\someWeirdPath\\su20076000_00000000
      when specifying path, either provide relative path or full path
      to either the SU container, a folder with $SystemUpdate folder in it,
      or a folder with flash update named 'su20076000_00000000' in it.
      Hash data will be output to the folder with the SU in it named _SU.ini""")
    parser.add_argument("system_update", metavar="systeUpdateConPath")
    parser.add_argument("-?", "-h", action="help", help="shows this help")
    return {"system_update": parser.parse_args(argv).system_update}


def _build(settings: dict) -> int:
    """Build mode from its settings."""
    if "cpu_key" in settings:
        logger.info("CPU key overridden from command line, not looking for cpukey.txt")
    if "one_bl_key" in settings:
        logger.info("1BL key overridden from command line, not looking for 1blkey.txt")
    if settings.get("verbose"):
        logging.getLogger().setLevel(logging.DEBUG)
    where = settings.get("per_build") or "data"
    ini = os.path.join(where, "options.ini")
    if "console" not in settings and os.path.isdir(where):
        named = Material(where).console_named()
        if named is not None:
            settings["console"] = named
    try:
        config = BuildConfig(ini=ini if os.path.isfile(ini) else None, **settings)
        out = build_image(config)
    except (ValueError, OSError) as why:
        logger.critical("FATAL BUILD ERROR: %s", why)
        return 1
    logger.info("image built path: %s", os.path.relpath(
        os.path.abspath(out), os.path.dirname(os.path.abspath(sys.argv[0]))))
    if not config.no_enter and sys.stdin.isatty():
        input("press <enter> to quit...")
    return 0


def _extract(settings: dict) -> int:
    """Extract mode from its settings. Its report is what it is for, so it is shown
    whatever `-v` says."""
    if settings["verbose"]:
        logging.getLogger().setLevel(logging.DEBUG)
    try:
        config = ExtractConfig(**settings)
        extracted = extract_image(config)
    except (ValueError, OSError) as why:
        logger.critical("Loading dump failed: %s", why)
        return 1
    if extracted is None:
        logger.critical("Loading dump failed!")
        return 1
    if not config.no_enter and sys.stdin.isatty():
        input("press <enter> to quit...")
    return 0


def _client(settings: dict) -> int:
    """Client mode from its settings."""
    if settings.get("verbose"):
        logging.getLogger().setLevel(logging.DEBUG)
    try:
        config = ClientConfig(**settings)
        run_client(config)
    except (ValueError, OSError, ServerError) as why:
        logger.critical("ERROR: %s", why)
        return 1
    if not config.no_enter and sys.stdin.isatty():
        input("press <enter> to quit...")
    return 0


def _update(settings: dict) -> int:
    """Update mode from its settings."""
    if settings.get("verbose"):
        logging.getLogger().setLevel(logging.DEBUG)
    try:
        config = UpdateConfig(**settings)
        kept = run_update(config)
    except (ValueError, OSError, ServerError) as why:
        logger.critical("FATAL UPDATE ERROR: %s", why)
        return 1
    if kept:
        logger.info("image built path: %s", os.path.relpath(
            os.path.abspath(kept), os.path.dirname(os.path.abspath(sys.argv[0]))))
    if not config.no_enter and sys.stdin.isatty():
        input("press <enter> to quit...")
    return 0


def _ini(settings: dict) -> int:
    """Ini mode from its settings. What it says is what it is for, so it is shown
    whatever the verbosity."""
    try:
        write_su_ini(IniConfig(**settings))
    except (ValueError, OSError) as why:
        logger.critical("Error loading SU! %s", why)
        return 1
    if sys.stdin.isatty():
        input("press <enter> to quit...")
    return 0
