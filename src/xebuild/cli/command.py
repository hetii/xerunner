"""xeBuild's command line, and what each switch sets: build mode's here, and the other
three modes' further down, each with its own usage.

The grammar is the original's, as its usage states it and as measured on it:

    xeBuild [mode] -t <type> [<switch> [<switch>...]] <out.bin>

The mode is optional and build is the default. Every switch but four takes the word
after it; `-v`, `-noenter`, `-norandom` and `-?` stand alone. `-s` is the one whose word
is optional, and it takes the next word whatever that is -- `-s -noenter` loses the
`-noenter`, measured on the original -- so a word beginning with a dash leaves the hash
file's name to be made up. `-o`, `-a` and `-8` may be given more than once, and one
`-o` may carry several settings separated by `;`, each `name` alone meaning true. What
is left over is the image's name, the last of it if more than one word is.

The per-build directory's `options.ini` is read first and the command line goes over it,
which is the order `BuildConfig` keeps; with no `-d` that directory is `./data/`, as
the original warns.
"""

import os
import sys
import time
import logging

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

USAGE = """\
Usage    :
   xeBuild [mode] -t <type> [<switch> [<switch>...]] <out.bin>

Switches:
   -t <type>: retail, jtag, glitch, glitch2, glitch2m, devkit (defaults to retail)
   -p <key> : 32 character CPU hex key (override, can be elsewhere)
   -b <key> : 32 character 1BL hex key (override, can be elsewhere)
   -c <con> : console type
   -d <dir> : per build files directory
   -f <dir> : use different data dir and file lists
   -s <file>: outputs SHA-1 of final image to <file>, if <file> is not provided an auto
              generated name is used
   -o <opt> : set xeBuild options
   -a <name>: append patches
   -i <ext> : adds _<ext> into firmware ini and patches file names
   -r <ext> : adds _<ext> into ini bl section name and patches file names
   -8 <pat> : adds raw patch to NAND just before finalizing
   -v       : shows more info during build process
   -noenter : suppresses prompt for enter key when finished
   -norandom: draws nothing, keeping the values the original was compiled with
   -?       : shows this info

[mode] is build, the default, or extract, client or update, each with usage of its own.
<opt> example: -o macid=00:22:48:F1:01:02;gameregion=0x00FF;nomobile
<pat> example: -8 myfile.bin,0x12345;myotherfile.bin,0x54321"""


EXTRACT_USAGE = """\
Usage    :
   xeBuild extract <switch> <input NAND image>

Example  :
   xeBuild extract -v nanddump.bin

Switches:
   -v       : shows more info during extract process
   -noenter : suppresses prompt for enter key when finished
   -?       : shows this info"""


# Ini mode's own usage, the original's words (0x418240); its main usage does not name
# the mode at all.
INI_USAGE = """\
Usage   :
   xeBuild ini [systeUpdateConPath]

Examples:
   xeBuild ini ./16547/
   xeBuild ini c:\\16547\\$SystemUpdate
   xeBuild ini z:\\someWeirdPath\\su20076000_00000000
      when specifying path, either provide relative path or full path
      to either the SU container, a folder with $SystemUpdate folder in it,
      or a folder with flash update named 'su20076000_00000000' in it.
      Hash data will be output to the folder with the SU in it named _SU.ini"""


CLIENT_USAGE = """\
Usage   :
   xeBuild client <switch> [<option>]

Examples:
   xeBuild client -r nanddump.bin
   xeBuild client -w nandflash.bin -ip 192.168.2.100

Switches:
   -i             : connects to console and shows some info about it
   -i <d>         : collects console information into folder <d>, usually enough for
                    build mode
   -r <f>         : dumps system area of NAND to <f>
   -w <f>         : writes system area of NAND from <f>
   -rb <f> <b> <l>: read series of blocks starting at <b> for <l>
   -wb <f> <b>    : write series of blocks starting at <b> for the number of blocks in
                    <f>
   -eb <b>        : attempt to erase a single block, even if marked bad on console
   -bp <f> <o>    : binary patch NAND with contents of <f> to logical offset <o>
   -keys          : will attempt to dump RSA and 1BL keys from console
   -e <d>         : format partition and send avatar/kinect data to HDD from <d>, must
                    match running kernel
   -c <d>         : format partition and send xbox compatibility data to HDD from <d>
   -s             : shutdown console
   -ip <add>      : force attempt to connect to addr (ie: -i 192.168.0.100)
   -noenter       : suppresses prompt for enter key when finished
   -reboot        : causes the console to hard reboot
   -v             : shows more info during client process
   -?             : shows this help

   -p             : will attempt to automatically update patches based on running
                    kernel version
   -p <f>         : update patches with <f>

<b>, <l> and <o> are hexadecimal."""


UPDATE_USAGE = """\
Usage   :
   xeBuild update <switch> [<option>]

Examples:
   xeBuild update -f 16197 -a nofcrt
   xeBuild update -f 16203 -d myflash -ip 192.168.2.100

Switches:
   -f <dir> : use different data dir and file lists
   -d <dir> : dumps NAND and other data to <dir> before flashing
   -a <name>: append patches
   -ip <add>: force attempt to connect to addr
   -i <ext> : adds _<ext> into firmware ini and patches file names
   -r <ext> : adds _<ext> into ini bl section name and patches file names
   -nowrite : will not write anything to console flash or HDD
              without -d results of update are not kept anywhere
   -noava   : will not send avatar data if available and HDD present
   -clean   : secdata, extended and statistics will not be retrieved from console
   -noreeb  : do not automatically reboot console after writes are completed
   -noenter : suppresses prompt for enter key when finished
   -v       : shows more info during update process
   -?       : shows this help"""


class UsageError(ValueError):
    """A command line the original would answer with its usage."""


def _options(text: str) -> dict:
    """One `-o`'s settings: `name` or `name=value`, several separated by `;`.

    Only the thirty-one options are reachable this way; a switch's own setting is not
    an option, and the original answers an unknown name with its usage.
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
            raise UsageError("%s is not an option" % name)
        out[name] = value.strip() if sign else True
    return out


def parse(argv) -> tuple:
    """`(mode, settings, flags)` from a command line.

    `settings` are `BuildConfig`'s, by its own names, ready to hand over. `flags` are
    what belongs to the run rather than the image: `help`.
    """
    rest = list(argv)
    if not rest:
        raise UsageError("invalid command line, you need to specify parameters!")
    mode = "build"
    if rest[0] in ("build", "extract", "client", "update"):
        mode = rest.pop(0)
    named = {"-t": "image_type", "-c": "console", "-p": "cpu_key", "-b": "one_bl_key",
             "-d": "per_build", "-f": "data", "-i": "firmware_ext",
             "-r": "section_ext"}
    settings, options, append, raw, out = {}, {}, [], [], []
    flags = {"help": False}
    while rest:
        one = rest.pop(0)
        if one.startswith("-v"):
            # The third character is the level: none, a space or 1 is one, 2 is two, 0
            # leaves it be -- anything else is taken and ignored, as the original does.
            level = {"": 1, " ": 1, "1": 1, "2": 2}.get(one[2:3])
            if level is not None:
                settings["verbose"] = level
            continue
        if one == "-noenter":
            settings["no_enter"] = True
        elif one == "-norandom":
            settings["no_random"] = True
        elif one == "-?":
            flags["help"] = True
            break
        elif one == "-s":
            taken = rest.pop(0) if rest else ""
            settings["sha_file"] = True if not taken or taken.startswith("-") \
                else taken
        elif one in named or one in ("-o", "-a", "-8"):
            if not rest:
                raise UsageError("%s needs a value" % one)
            value = rest.pop(0)
            if one == "-o":
                options.update(_options(value))
            elif one == "-a":
                append.append(value)
            elif one == "-8":
                raw.append(value)
            else:
                settings[named[one]] = value
                if one == "-p":
                    logger.info("CPU key overridden from command line, not looking for "
                                "cpukey.txt")
                elif one == "-b":
                    logger.info("1BL key overridden from command line, not looking for "
                                "1blkey.txt")
        elif one.startswith("-"):
            raise UsageError("%s is not a switch" % one)
        else:
            out.append(one)
    settings.update(options)
    if append:
        settings["append"] = tuple(append)
    if raw:
        settings["raw_patches"] = ";".join(raw)
    if out:
        settings["out"] = out[-1]
    return mode, settings, flags


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
    """Build mode from a command line; the exit status the shell gets back."""
    argv = sys.argv[1:] if argv is None else argv
    # INFO for every mode, before any switch is read -- some say things themselves;
    # `-v` then takes it a level down, to what the original shows only with it.
    handler = logging.StreamHandler()
    handler.setFormatter(LogFormatter(handler.stream.isatty()))
    logging.basicConfig(level=logging.INFO, handlers=[handler])
    logger.info("started %s", time.strftime("%Y-%m-%d %H:%M:%S"))
    logger.info("cmd: %s", " ".join([os.path.basename(sys.argv[0]), *argv]))
    if argv and argv[0] == "client":
        return _client(argv[1:])
    if argv and argv[0] == "update":
        return _update(argv[1:])
    if argv and argv[0] == "ini":
        return _ini(argv[1:])
    try:
        mode, settings, flags = parse(argv)
    except UsageError as why:
        print("ERROR: %s" % why, file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return 2
    if mode == "extract":
        return _extract(settings, flags)
    if flags["help"]:
        print(USAGE)
        return 0
    if mode != "build":
        print("ERROR: %s mode is not implemented here" % mode, file=sys.stderr)
        return 2
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


def _extract(settings: dict, flags: dict) -> int:
    """Extract mode: `-v`, `-noenter` and the image, which is all its usage names.

    Its report is what it is for, so it is shown whatever `-v` says.
    """
    if flags["help"]:
        print(EXTRACT_USAGE)
        return 0
    extra = set(settings) - {"verbose", "no_enter", "out"}
    if extra or "out" not in settings:
        why = ("%s is not a setting extract mode takes" % sorted(extra)[0] if extra
               else "not enough info provided to carry out command!")
        print("ERROR: %s" % why, file=sys.stderr)
        print(EXTRACT_USAGE, file=sys.stderr)
        return 2
    if settings.get("verbose"):
        logging.getLogger().setLevel(logging.DEBUG)
    try:
        config = ExtractConfig(image=settings["out"],
                               verbose=settings.get("verbose", 0),
                               no_enter=settings.get("no_enter", False))
        found = extract_image(config)
    except (ValueError, OSError) as why:
        logger.critical("Loading dump failed: %s", why)
        return 1
    if found is None:
        logger.critical("Loading dump failed!")
        return 1
    if not config.no_enter and sys.stdin.isatty():
        input("press <enter> to quit...")
    return 0


def parse_client(argv) -> tuple:
    """`(settings, flags)` for `config.ClientConfig` from client mode's switches.

    One action and what rides with it, as the original's own note has it: "stacking
    commands is not possible with the exception of v, noenter, ip, s and reboot" --
    a second action is refused, "option flag %s on command line but option was
    already set!", and one short of its words, "not enough arguments provided!".
    """
    rest, settings, flags = list(argv), {}, {"help": False}
    # The action each switch names and the words it takes after it.
    takes = {"-i": ("info", ()), "-r": ("read", ("file",)),
             "-w": ("write", ("file",)),
             "-rb": ("read-blocks", ("file", "block", "length")),
             "-wb": ("write-blocks", ("file", "block")),
             "-eb": ("erase-block", ("block",)), "-keys": ("keys", ())}
    while rest:
        one = rest.pop(0)
        if one.startswith("-v"):
            settings["verbose"] = 1
        elif one == "-noenter":
            settings["no_enter"] = True
        elif one == "-s":
            # A reboot supersedes a shutdown in either order, and says which it saw
            # first -- measured, both orders, the wire ending in REEB.
            if settings.get("reboot"):
                logger.warning("reboot has already been set on command line, "
                               "ignoring -s")
            else:
                settings["shutdown"] = True
        elif one == "-reboot":
            if settings.pop("shutdown", False):
                logger.warning("shutdown superseded by reboot, ignoring -s in favor of "
                               "-reboot")
            settings["reboot"] = True
        elif one == "-?":
            flags["help"] = True
            break
        elif one == "-ip":
            if not rest:
                raise UsageError("option flag -ip on command line but no argument "
                                 "provided!")
            settings["address"] = rest.pop(0)
        elif one in takes:
            if "action" in settings:
                raise UsageError("option flag %s on command line but option was "
                                 "already set!" % one)
            action, words = takes[one]
            settings["action"] = action
            for word in words:
                if not rest or rest[0].startswith("-"):
                    raise UsageError("option flag %s on command line not enough "
                                     "arguments provided!" % one)
                settings[word] = rest.pop(0)
            # `-i` takes a directory when a word follows it.
            if one == "-i" and rest and not rest[0].startswith("-"):
                settings["directory"] = rest.pop(0)
        elif one == "-p":
            if "action" in settings:
                raise UsageError("option flag -p on command line but option was "
                                 "already set!")
            settings["action"] = "patches"
            if rest and not rest[0].startswith("-"):
                settings["file"] = rest.pop(0)
        elif one in ("-e", "-c"):
            if "action" in settings:
                raise UsageError("option flag %s on command line but option was "
                                 "already set!" % one)
            if not rest or rest[0].startswith("-"):
                raise UsageError("option flag %s on command line not enough "
                                 "arguments provided!" % one)
            settings["action"] = "avatar" if one == "-e" else "compatibility"
            settings["directory"] = rest.pop(0)
        elif one == "-bp":
            if "action" in settings:
                raise UsageError("option flag -bp on command line but option was "
                                 "already set!")
            if len(rest) < 2 or any(word.startswith("-") for word in rest[:2]):
                raise UsageError("option flag -bp on command line not enough "
                                 "arguments provided!")
            settings["action"] = "binary-patch"
            settings["file"], settings["offset"] = rest.pop(0), rest.pop(0)
        else:
            raise UsageError("%s is not a client switch" % one)
    return settings, flags


def _client(argv) -> int:
    """Client mode from its own switches."""
    try:
        settings, flags = parse_client(argv)
    except UsageError as why:
        print("ERROR: %s" % why, file=sys.stderr)
        print(CLIENT_USAGE, file=sys.stderr)
        return 2
    if flags["help"]:
        print(CLIENT_USAGE)
        return 0
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


def parse_update(argv) -> tuple:
    """`(settings, flags)` for `config.UpdateConfig` from update mode's switches.

    `-nowrite` implies `-noava` and `-noreeb`, as the original sets all three for it
    (0x404F13). Each of `-nowrite`, `-noava`, `-noreeb` and `-clean` stands alone
    here, which is what the usage says; the original's handlers also skip the word
    after them (`add ebx, 1` at 0x404F10, 0x404FA8, 0x405005, 0x40526C), so
    `-noava -noreeb` reboots and `-noreeb -clean` fetches what `-clean` should leave --
    both measured. A deliberate divergence: a switch that eats its neighbour is a
    fault, not a behaviour anyone asks for.
    """
    rest, settings, flags = list(argv), {}, {"help": False}
    takes = {"-f": "data", "-d": "dump_to", "-ip": "address", "-i": "firmware_ext",
             "-r": "section_ext"}
    appended = []
    while rest:
        one = rest.pop(0)
        if one == "-?":
            flags["help"] = True
            break
        if one.startswith("-v"):
            settings["verbose"] = 1
        elif one == "-noenter":
            settings["no_enter"] = True
        elif one == "-nowrite":
            settings.update(no_write=True, no_avatar=True, no_reboot=True)
        elif one == "-noava":
            settings["no_avatar"] = True
        elif one == "-noreeb":
            settings["no_reboot"] = True
        elif one == "-clean":
            settings["clean"] = True
        elif one in takes or one == "-a":
            if not rest:
                raise UsageError("option flag %s on command line but no argument "
                                 "provided!" % one)
            if one == "-a":
                appended.append(rest.pop(0))
            else:
                settings[takes[one]] = rest.pop(0)
        else:
            raise UsageError("unknown option '%s' provided on command line!" % one)
    if appended:
        settings["append"] = tuple(appended)
    return settings, flags


def _ini(argv) -> int:
    """Ini mode: one path and nothing else, not `-noenter` either -- any other count
    of words gets its usage, measured. What it says is what it is for, so it is
    shown whatever the verbosity."""
    if len(argv) != 1:
        print(INI_USAGE, file=sys.stderr)
        return 2
    try:
        write_su_ini(IniConfig(system_update=argv[0]))
    except (ValueError, OSError) as why:
        logger.critical("Error loading SU! %s", why)
        return 1
    if sys.stdin.isatty():
        input("press <enter> to quit...")
    return 0


def _update(argv) -> int:
    """Update mode from its own switches."""
    try:
        settings, flags = parse_update(argv)
    except UsageError as why:
        print("ERROR: %s" % why, file=sys.stderr)
        print(UPDATE_USAGE, file=sys.stderr)
        return 2
    if flags["help"]:
        print(UPDATE_USAGE)
        return 0
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
