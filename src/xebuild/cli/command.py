"""xeBuild's command line for build mode, and what each switch sets.

The grammar is the original's, as its usage states it and as x360mcp measured it:

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

from __future__ import annotations

import logging
import os
import sys

from ..build import build_image
from ..config import BuildConfig
from ..config.options import OptionsConfig

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

[mode] is build, the default and the one mode this implements.
<opt> example: -o macid=00:22:48:F1:01:02;gameregion=0x00FF;nomobile
<pat> example: -8 myfile.bin,0x12345;myotherfile.bin,0x54321"""


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


def main(argv=None) -> int:
    """Build mode from a command line; the exit status the shell gets back."""
    argv = sys.argv[1:] if argv is None else argv
    try:
        mode, settings, flags = parse(argv)
    except UsageError as why:
        print("ERROR: %s" % why, file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return 2
    if flags["help"]:
        print(USAGE)
        return 0
    if mode != "build":
        print("ERROR: %s mode is not implemented here; build is" % mode,
              file=sys.stderr)
        return 2
    logging.basicConfig(
        format="%(message)s",
        level=logging.INFO if settings.get("verbose") else logging.WARNING,
    )
    ini = os.path.join(settings.get("per_build") or "data", "options.ini")
    try:
        config = BuildConfig(ini=ini if os.path.isfile(ini) else None, **settings)
        out = build_image(config)
    except (ValueError, OSError) as why:
        print("FATAL BUILD ERROR: %s" % why, file=sys.stderr)
        return 1
    print("%s image built" % out)
    if not config.no_enter and sys.stdin.isatty():
        input("press <enter> to quit...")
    return 0
