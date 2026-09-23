# Working rules for this repository

## What it is

A NAND image builder for the Xbox 360, written from nothing. It is not a port: no line
comes from any earlier tree, and where an earlier tree is mentioned it is as a thing that
was measured, never as a thing to copy.

## Comments

A comment says what is true now and where the measurement behind it came from. It never
says what was believed earlier, what turned out wrong, or what was changed and why. A
correction is made by rewriting the comment, not by adding to it. Anything worth keeping
about how a conclusion was reached belongs here or in the assistant's memory, not in the
source.

Nothing is asserted that was not measured. Where a value came off an image, a binary or
a running console, the comment says which.

## Names at module level

A name at module level has to earn it. It earns it by being used more than once in its own
file, or by being something outside the module reads. A value used in exactly one place
belongs in that place, as a local, however tempting it is to give it a capitalised name at
the top -- `MAGIC = 0xFF4F` read once in one predicate is noise, not documentation. The
comment that would have gone above it goes above the line that uses it.

This has been corrected more than once. Before writing a constant at module level, count
its uses.

## Logging

The standard library's `logging`, used as it was meant to be: a module logger, and
`logger.info("...")` at the point where something has happened. Nothing is buffered to be
replayed later, there is no silent sink, and no structure exists whose purpose is to make
the output line up with another tool's. The original's messages are a reference for what
is worth saying, not a format to reproduce. Where ours diverge, they diverge.

Log files are out of scope for now; the screen is enough.

## Language

Code, comments, identifiers, log strings, documentation and commit messages are English.
Discussion is Polish.

## Commits

Author is always Grzegorz Hetman. Never add a Co-Authored-By line.

## Order of work

`boards`, then `config`, then `build`. Each module is reviewed and accepted before the
next one is started.

**Nothing is committed without the user saying so, for that commit.** Not a module, not a
fix, not a tidy-up. Permission to commit one thing is permission for that one thing and
expires with it; "finish the step" is not permission to commit the step. The work is
finished, `ruff` and the tests are run, and then it waits with the diff on the screen
until the user has looked at it. A frozen module additionally needs permission to be
touched at all, which is a separate question from permission to commit.

## Decisions deliberately left open

**Where `cpukey.txt` and `1blkey.txt` are read.** Not in `BuildConfig` for now. What is
already measured: both live in the per build directory that `-d` names -- the base
directory is not searched and neither is `-f` -- and each key has four sources in order,
the command line (after which the file is not even opened: "CPU key overridden from
command line, not looking for cpukey.txt"), then the file, then `options.ini`, then the
refusal "you need to specify CPU key!".

What decides where the reader belongs is how much else the builder fills from that same
directory. If it turns out to be only these two keys, a reader beside
`BuildConfig.settings_in_ini` has the same shape and belongs there. If the builder ends
up reading a family from there -- `nanddump.bin`, `smc.bin`, `kv.bin` and the rest -- then
the directory is the builder's business and the two keys go with it, so that it is opened
once, in one place. Decide it when `build` exists and the answer is countable.

## Decisions already made

**A configuration checks what it was told and invents nothing.** `-f` and `-d` name
directories that are read, so a value given for either is refused unless the directory is
there, whether it is given at construction or set later. A value nobody gave stays
`None`, which means "nobody said" and not "this is fine": there is nothing to check yet,
and the original does not check these directories either -- measured, it takes `-f
niematego` and `-d xeBuild.exe` without a word and fails later on the file it cannot
open.

Resolving the defaults therefore belongs to `build`, where the original resolves them and
says so: `-f` falls back to `./data/`, `-d` falls back to whatever `-f` ended up being,
and the warning "you did not specify per build directory! Using X" is printed there. A
directory that is written rather than read is the other way round: `dump_to` takes a path
that does not exist yet and refuses only a path that is an existing file.

**Update mode writes an `options.ini` into the directory `-d` names, as the original
does.** It is how the console's own values reach the build: measured on the original,
update mode collects the console's material into that directory in the shape build mode
reads, and the keys travel only through that file -- nothing hands them over as
arguments. Five values go in it: the board as `type`, `1blkey`, `cpukey`, `cfldv` and
`dvdkey`, plus `xellbutton` where the boot flags named one.

What makes an update an update is the release that `-f` names, not a flag: new
bootloaders, a new kernel and its patches, while every console-specific byte is carried
over unchanged. The image type defaults to `glitch`, because a console being updated this
way is already hacked and stays that way. Update mode has no `-o`, so every other option
takes its default -- an image does not record which options built it.

## Before a commit

`ruff check src tests` passes. Its settings live in `pyproject.toml` and the one rule
left out is explained there. `ruff format` is not run: its output is a different house
style from what is written here, and reformatting is not checking.

**What `cfldv` becomes when nothing supplies it belongs to `build`.** Zero is not a
value there, it is the absence of one, so a configuration holds `None`. The original's
own messages give the order: "LDV was already set to %d" when the ini or `-o` named one,
else "setting LDV from image to %d" from the dump's CF, else "Did not find a LDV value to
use, setting it to 0 for devkit!" (and the same for testkit), else "could not find a
non-zero CF LDV to use, setting it to 1 but that may be incorrect!". It needs the image
type and the dump, so it cannot be answered here.

**A value outside a known range is refused, never replaced.** Not wrapped into the range
and not moved to the nearest end of it. The original does both to `cfldv`: it takes the
value modulo 256 first -- proven on four, `=999` is reported as 231, `=300` as 44, `=288`
passes silently because it becomes exactly 32, and `=256` is refused because it becomes
zero -- and then clamps what survives, so `-o cfldv=200` builds an image for 32 with
nothing said. Both are deliberate divergences: a number the caller did not ask for is a
fault that leaves no trace. `check_number` takes a `between` and refuses outside it, and
that is the only range mechanism there is.

**The range is 1 to 32 on purpose, and it is the tool's limit rather than the console's.**
The LDV is the count of 0xF nibbles burnt into the lockdown fuse rows -- confirmed on a
real console, whose fuse row 7 reads `fffffffffffff000` and whose CF reports 13. Rows 7
to 11 are all available, which is eighty nibbles, while the original's ini describes rows
7 and 8 and its parser clamps at 32. If a console past 32 ever appears, widening this is
one number.
