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
`logger.info("...")` at the point where something has happened. The log is whatever those
calls produce, in the order the code happens to reach them.

**The single message may be the original's.** When the original says something about an
event this code also handles -- "flash header SysUpdateCount is not 2, continuing
anyway" -- use its sentence, word for word, at the place where that event happens here.
Rewording it only so it differs is as pointless as copying the log whole. Leave out its
decoration: the `*******` prefixes, the leading newlines, the "ERROR loading '%s'," frame
that belongs to its own output; pick the level (`info`, `warning`, `error`) by what the
event means here.

**The log as a whole is never made to match.** This is the mistake that was made in
x360mcp and must not come back: lines collected into lists and printed later, messages
reordered so they come out in the original's sequence, blank lines and separators added
because the original has them, messages invented or duplicated only to fill a slot the
original's log has. None of that. Concretely:

- no list, buffer or queue of log lines, and no function that prints a batch of them;
- no ordering logic of any kind whose purpose is the order of the output;
- no blank lines, rulers or banners (`------ adding firmware files ------`);
- no message emitted anywhere but at the point where its event actually happens;
- no test that compares our log with the original's.

If our code does things in a different order than the original, our log comes out in a
different order, and that is correct. What is held against the original is the image,
never the log.

Log files are out of scope for now; the screen is enough.

## Language

Code, comments, identifiers, log strings, documentation and commit messages are English.
Discussion is Polish.

## Approval and commits

Author is always Grzegorz Hetman. Never add a Co-Authored-By line.

**What is approved is what was listed, and nothing beside it.** An approval covers the
things that were named at the time and no others. Two ways of breaking that, both of
which have happened:

- Adding something that was never proposed. If it turns out while writing that one more
  method is needed, it stops there and is put to the user before it is written. "It was
  needed for the thing you approved" is not an approval.
- Naming examples and delivering a set. Showing four fields and then writing setters for
  all fifteen is not the same proposal, even when all fifteen are right. **Say the number
  and the whole list before asking for a yes**; "all of them" is a fact the user cannot
  guess from an example.

**Nothing is committed without the user saying so, for that commit.** Not a module, not a
fix, not a tidy-up. Permission to commit one thing is permission for that one thing and
expires with it; "finish the step" is not permission to commit the step. The work is
finished, `ruff` and the tests are run, and then it waits with the diff on the screen
until the user has looked at it. A frozen module additionally needs permission to be
touched at all, which is a separate question from permission to commit.

## The surface is checked before anything is proposed

Before proposing or writing a function, a method or a constant, the existing surface of
every package involved is listed and read -- not remembered. It goes in the proposal, as
"what exists / what is missing", so the user is reading a check rather than a claim.

This has been got wrong twice, both times by proposing something that was already there:
a keying order that `chain.sealing.keys` already had, and a name that collided with
`chain.Chain.stages`. Both were caught by the user, not by me. Remembering the tree is not
a method; listing it is, and it costs one command.

The same check finds the other kind: one fact defined in two places. `ast` over `src`
answers both questions -- names that appear in more than one module, and integer literals
that appear in the code of more than one module -- and it is run before a step, not after.

## A module that has been committed is frozen

Once a module is committed it is not touched again without the user saying so for that
change. Noticing that something in it should be different is the assistant's job; deciding
that it may be edited is the user's, and the two are asked separately: what is wrong, then
whether to open it. Permission to commit is not permission to edit a frozen module, and
permission to edit one is not permission to commit the result.

## Decisions already made

**The two keys are read where the original reads them, in `BuildConfig`.** Each comes
from the command line, then its file, then `options.ini`: `cpukey.txt` in the per build
directory, `1blkey.txt` in the directory the tool runs in -- the exe's own, as the
original's. A file whose key fails its check is said and passed over.

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

## Before a commit

`ruff check src tests` passes. Its settings live in `pyproject.toml` and the one rule
left out is explained there. `ruff format` is not run: its output is a different house
style from what is written here, and reformatting is not checking.

**Two suites, and both are run.** The fast one needs nothing and must show **no skips** --
a skip there is a fault, not a missing file:

    python -m unittest discover -s tests -t .

The other holds this tool against the original xeBuild, through recordings of what the
original built, wrote, sent and said:

    pytest tests/xebuild/e2e -n auto --dist load

Its material is made, not kept: `tests/xebuild/e2e/bootstrap`, run by `conftest.py`
before the tests are collected, downloads J-Runner's release and the 17559 system
update, takes the console from `XEBUILD_E2E_DUMP` and `XEBUILD_E2E_CPUKEY` -- or builds a
donor console without them -- and runs every case through the original, its clock
frozen, under wine in `docker/Dockerfile.xebuild`'s container or natively on Windows.
It writes under `XEBUILD_E2E_INPUT` and the tests' scratch goes under
`XEBUILD_E2E_OUTPUT`, `/dev/shm/new-material/{input,output}` by default. Run it on both:
a real console's dump and the donor console each find what the other does not.

A test belongs in `e2e/` when it reads what the original made. A new case is a recipe
in the bootstrap -- its input made from the console's dump or from public files, never
a file kept by hand outside the repository -- and nothing a console of the user's alone
holds, its dump or its key, is written into the tree.
