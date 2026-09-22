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
