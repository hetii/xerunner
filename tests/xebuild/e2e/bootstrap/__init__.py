"""The material the end-to-end tests read, made from nothing but public downloads.

The e2e tests compare this tool with the original xeBuild through recordings: what the
original built, wrote, sent or said for a case, stored beside the input it was given.
This package makes all of it, so a fresh clone can run them:

- J-Runner with Extras V3.4.0 r6, from its GitHub release, carries the original
  `xeBuild.exe` with its releases, its data directory and the donor files;
- the 17559 system update, from the Internet Archive, carries the avatar data;
- a console's dump and its CPU key come from the caller, `XEBUILD_E2E_DUMP` and
  `XEBUILD_E2E_CPUKEY`; without them a donor image the original builds stands in, under
  a key made up for it;
- every case is then run through the original -- natively on Windows, under wine in a
  container elsewhere, with its clock frozen -- and what it made is kept.

Everything goes under one directory, `XEBUILD_E2E_INPUT`, and is made once: a part
that is already there is taken as it stands when the stamp beside it names the same
inputs, and made again when it does not. The tests' own scratch goes under
`XEBUILD_E2E_OUTPUT`. Nothing is written anywhere else.

`prepare()` returns the environment the tests read; `conftest.py` beside the tests
calls it before they are collected. `python -m tests.xebuild.e2e.bootstrap` does the
same and prints the variables, for a run outside pytest.
"""

import os

INPUT = os.path.abspath(os.environ.get("XEBUILD_E2E_INPUT")
                        or "/dev/shm/new-material/input")
OUTPUT = os.path.abspath(os.environ.get("XEBUILD_E2E_OUTPUT")
                         or "/dev/shm/new-material/output")


def prepare() -> dict:
    """Every part made or found, and the environment the tests read."""
    from . import material
    return material.prepare(INPUT)
