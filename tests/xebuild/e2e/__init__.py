"""The tests that hold this tool against the original xeBuild, through its recordings.

Everything under `tests/xebuild` above this runs on data made up in the test itself, so
it runs anywhere in seconds and a skip there means something is wrong. These read what
the original built, wrote, sent and said, and that material is made before they are
collected: `conftest.py` runs `bootstrap`, which downloads J-Runner's release and the
17559 system update, takes the console from `XEBUILD_E2E_DUMP` and `XEBUILD_E2E_CPUKEY`
or builds a donor console without them, and runs every case through the original. Each
test still reads what it needs from an environment variable, which the bootstrap sets.

    the fast one   python -m unittest discover -s tests -t .
    this one       pytest tests/xebuild/e2e -n auto --dist load

`pytest` it is, for `conftest.py`, with the `test` dependency group of `pyproject.toml`;
`-n auto` runs each test on whichever core is free. A class's `setUpClass` may then run
on more than one worker; the few that do real work there cost a little CPU and save
minutes of waiting behind one another. The long comparisons are split into one test per
group -- of cells, of reference types, of the grid's image types -- so that they spread,
and each has a test that fails if a case falls outside every group.
`python -m tests.xebuild.e2e.bootstrap` makes the material without the tests and prints
its variables, for a run under `unittest`.

`e2e_*.py` rather than `test_*.py` on purpose: the fast run discovers `test*.py` and so
does not reach in here at all.
"""
