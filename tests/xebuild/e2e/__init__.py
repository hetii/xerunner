"""The tests that need real material: dumps, a release, images the original built.

Everything under `tests/xebuild` above this runs on data made up in the test itself, so
it runs anywhere in seconds and a skip there means something is wrong. These do not:
each says through an environment variable what it needs, and skips when it is not there.
Keeping them apart is what makes the other suite's "no skips" mean anything.

    the fast one   python -m unittest discover -s tests -t .
    this one       python -m unittest discover -s tests/xebuild/e2e -t . -p 'e2e_*.py'
    in parallel    pytest tests/xebuild/e2e -n auto --dist load

The last runs each test on whichever core is free, with the `test` dependency group of
`pyproject.toml` installed: about a minute and a half on sixteen cores where the second
takes twelve. A class's `setUpClass` may then run on more than one worker; the few that
do real work there cost a little CPU and save minutes of waiting behind one another.
The long comparisons are split into one test per group -- of cells, of reference types
-- so that they spread, and each has a test that fails if a cell or a type falls
outside every group.

`e2e_*.py` rather than `test_*.py` on purpose: the fast run discovers `test*.py` and so
does not reach in here at all.
"""
