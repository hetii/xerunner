"""The tests that need real material: dumps, a release, images the original built.

Everything under `tests/xebuild` above this runs on data made up in the test itself, so
it runs anywhere in seconds and a skip there means something is wrong. These do not:
each says through an environment variable what it needs, and skips when it is not there.
Keeping them apart is what makes the other suite's "no skips" mean anything.

    the fast one   python -m unittest discover -s tests -t .
    this one       python -m unittest discover -s tests/xebuild/e2e -t . -p 'e2e_*.py'

`e2e_*.py` rather than `test_*.py` on purpose: the fast run discovers `test*.py` and so
does not reach in here at all.
"""
