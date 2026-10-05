"""The material, made or found before any end-to-end test is collected.

Each test reads what it needs from an environment variable and skips when it is not
there; this sets every one of them from `bootstrap`, so a fresh clone runs them all.
A variable already set is left as it is, which keeps a hand-picked file in charge.

Scratch goes under `XEBUILD_E2E_OUTPUT` rather than wherever `tests/__init__.py` put it.
Workers of `pytest -n` each run this, and the first to arrive makes the material while
the others wait on its lock.
"""

import os
import tempfile

from .bootstrap import INPUT, OUTPUT, prepare


def pytest_configure(config):
    os.makedirs(INPUT, exist_ok=True)
    os.makedirs(OUTPUT, exist_ok=True)
    with open(os.path.join(INPUT, ".lock"), "a+") as lock:
        _locked(lock)
        made = prepare()
    for name, value in made.items():
        os.environ.setdefault(name, value)
    os.environ["XEBUILD_SCRATCH"] = OUTPUT
    tempfile.tempdir = OUTPUT


def _locked(lock) -> None:
    """The lock held until the file is closed, however long the first worker takes."""
    if os.name == "nt":
        import msvcrt
        lock.seek(0)
        while True:
            try:
                msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
                return
            except OSError:
                continue
    import fcntl
    fcntl.flock(lock, fcntl.LOCK_EX)
