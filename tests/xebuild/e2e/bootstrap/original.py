"""Running the original xeBuild with its clock frozen, here or under wine.

Two runs of the original from the same input differ, because it seeds its generator from
`time()` and stamps its directory entries with it. A copy with `time()` returning a
constant repeats itself, and a recording made with it can be made again. The patch is
six bytes at the import thunk of `msvcrt!time` (0x449050), whose four callers all pass
NULL, so nothing reads the pointer this version ignores:

    ff 25 fc f3 50 00     jmp  DWORD PTR ds:0x50f3fc
    b8 xx xx xx xx c3     mov  eax, <when> / ret

On Windows the copy runs as it is. Elsewhere it runs under wine in the container
`docker/Dockerfile.xebuild` describes, built on first use, with the material's
directory mounted at its own path so a link laid in it still names its file, and with
no network beyond its own loopback. A stand-in console, when a run needs one, runs
inside the same container, where port 49 is its own to bind.
"""

import os
import sys
import time
import shlex
import struct
import shutil
import subprocess

# The import thunk, as a file offset of xeBuild v1.21.810's .text, and its bytes.
THUNK_AT = 0x48450
THUNK = bytes.fromhex("ff25fcf35000")

# The container the original runs in, and the file it is built from.
IMAGE = os.environ.get("XEBUILD_E2E_WINE_IMAGE", "localhost/xebuild-py:wine")
DOCKERFILE = os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, os.pardir,
                          os.pardir, "docker", "Dockerfile.xebuild")


def frozen(exe: bytes, when: int) -> bytes:
    """`exe` with `time()` returning `when`; refused for any other build of it."""
    if exe[THUNK_AT:THUNK_AT + len(THUNK)] != THUNK:
        raise ValueError("this is not the xeBuild v1.21.810 the clock patch was read "
                         "from: 0x%X holds %s" % (THUNK_AT,
                                                  exe[THUNK_AT:THUNK_AT + 6].hex()))
    patch = b"\xb8" + struct.pack("<I", when) + b"\xc3"
    return exe[:THUNK_AT] + patch + exe[THUNK_AT + len(THUNK):]


def run(work: str, exe: str, args: list, mount: str, timeout: float = 900,
        server: str | None = None) -> str:
    """Run `exe` (in `work`) with `args` from `work`, and return all it printed.

    `mount` is the directory every file the run reaches lies under, links included.
    `server`, when given, is a script started first, beside it, with `work` as its
    argument, which says it is ready by creating `work/ready`.
    """
    if sys.platform == "win32":
        serving = None
        if server is not None:
            serving = subprocess.Popen([sys.executable, server, work], cwd=work)
            while not os.path.exists(os.path.join(work, "ready")):
                time.sleep(0.2)
        try:
            done = subprocess.run([os.path.join(work, exe), *args], cwd=work,
                                  capture_output=True, timeout=timeout,
                                  stdin=subprocess.DEVNULL)
        finally:
            if serving is not None:
                time.sleep(1)
                serving.terminate()
                serving.wait(timeout)
        out = (done.stdout + done.stderr).decode("latin-1")
        return out.replace("\r\n", "\n").replace("\r", "\n")
    engine = _engine()
    command = " ".join(shlex.quote(one) for one in ["wine", exe, *args])
    if server is not None:
        # The server notes a connection the original drops without QUIT once it
        # reads the end of it; the container stays up a moment for that line.
        command = ("(python3 %s %s > /dev/null 2>&1 &) && "
                   "while [ ! -f ready ]; do sleep 0.2; done && { %s; sleep 1; }"
                   % (shlex.quote(server), shlex.quote(work), command))
    # Into a file, and read back as text, as every recording was made: a carriage
    # return the original writes alone -- after each progress line -- and wine's CR LF
    # both come back as one line end.
    said = os.path.join(work, ".original.log")
    subprocess.run(
        [engine, "run", "--rm", "-v", "%s:%s" % (mount, mount), "-w", work,
         "-e", "WINEDEBUG=-all", IMAGE, "sh", "-c",
         "%s </dev/null > .original.log 2>&1" % command],
        capture_output=True, timeout=timeout)
    with open(said, encoding="latin-1") as handle:
        out = handle.read()
    os.remove(said)
    return out


def _engine() -> str:
    """podman or docker, whichever there is, with the image built if it is not."""
    engine = shutil.which("podman") or shutil.which("docker")
    if engine is None:
        raise RuntimeError("the original runs under wine in a container here, and "
                           "neither podman nor docker is installed")
    present = subprocess.run([engine, "image", "inspect", IMAGE], capture_output=True)
    if present.returncode != 0:
        subprocess.run([engine, "build", "-t", IMAGE, "-f",
                        os.path.abspath(DOCKERFILE),
                        os.path.dirname(os.path.abspath(DOCKERFILE))], check=True)
    return engine
