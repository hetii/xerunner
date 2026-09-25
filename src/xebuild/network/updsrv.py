"""The update server's protocol, as xeBuild speaks it.

Read out of the original and held against it: the original's client mode was run under
wine against a stand-in server that records every byte, and this sends the same.

* The console announces itself with an eight-byte datagram to UDP 48 whose first four
  bytes are `NSvr` (compared at 0x41EBC4, read through the big-endian helper at
  0x420AD0); the client learns the address from where it came. `-ip` skips the wait.
* Commands go to TCP 49 as one line of text each, ended by a newline, and nothing
  acknowledges one: a read goes straight from the command to its answer (`GTFL` is
  sent at 0x41FE64 and its payload read at 0x41FEA8).
* A payload either way is a four-byte big-endian length and then that many bytes
  (0x41E800). A length of 0xFFFFFFFF is a refusal, the only "no" this protocol has, and
  0 is a real, empty answer.
* A write is answered with a payload of its own: two bytes, `OK` where it worked. The
  original checks both, the length (0x420071) and the letters (0x4203F8), and calls
  anything else a failure -- measured: two zeros made it say "Failed to erase block".
"""

from __future__ import annotations

import logging
import socket
import struct

logger = logging.getLogger(__name__)

PORT = 49


class ServerError(Exception):
    """The console refused, or the connection failed."""


def find(timeout: float = 30.0) -> str:
    """Wait for a console to announce itself on UDP 48, and give its address.

    Thirty seconds, as the original waits (the 0x1E at 0x41EC18); anything else
    broadcasting on that port is ignored, as it ignores it.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("", 48))
        except PermissionError:
            raise ServerError("listening on UDP 48 needs privileges here; give the "
                              "console's address with -ip instead") from None
        sock.settimeout(timeout)
        while True:
            try:
                data, where = sock.recvfrom(8)
            except (socket.timeout, TimeoutError):
                raise ServerError("no console announced itself in %g seconds"
                                  % timeout) from None
            if data[:4] == b"NSvr":
                logger.info("server beacon from %s", where[0])
                return where[0]
    finally:
        sock.close()


class Server:
    """One connection to a console's update server; a context manager that says QUIT
    on the way out unless the console was told to shut down or reboot."""

    def __init__(self, host: str, port: int = PORT, timeout: float = 30.0):
        self.host, self.port, self.timeout = host, port, timeout
        self.sock = None
        self.hung_up = False

    def __enter__(self) -> Server:
        try:
            self.sock = socket.create_connection((self.host, self.port), self.timeout)
        except OSError as why:
            raise ServerError("could not connect to %s: %s"
                              % (self.host, why)) from None
        self.sock.settimeout(self.timeout)
        logger.info("attempting forced connection to %s...success!", self.host)
        return self

    def __exit__(self, *_exc) -> None:
        try:
            if self.sock is not None and not self.hung_up:
                self.command("QUIT")
        except OSError:
            pass
        finally:
            if self.sock is not None:
                self.sock.close()
            self.sock = None

    # --- the wire --------------------------------------------------------------
    def _exact(self, count: int) -> bytes:
        out = bytearray()
        while len(out) < count:
            try:
                chunk = self.sock.recv(min(count - len(out), 0x100000))
            except (socket.timeout, TimeoutError):
                raise ServerError("timeout waiting for data, %d of %d bytes in"
                                  % (len(out), count)) from None
            if not chunk:
                raise ServerError("the console closed the connection with %d of %d "
                                  "bytes still to come" % (len(out), count))
            out += chunk
        return bytes(out)

    def command(self, text: str) -> None:
        """One command line. Nothing comes back to say it arrived."""
        self.sock.sendall(text.encode("latin-1") + b"\n")

    def payload(self) -> bytes | None:
        """A length and that many bytes; None where the console refused."""
        count = struct.unpack(">I", self._exact(4))[0]
        if count == 0xFFFFFFFF:
            return None
        return self._exact(count) if count else b""

    def send_payload(self, body: bytes) -> None:
        self.sock.sendall(struct.pack(">I", len(body)) + bytes(body))

    def _ask(self, text: str) -> bytes:
        self.command(text)
        body = self.payload()
        if body is None:
            raise ServerError("the console refused %s" % text.split()[0])
        return body

    def _write(self, text: str, body: bytes | None = None) -> None:
        """A command that changes the console, with its payload if it takes one, and
        refused unless the console answers `OK`."""
        self.command(text)
        if body is not None:
            self.send_payload(body)
        answer = self.payload()
        if answer != b"OK":
            raise ServerError("the console did not answer OK to %s: %r"
                              % (text[:4], answer))

    # --- the verbs, spelled as the original spells them --------------------------
    def info(self) -> bytes:
        """`GTIN`: what the console is. The original wants at least 0x4A0 bytes and
        says "failed!" of anything shorter (0x41F4D5)."""
        body = self._ask("GTIN")
        if len(body) < 0x4A0:
            raise ServerError("the console's info is %#x bytes, less than 0x4a0"
                              % len(body))
        return body

    def flash(self) -> bytes:
        """`GTFL`: the whole system area, spare included."""
        return self._ask("GTFL")

    def bootloaders(self) -> bytes:
        """`GTBL`: the bootloaders, from the start of the flash to the first slot."""
        return self._ask("GTBL")

    def bad_blocks(self) -> bytes:
        """`GTBB`: the console's list of bad blocks, empty where it has none."""
        return self._ask("GTBB")

    def file(self, name: str) -> bytes | None:
        """`GETF<name>`: one of the files the server offers, or None where it has
        none by that name -- `flash_hdr` is the flash's first page."""
        self.command("GETF%s" % name)
        return self.payload()

    def mount(self, drive: str, path: str) -> None:
        """`MTPT<drive>: <path>`, answered with two bytes (0x41FBCF)."""
        self.command("MTPT%s: %s" % (drive, path))
        if len(self.payload() or b"") != 2:
            raise ServerError("could not mount %s to %s:" % (path, drive))

    def unmount(self, drive: str) -> None:
        """`UMPT<drive>:`, answered the same way (0x41FCFF)."""
        self.command("UMPT%s:" % drive)
        if len(self.payload() or b"") != 2:
            raise ServerError("could not unmount %s:" % drive)

    def format_extended(self) -> None:
        """`FMEX`: the hard disk's system extended partition wiped, which avatar data
        goes to. No argument; answered `OK` (0x4205D0)."""
        self._write("FMEX")

    def format_compatibility(self) -> None:
        """`FMCM`: the same for the compatibility partition (0x420670)."""
        self._write("FMCM")

    def make_directory(self, path: str) -> None:
        """`MKDR<path>`, a verb the original builds as an immediate (0x420732) rather
        than keeping as a string."""
        self._write("MKDR%s" % path)

    def send_file(self, path: str, body: bytes) -> None:
        """`SNDF<path>` and the file, an empty one included -- measured -- through the
        sender `WRFL` uses (0x4204A1)."""
        self._write("SNDF%s" % path, body)

    def read_blocks(self, first: int, count: int) -> bytes:
        return self._ask("RBLK%04x%04x" % (first, count))

    def write_flash(self, body: bytes) -> None:
        self._write("WRFL", body)

    def write_blocks(self, first: int, body: bytes, count: int) -> None:
        self._write("WBLK%04x%04x" % (first, count), body)

    def erase_blocks(self, first: int, count: int = 1) -> None:
        self._write("ERBL%04x%04x" % (first, count))

    def write_patches(self, body: bytes) -> None:
        """`WBPT`: the patches the running console's hypervisor and kernel take."""
        self._write("WBPT", body)

    def shut_down(self) -> None:
        """`SHDN`, which ends the connection as QUIT would."""
        self.command("SHDN")
        self.hung_up = True

    def reboot(self) -> None:
        """`REEB`: a hard reboot, which ends the connection too."""
        self.command("REEB")
        self.hung_up = True
