"""A stand-in for a console's update server, shared by the client and update tests.

It answers as the stand-in the original was recorded against: from a directory of
captured answers (`serve.json` naming them, or the client recordings' fixed names), `OK`
to every write, and a log of what it was sent in the recordings' own format -- each
command on a line, each payload as "  <- payload payloadNN.bin 0x... bytes".
"""

import os
import json
import socket
import struct
import threading


class StandIn(threading.Thread):

    def __init__(self, serve: str):
        super().__init__(daemon=True)

        def read(name):
            with open(os.path.join(serve, name), "rb") as handle:
                return handle.read()

        described = os.path.join(serve, "serve.json")
        if os.path.isfile(described):
            with open(described) as handle:
                table = json.load(handle)
        else:
            table = {"info": "info.bin", "flash": "flash.bin",
                     "files": {"flash_hdr": "flash_hdr.bin"}}
            if os.path.isfile(os.path.join(serve, "patches.bin")):
                table["files"]["patches"] = "patches.bin"
        self.info, self.flash = read(table["info"]), read(table["flash"])
        self.bootloaders = read(table["bootloaders"]) if "bootloaders" in table else b""
        self.files = {name.lower(): read(path)
                      for name, path in table.get("files", {}).items()}
        self.lines, self.payloads = [], []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]

    def exact(self, conn, count):
        out = bytearray()
        while len(out) < count:
            chunk = conn.recv(min(count - len(out), 0x100000))
            if not chunk:
                raise EOFError
            out += chunk
        return bytes(out)

    def send(self, conn, body):
        conn.sendall(struct.pack(">I", 0xFFFFFFFF) if body is None
                     else struct.pack(">I", len(body)) + body)

    def run(self):
        conn, _ = self.sock.accept()
        self.lines.append("== connection")
        try:
            while True:
                text = b""
                while not text.endswith(b"\n"):
                    text += self.exact(conn, 1)
                text = text[:-1].decode("latin-1")
                self.lines.append(text)
                verb, rest = text[:4], text[4:]
                if verb == "GTIN":
                    self.send(conn, self.info)
                elif verb == "GTFL":
                    self.send(conn, self.flash)
                elif verb == "GTBL":
                    self.send(conn, self.bootloaders)
                elif verb == "GTBB":
                    self.send(conn, b"")
                elif verb == "GETF":
                    self.send(conn, self.files.get(rest.lower()))
                elif verb == "RBLK":
                    first, count = int(rest[:4], 16), int(rest[4:8], 16)
                    self.send(conn, self.flash[first * 0x4200:(first + count) * 0x4200])
                elif verb in ("WRFL", "WBLK", "WBPT", "SNDF"):
                    length = struct.unpack(">I", self.exact(conn, 4))[0]
                    self.payloads.append(self.exact(conn, length))
                    self.lines.append("  <- payload payload%02d.bin %#x bytes"
                                      % (len(self.payloads), length))
                    self.send(conn, b"OK")
                elif verb in ("ERBL", "MTPT", "UMPT", "FMEX", "FMCM", "MKDR"):
                    self.send(conn, b"OK")
                elif verb in ("SHDN", "REEB", "QUIT"):
                    return
        except EOFError:
            self.lines.append("== closed by client")
        finally:
            conn.close()
            self.sock.close()
