"""A stand-in console's update server, run beside the original inside its container.

`python3 server.py <directory>`: answers from the files `serve.json` there names,
writes every command it is sent to `wire.log` and every payload to `payloads/`, and
answers a write with `OK`. It listens on TCP 49 on the loopback, the port the original
dials, which a container may bind where a user on the host may not; it says it is
listening by creating `ready`, and stops after `idle` seconds without a connection.

Standard library only: the container has Python and nothing else of this repository.
The wire log's lines are the ones `tests/xebuild/e2e/standin.py` keeps, so a recording
reads the same whichever side made it.
"""

import os
import sys
import json
import socket
import struct

HERE = sys.argv[1]
with open(os.path.join(HERE, "serve.json")) as handle:
    TABLE = json.load(handle)


def material(key):
    path = TABLE.get(key)
    if not path:
        return None
    with open(os.path.join(HERE, path), "rb") as handle:
        return handle.read()


INFO, FLASH, BOOTLOADERS = material("info"), material("flash"), material("bootloaders")
BAD = material("bad") or b""
FILES = {name.lower(): os.path.join(HERE, path)
         for name, path in TABLE.get("files", {}).items()}
BLOCK = TABLE.get("block", 0x4200)
ANSWER = TABLE.get("answer", "OK").encode()
os.makedirs(os.path.join(HERE, "payloads"), exist_ok=True)
COUNT = [0]


def send(conn, body):
    if body is None:
        conn.sendall(struct.pack(">I", 0xFFFFFFFF))
        return
    conn.sendall(struct.pack(">I", len(body)) + body)


def exact(conn, length):
    out = b""
    while len(out) < length:
        chunk = conn.recv(length - len(out))
        if not chunk:
            raise EOFError
        out += chunk
    return out


def payload(conn):
    length = struct.unpack(">I", exact(conn, 4))[0]
    body = exact(conn, length)
    COUNT[0] += 1
    name = "payload%02d.bin" % COUNT[0]
    with open(os.path.join(HERE, "payloads", name), "wb") as handle:
        handle.write(body)
    LOG.write("  <- payload %s %#x bytes\n" % (name, length))


def line(conn):
    out = b""
    while not out.endswith(b"\n"):
        chunk = conn.recv(1)
        if not chunk:
            raise EOFError
        out += chunk
    return out[:-1].decode("latin1")


def serve(conn):
    while True:
        text = line(conn)
        LOG.write("%s\n" % text)
        verb, rest = text[:4], text[4:]
        if verb == "GTIN":
            send(conn, INFO)
        elif verb == "GTFL":
            send(conn, FLASH)
        elif verb == "GTBL":
            send(conn, BOOTLOADERS)
        elif verb == "GTBB":
            send(conn, BAD)
        elif verb == "GETF":
            path = FILES.get(rest.lower())
            if path is None:
                send(conn, None)
            else:
                with open(path, "rb") as handle:
                    send(conn, handle.read())
        elif verb == "RBLK":
            first, count = int(rest[:4], 16), int(rest[4:8], 16)
            send(conn, FLASH[first * BLOCK:(first + count) * BLOCK])
        elif verb in ("WRFL", "WBLK", "WBPT", "SNDF"):
            payload(conn)
            send(conn, ANSWER)
        elif verb in ("ERBL", "MTPT", "UMPT", "FMEX", "FMCM", "MKDR"):
            send(conn, ANSWER)
        elif verb in ("SHDN", "REEB", "QUIT"):
            return
        else:
            LOG.write("  ?? unknown verb\n")
            send(conn, ANSWER)


listening = socket.socket()
listening.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listening.bind(("127.0.0.1", 49))
listening.listen(4)
# Line-buffered, so what is in the log is what was sent when the container stops.
with open(os.path.join(HERE, "wire.log"), "w", buffering=1) as LOG:
    open(os.path.join(HERE, "ready"), "w").close()
    listening.settimeout(TABLE.get("idle", 300))
    try:
        while True:
            conn, _ = listening.accept()
            LOG.write("== connection\n")
            try:
                serve(conn)
            except EOFError:
                LOG.write("== closed by client\n")
            finally:
                conn.close()
    except TimeoutError:
        pass
