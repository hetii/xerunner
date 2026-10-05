"""The two public downloads everything else is made from, checked before use."""

import os
import shutil
import hashlib
import zipfile
import urllib.request

# The J-Runner release the original's behaviour was measured on: its xeBuild folder is
# byte for byte the one every recording was made with.
JRUNNER = ("https://github.com/J-Runner-With-Extras/J-Runner-with-Extras/releases/"
           "download/V3.4.0-r6/J-Runner-with-Extras.zip",
           "55ffecb55e93c0291410407fe74080d0a9719a502607b63b856922f4ad70bc9f")

# The last system update, as the disc image's files: the USB package lacks
# `default.xex`, which the avatar recordings walked past.
SYSTEM_UPDATE = ("https://archive.org/download/xbox-360-system-update-17559-cd-usb/"
                 "SystemUpdate_17559_CD.zip",
                 "9f16def9ab1aa59e105b6b2cf370795dc6676c8a3d915d6d7dc39198bb12d5c6")


def fetched(source: tuple, into: str) -> str:
    """The directory `source` unpacks to under `into`, downloaded and checked first.

    The archive is checked against its SHA-256 before anything is unpacked, and a
    directory already unpacked from it is taken as it stands.
    """
    url, digest = source
    done = os.path.join(into, "unpacked")
    if os.path.isfile(os.path.join(into, "unpacked.sha256")):
        with open(os.path.join(into, "unpacked.sha256")) as handle:
            if handle.read().strip() == digest:
                return done
    os.makedirs(into, exist_ok=True)
    archive = os.path.join(into, os.path.basename(url))
    if not os.path.isfile(archive) or _sha256(archive) != digest:
        with urllib.request.urlopen(url) as answer, open(archive, "wb") as handle:
            shutil.copyfileobj(answer, handle, 1 << 20)
    found = _sha256(archive)
    if found != digest:
        raise RuntimeError("%s is not the file this was measured on: SHA-256 %s, "
                           "expected %s" % (url, found, digest))
    shutil.rmtree(done, ignore_errors=True)
    with zipfile.ZipFile(archive) as unpacking:
        unpacking.extractall(done)
    os.remove(archive)
    with open(os.path.join(into, "unpacked.sha256"), "w") as handle:
        handle.write(digest + "\n")
    return done


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()
