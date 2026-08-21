"""Fetch the raw corpora into data/raw/ and unpack the tarballs.

Run: python -m src.download

Downloads are cached by size: if the local file already matches the
Content-Length the server advertises, it is left alone. That keeps repeat runs
cheap and keeps the pipeline offline-reproducible once data/raw is warm.
"""
from __future__ import annotations

import hashlib
import sys
import tarfile

import requests

from .config import (
    DATA_RAW,
    HAM_ARCHIVES,
    NAZARIO_BASE,
    PHISH_ARCHIVES,
    SA_BASE,
    SPAM_ARCHIVES,
)

TIMEOUT = 120
CHUNK = 1 << 16


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def fetch(url: str, dest_name: str) -> "tuple[str, int, str]":
    dest = DATA_RAW / dest_name
    remote_len = None
    try:
        head = requests.head(url, timeout=TIMEOUT, allow_redirects=True)
        if head.ok:
            remote_len = int(head.headers.get("Content-Length", 0)) or None
    except requests.RequestException:
        pass

    if dest.exists() and remote_len and dest.stat().st_size == remote_len:
        print(f"  cached  {dest_name} ({dest.stat().st_size:,} bytes)")
        return dest_name, dest.stat().st_size, _sha256(dest)

    print(f"  GET     {url}")
    with requests.get(url, stream=True, timeout=TIMEOUT) as r:
        r.raise_for_status()
        tmp = dest.with_suffix(dest.suffix + ".part")
        with open(tmp, "wb") as fh:
            for chunk in r.iter_content(CHUNK):
                fh.write(chunk)
        tmp.replace(dest)
    size = dest.stat().st_size
    print(f"          -> {dest_name} ({size:,} bytes)")
    return dest_name, size, _sha256(dest)


def unpack(archive_name: str) -> None:
    """Unpack a SpamAssassin tarball. Each contains one directory of RFC822
    files with no extension, one message per file."""
    archive = DATA_RAW / archive_name
    marker = DATA_RAW / (archive_name.replace(".tar.bz2", "") + ".unpacked")
    if marker.exists():
        print(f"  unpacked already: {archive_name}")
        return
    target = DATA_RAW / "spamassassin" / archive_name.replace(".tar.bz2", "")
    target.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:bz2") as tf:
        # filter="data" refuses absolute paths and links; these are third-party
        # tarballs so we do not extract them blind.
        tf.extractall(target, filter="data")
    n = sum(1 for p in target.rglob("*") if p.is_file())
    marker.write_text(str(n), encoding="utf-8")
    print(f"  unpacked {archive_name}: {n} files")


def main() -> int:
    manifest = []
    print("SpamAssassin ham:")
    for name in HAM_ARCHIVES:
        manifest.append(fetch(SA_BASE + name, name))
    print("SpamAssassin spam (held-out probe):")
    for name in SPAM_ARCHIVES:
        manifest.append(fetch(SA_BASE + name, name))
    print("Nazario phishing:")
    for name in PHISH_ARCHIVES:
        manifest.append(fetch(NAZARIO_BASE + name, name))

    print("Unpacking:")
    for name in HAM_ARCHIVES + SPAM_ARCHIVES:
        unpack(name)

    lines = ["file,bytes,sha256"]
    lines += [f"{n},{s},{h}" for n, s, h in manifest]
    (DATA_RAW / "MANIFEST.csv").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nwrote {DATA_RAW / 'MANIFEST.csv'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
