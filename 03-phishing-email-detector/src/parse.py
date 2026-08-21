"""Turn raw RFC822 mail into a flat record table.

Run: python -m src.parse   ->  data/processed/emails.jsonl.gz

The important thing this module does is keep the header block and the body
strictly separate, because the whole leakage experiment depends on being able
to build a text view that provably contains no header material.
"""
from __future__ import annotations

import email
import email.policy
import gzip
import html as html_mod
import json
import re
import sys
from email.parser import BytesParser
from pathlib import Path

from .config import (
    BODY_CHAR_LIMIT,
    COLLECTION_ARTIFACT_HEADERS,
    DATA_PROCESSED,
    DATA_RAW,
    HAM_ARCHIVES,
    PHISH_ARCHIVES,
    SPAM_ARCHIVES,
)

HEADER_CHAR_LIMIT = 8_000

# A message separator in an mbox is a line starting with "From " followed by an
# address and an asctime date. Requiring the weekday avoids chopping a message
# in half at a body line that happens to begin with "From ".
MBOX_SEP = re.compile(
    rb"(?m)^From \S*\s+(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s",
)

_SCRIPT_STYLE = re.compile(
    r"<(script|style)\b.*?</\1\s*>", re.IGNORECASE | re.DOTALL
)
_TAG = re.compile(r"<[^>]{0,4000}>", re.DOTALL)
_WS = re.compile(r"[ \t\r\f\v]+")
_NL = re.compile(r"\n{3,}")


def strip_html(raw: str) -> str:
    """Crude but adequate tag stripper. We are not rendering the mail, only
    recovering the words a reader would have seen."""
    txt = _SCRIPT_STYLE.sub(" ", raw)
    txt = re.sub(r"<br\s*/?>|</p>|</div>|</tr>", "\n", txt, flags=re.IGNORECASE)
    txt = _TAG.sub(" ", txt)
    txt = html_mod.unescape(txt)
    txt = _WS.sub(" ", txt)
    return _NL.sub("\n\n", txt).strip()


def _decode(part) -> str:
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        return ""
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    for enc in (charset, "utf-8", "cp1252", "latin-1"):
        try:
            return payload.decode(enc, errors="strict")
        except (LookupError, UnicodeDecodeError):
            continue
    return payload.decode("latin-1", errors="replace")


def split_header_body(raw: bytes) -> "tuple[bytes, bytes]":
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = raw.find(sep)
        if idx != -1:
            return raw[:idx], raw[idx + len(sep):]
    return raw, b""


def _header_lines(header_block: str) -> "list[tuple[str, str]]":
    """Unfold a header block into (name, value) pairs without going through the
    email parser, so that malformed headers still show up in the text views."""
    out = []
    cur_name, cur_val = None, []
    for line in header_block.splitlines():
        if line[:1] in (" ", "\t") and cur_name is not None:
            cur_val.append(line.strip())
        elif ":" in line:
            if cur_name is not None:
                out.append((cur_name, " ".join(cur_val).strip()))
            name, _, val = line.partition(":")
            cur_name, cur_val = name.strip(), [val.strip()]
        # A line that is neither a continuation nor "name: value" (e.g. the
        # mbox "From " line) is dropped.
    if cur_name is not None:
        out.append((cur_name, " ".join(cur_val).strip()))
    return out


def is_artifact_header(name: str) -> bool:
    low = name.lower()
    return any(low.startswith(p) for p in COLLECTION_ARTIFACT_HEADERS)


FROM_LINE = re.compile(
    rb"^From \S*\s+(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s[^\n]*\n"
)


def parse_message(raw: bytes, source_file: str, label: int, idx: int) -> dict:
    # The SpamAssassin files keep their mbox "From " separator line; the
    # phishing mbox files have theirs stripped by the splitter. Removing it
    # everywhere matters: left in, it becomes a bogus "From <addr>  Thu Aug 22
    # 15" header on ham only (it contains a colon, so the header unfolder
    # accepts it) and hands the model a free label. That would be leakage I
    # introduced, which is not the leakage this project is about.
    raw = FROM_LINE.sub(b"", raw, count=1)
    header_bytes, body_bytes = split_header_body(raw)
    header_text = header_bytes.decode("utf-8", errors="replace")
    pairs = _header_lines(header_text)

    try:
        msg = BytesParser(policy=email.policy.compat32).parsebytes(raw)
    except Exception:
        msg = None

    plain_parts, html_parts = [], []
    if msg is not None:
        if msg.is_multipart():
            for part in msg.walk():
                if part.is_multipart():
                    continue
                ctype = (part.get_content_type() or "").lower()
                if ctype == "text/plain":
                    plain_parts.append(_decode(part))
                elif ctype == "text/html":
                    html_parts.append(_decode(part))
        else:
            ctype = (msg.get_content_type() or "").lower()
            text = _decode(msg)
            if ctype == "text/html":
                html_parts.append(text)
            else:
                plain_parts.append(text)

    if not plain_parts and not html_parts:
        # Undecodable MIME structure: fall back to the raw body so the record
        # is never empty. Happens on a handful of truncated phishing messages.
        plain_parts.append(body_bytes.decode("utf-8", errors="replace"))

    body_html = "\n".join(html_parts)
    body_plain = "\n".join(plain_parts)
    body_text = (body_plain + "\n" + strip_html(body_html)).strip()

    def hdr(name):
        for n, v in pairs:
            if n.lower() == name:
                return v
        return ""

    subject_raw = hdr("subject")
    try:
        subject = str(email.header.make_header(email.header.decode_header(subject_raw)))
    except Exception:
        subject = subject_raw

    kept = [(n, v) for n, v in pairs if not is_artifact_header(n)]
    return {
        "id": f"{source_file}#{idx}",
        "label": label,
        "source_file": source_file,
        "subject": subject[:1000],
        "from_raw": hdr("from")[:400],
        "date_raw": hdr("date")[:200],
        "n_headers": len(pairs),
        "header_names": sorted({n.lower() for n, _ in pairs}),
        "headers_full": header_text[:HEADER_CHAR_LIMIT],
        "headers_scrubbed": "\n".join(f"{n}: {v}" for n, v in kept)[:HEADER_CHAR_LIMIT],
        "body_html": body_html[:BODY_CHAR_LIMIT],
        "body_text": body_text[:BODY_CHAR_LIMIT],
        "raw_bytes": len(raw),
    }


def iter_maildir(dirname: str, label: int):
    root = DATA_RAW / "spamassassin" / dirname
    files = sorted(p for p in root.rglob("*") if p.is_file() and p.name != "cmds")
    for i, p in enumerate(files):
        yield parse_message(p.read_bytes(), f"{dirname}/{p.name}", label, i)


def iter_mbox(name: str, label: int):
    data = (DATA_RAW / name).read_bytes()
    starts = [m.start() for m in MBOX_SEP.finditer(data)]
    if not starts:
        return
    bounds = list(zip(starts, starts[1:] + [len(data)]))
    for i, (a, b) in enumerate(bounds):
        chunk = data[a:b]
        nl = chunk.find(b"\n")
        if nl != -1:
            chunk = chunk[nl + 1:]  # drop the "From " separator line itself
        if not chunk.strip():
            continue
        yield parse_message(chunk, name, label, i)


def write_jsonl_gz(path, records) -> None:
    """Deterministic gzip: mtime is pinned to 0 so that two runs of the
    pipeline produce byte-identical files, which is how we check determinism."""
    with open(path, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as gz:
            for r in records:
                gz.write((json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8"))


def main() -> int:
    records = []
    for arch in HAM_ARCHIVES:
        d = arch.replace(".tar.bz2", "")
        n0 = len(records)
        records.extend(iter_maildir(d, 0))
        print(f"ham   {d:28s} {len(records) - n0:6d}")
    for name in PHISH_ARCHIVES:
        n0 = len(records)
        records.extend(iter_mbox(name, 1))
        print(f"phish {name:28s} {len(records) - n0:6d}")

    out = DATA_PROCESSED / "emails.jsonl.gz"
    write_jsonl_gz(out, records)
    n_phish = sum(r["label"] for r in records)
    print(f"\n{len(records)} messages ({n_phish} phishing, {len(records) - n_phish} ham)")
    print(f"wrote {out} ({out.stat().st_size:,} bytes)")

    # The spam probe is written separately and is never read by the trainer.
    probe = []
    for arch in SPAM_ARCHIVES:
        d = arch.replace(".tar.bz2", "")
        n0 = len(probe)
        probe.extend(iter_maildir(d, -1))
        print(f"spam  {d:28s} {len(probe) - n0:6d}")
    pout = DATA_PROCESSED / "spam_probe.jsonl.gz"
    write_jsonl_gz(pout, probe)
    print(f"wrote {pout} ({pout.stat().st_size:,} bytes)")
    return 0


def load(path: "str | Path" = None) -> "list[dict]":
    path = Path(path) if path else DATA_PROCESSED / "emails.jsonl.gz"
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


if __name__ == "__main__":
    sys.exit(main())
