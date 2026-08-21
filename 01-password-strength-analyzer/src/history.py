"""Per-user password history, so an old password cannot be re-used.

This is the "integrate with a database to prevent reuse of old passwords" feature
from the brief. It stores two things per retired password:

1. An Argon2id hash. This detects *exact* re-use and nothing else - a hash is
   opaque by construction, which is the point.

2. A keyed HMAC-SHA256 of the password's "skeleton": lower-cased, leet folded
   back to letters, trailing digits and punctuation removed. This detects the
   thing exact-hash comparison misses entirely - `Summer2024!` retired and
   `Summer2025!` chosen as its replacement. Cracking rulesets try exactly that
   mutation first, so a history check that lets it through has not done its job.

The judgement call, stated plainly: the skeleton HMAC is a deliberate weakening.
It buckets passwords that share a root, so an attacker holding the HMAC key and
the database learns which of a user's passwords were variations of each other.
It is accepted here because (a) the key lives outside the database, so stealing
one table is not enough, (b) the HMAC is over a *stripped* string, so it never
confirms a full password, and (c) blocking suffix-increment re-use is worth more
in practice than the residual leak costs. A deployment that disagrees can set
`track_skeletons=False` and keep exact-match-only history.
"""
from __future__ import annotations

import hmac
import secrets
import sqlite3
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from argon2.low_level import Type

from .guessing import LEET_REVERSE

# RFC 9106, section 4, second recommended option: t=3, m=64 MiB, p=4.
HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4,
                        hash_len=32, salt_len=16, type=Type.ID)

SCHEMA = """
CREATE TABLE IF NOT EXISTS password_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       TEXT    NOT NULL,
    retired_at    TEXT    NOT NULL,
    argon2_hash   TEXT    NOT NULL,
    skeleton_hmac TEXT
);
CREATE INDEX IF NOT EXISTS ix_history_user ON password_history(user_id);
"""


TRAILING_JUNK = "0123456789!@#$%^&*()_+-=.,?~`"


def skeleton(password: str) -> str:
    """Strip a password down to the root a cracking rule would mutate.

    Order matters, and getting it wrong is easy: the leet table maps digits onto
    letters (2->z, 0->o, 4->a), so folding before trimming turns `Summer2024!`
    into `summerzozai` and the trailing-digit trim then finds nothing to remove.
    Trim the suffix first, then fold what is left.
    """
    trimmed = password.strip().rstrip(TRAILING_JUNK)
    return "".join(LEET_REVERSE.get(c.lower(), c.lower()) for c in trimmed)


class PasswordHistory:
    def __init__(self, db_path: str | Path, key_path: str | Path | None = None,
                 track_skeletons: bool = True) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.track_skeletons = track_skeletons
        # The HMAC key is kept in its own file, never in the history table.
        self.key_path = Path(key_path) if key_path else self.db_path.with_suffix(".hmac_key")
        if not self.key_path.exists():
            self.key_path.write_bytes(secrets.token_bytes(32))
        self.key = self.key_path.read_bytes()
        self.conn = sqlite3.connect(self.db_path)
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def _hmac(self, password: str) -> str:
        return hmac.new(self.key, skeleton(password).encode("utf-8"), sha256).hexdigest()

    def retire(self, user_id: str, password: str) -> int:
        """Record a password the user is moving away from."""
        row = (
            user_id,
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            HASHER.hash(password),
            self._hmac(password) if self.track_skeletons else None,
        )
        cur = self.conn.execute(
            "INSERT INTO password_history (user_id, retired_at, argon2_hash, skeleton_hmac)"
            " VALUES (?, ?, ?, ?)",
            row,
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def check(self, user_id: str, candidate: str) -> dict[str, object]:
        """Is this candidate a re-use, or a mutation of one, of a past password?"""
        rows = self.conn.execute(
            "SELECT id, retired_at, argon2_hash, skeleton_hmac FROM password_history"
            " WHERE user_id = ? ORDER BY id DESC",
            (user_id,),
        ).fetchall()

        exact_id = None
        for rid, _retired, h, _sk in rows:
            try:
                if HASHER.verify(h, candidate):
                    exact_id = rid
                    break
            except (VerifyMismatchError, InvalidHashError):
                continue

        near_ids: list[int] = []
        if self.track_skeletons:
            cand_hmac = self._hmac(candidate)
            near_ids = [rid for rid, _r, _h, sk in rows
                        if sk and hmac.compare_digest(sk, cand_hmac) and rid != exact_id]

        return {
            "history_size": len(rows),
            "exact_reuse": exact_id is not None,
            "exact_match_id": exact_id,
            "near_reuse": bool(near_ids),
            "near_match_ids": near_ids,
            "skeleton": skeleton(candidate) if self.track_skeletons else None,
        }

    def close(self) -> None:
        self.conn.close()
