"""Password hashing with Argon2id, and the dummy-verify that closes the
user-enumeration timing leak.

Why Argon2id and not bcrypt:
  - bcrypt silently truncates at 72 bytes. A passphrase longer than that has its
    tail ignored, and the user is never told. Argon2 has no such limit.
  - bcrypt's cost parameter buys CPU time only. Its memory footprint is ~4 KiB,
    which fits in a GPU core's local memory, so a GPU or FPGA attacker gets a
    very large parallel speed-up. Argon2's memory cost is the defence against
    exactly that: 64 MiB per guess is what makes a 10000-core GPU useless,
    because 10000 x 64 MiB is 625 GiB of RAM the attacker does not have.
  - Argon2id is the hybrid: the first half-pass is data-independent (Argon2i,
    side-channel resistant) and the rest is data-dependent (Argon2d, better
    against time-memory trade-off attacks). RFC 9106 section 4 point 3 says to
    pick id if you do not know which you need or consider side channels a threat.
"""

from __future__ import annotations

import contextlib
import secrets
import threading
from typing import Any, Iterator

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .config import Config


class CapacityExhausted(RuntimeError):
    """Raised when too many Argon2 operations are already in flight.

    Exists because of what bench/bench_argon2.py measured. 64 MiB per verify on
    an unauthenticated endpoint means peak memory is set by whoever is sending
    the most requests: 16 concurrent attempts held 1 GiB, and the measured
    latency for a legitimate user went to 11x baseline. A counter-based rate
    limiter does not bound that, because it caps requests per username per
    window, not requests in flight right now.

    A concurrency cap does bound it. Peak transient memory becomes
    max_concurrent x 64 MiB regardless of offered load. The honest limitation:
    this protects the server from being pushed into swap or OOM, it does not
    make a flooded login fast. Excess requests queue, and requests that queue
    too long are refused with 503 and Retry-After rather than being left to
    pile up.
    """


class PasswordService:
    def __init__(self, config: Config) -> None:
        self.config = config
        self._hasher = PasswordHasher(
            time_cost=config.argon2_time_cost,
            memory_cost=config.argon2_memory_cost_kib,
            parallelism=config.argon2_parallelism,
            hash_len=config.argon2_hash_bytes,
            salt_len=config.argon2_salt_bytes,
            type=Type.ID,  # Argon2id
        )
        # The dummy hash is the fix for trap 1 (user enumeration by timing).
        #
        # Without it, POST /login for a username that does not exist returns as
        # soon as the SELECT misses -- microseconds. For a username that does
        # exist, it returns after an Argon2id verify -- tens of milliseconds.
        # That is a three-orders-of-magnitude difference visible over the
        # network, so anyone can enumerate valid accounts at request speed
        # without ever guessing a password. Identical error text does not help;
        # the clock is the oracle.
        #
        # So on the unknown-user path we verify the submitted password against
        # this throwaway hash and discard the result. Same parameters, so the
        # same work, so the same latency. The password behind it is random and
        # never stored anywhere, so the verify always fails, which is fine --
        # we ignore the answer.
        self._dummy_hash = self._hasher.hash(secrets.token_urlsafe(32))

        # Concurrency cap. The default of 4 is not a round number picked for
        # comfort: bench/bench_argon2.py measured throughput on this machine
        # peaking at 4 concurrent hashes (about 2x the serial rate) and getting
        # no better at 8 or 16, while p95 latency kept climbing and transient
        # memory kept doubling. Past 4, extra concurrency buys latency and
        # memory pressure and no throughput, so 4 is where the cap belongs.
        self._max_concurrent = max(1, config.argon2_max_concurrent)
        self._slots = threading.BoundedSemaphore(self._max_concurrent)
        self._queue_timeout_s = config.argon2_queue_timeout_s
        self._capacity_refusals = 0
        self._refusal_lock = threading.Lock()

    @contextlib.contextmanager
    def capacity(self) -> Iterator[None]:
        """Hold one of the Argon2 slots for the duration of the block.

        Every call site that performs Argon2 work goes through here, so peak
        memory is bounded by construction rather than by hoping the rate limiter
        got there first.
        """
        if not self._slots.acquire(timeout=self._queue_timeout_s):
            with self._refusal_lock:
                self._capacity_refusals += 1
            raise CapacityExhausted(
                f"more than {self._max_concurrent} password hashes in flight "
                f"for longer than {self._queue_timeout_s}s")
        try:
            yield
        finally:
            self._slots.release()

    @property
    def capacity_refusals(self) -> int:
        return self._capacity_refusals

    def capacity_limits(self) -> dict[str, Any]:
        return {
            "max_concurrent": self._max_concurrent,
            "queue_timeout_s": self._queue_timeout_s,
            "peak_transient_mib": round(
                self._max_concurrent * self.config.argon2_memory_mib(), 1),
            "refusals_so_far": self._capacity_refusals,
        }

    # --- hashing --------------------------------------------------------------

    def hash(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify(self, stored_hash: str, password: str) -> bool:
        """Verify, returning a bool instead of raising.

        argon2-cffi already compares the tag in constant time internally, so
        there is nothing to fix on that front; what matters is that both
        branches of this function cost the same, which they do, because the
        expensive part (deriving the tag) happens before any comparison.
        """
        try:
            self._hasher.verify(stored_hash, password)
            return True
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def verify_dummy(self, password: str) -> None:
        """Burn the same CPU and memory as a real verify, then throw it away.

        Called on the unknown-user path so that path costs what the known-user
        path costs. The return value is meaningless by construction.
        """
        try:
            self._hasher.verify(self._dummy_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            pass

    def needs_rehash(self, stored_hash: str) -> bool:
        """True when a stored hash used weaker parameters than we use now.

        Login is the only moment the server ever holds the plaintext, so it is
        the only moment a stored hash can be upgraded. Skipping this means old
        accounts keep 2019 parameters forever.
        """
        try:
            return self._hasher.check_needs_rehash(stored_hash)
        except InvalidHashError:
            # An unparseable hash cannot be upgraded in place; treat it as not
            # needing a rehash and let verify() fail it instead.
            return False

    def parameters(self) -> dict[str, Any]:
        return {
            "type": "Argon2id",
            "time_cost": self._hasher.time_cost,
            "memory_cost_kib": self._hasher.memory_cost,
            "memory_cost_mib": self._hasher.memory_cost / 1024,
            "parallelism": self._hasher.parallelism,
            "hash_len": self._hasher.hash_len,
            "salt_len": self._hasher.salt_len,
        }
