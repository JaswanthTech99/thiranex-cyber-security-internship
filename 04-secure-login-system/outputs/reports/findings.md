# Findings

M Jaswanth Kumar. Every number below came from a run on this machine, recorded in
`summary_stats.json`, `argon2_bench.json`, `test_run.txt` and
`argon2_bench_run.txt` in this directory. Where a measurement contradicted what I
expected, that is called out rather than smoothed over.

Test machine: Windows 11 (build 26200), Intel Tiger Lake mobile CPU (Family 6
Model 140), 8 logical CPUs, 32448 MiB RAM, Python 3.14.4. It is a shared laptop
with unrelated processes running, which turned out to matter (finding 7).

Full suite as of the run recorded here: **272 of 272 checks passed**, across 8
suites, 248.8 s.

---

## 1. User enumeration by login response time

**The leak.** A login attempt for a username that does not exist can return as
soon as the `SELECT` misses. One for a username that does exist has to run an
Argon2id verify first. The difference is visible over the network and it does not
care that the error message and status code are identical.

**Measured, 150 interleaved samples per class per arm, seed 20260821:**

| | existing username | absent username | median gap | Cohen's d | single-request classifier |
|---|---|---|---|---|---|
| No mitigation | median 108.2 ms, p95 138.9, p99 161.0 | median 19.3 ms, p95 38.1, p99 42.0 | **+88.9 ms** | 6.38 | **100.0 %** |
| With mitigation | median 115.0 ms, p95 215.5, p99 270.1 | median 118.2 ms, p95 184.8, p99 300.7 | **-3.2 ms** | 0.067 | **51.3 %** |

Repeat runs during the full-suite passes gave +103.1 ms / 100.0 % and
+139.2 ms / 100.0 % without the fix, and -1.6 ms / 51.7 % and -0.6 ms / 54.7 %
with it. The direction and the magnitude of the effect are stable across runs; the
absolute values move with machine load, which is finding 7.

100 % single-request accuracy is the number that matters. It means an attacker
does not need statistics, repeat sampling, or a quiet network: one request per
candidate username tells them whether the account exists. At HTTP speed that is
an account list, and an account list is the input to every credential-stuffing
run. 51.3 % is chance.

**The fix** (`src/passwords.py`, `PasswordService.verify_dummy`): on the
unknown-user path, verify the submitted password against a throwaway hash built
with the same parameters, and discard the result. Same work, same latency. The
dummy hash is created at startup over `secrets.token_urlsafe(32)`, so it can
never match anything.

Alongside it, and necessary but not sufficient on its own: one error string
(`"Invalid username or password."`) and one status code for every failure mode,
routed through a single `login_failure_response()` helper so the branches cannot
drift apart. The suite asserts the status codes and client-visible messages are
set-identical between the two classes in **both** arms, so the timing experiment
is measuring only timing.

**What I did not claim.** The residual gap is -3.2 ms, i.e. the unknown-user path
came out marginally *slower* than the known-user one. With Cohen's d of 0.067
that is noise, not a reverse oracle, and I did not assert the gap is zero. A
dummy verify equalises the dominant cost, not every instruction; asserting
perfect equality would be a flaky test dressed up as a strong claim. The
assertion in the suite is that single-request accuracy falls below 70 %, which is
the property an attacker actually cares about.

Figure: `../figures/enumeration_timing.png`. The left column is two cleanly
separated distributions; the right column is two overlapping ones.

## 2. The lockout was almost a second enumeration oracle

Keying the failure counter on a resolved user id is the obvious implementation and
it reintroduces the leak the dummy hash just closed, by a different route: only a
real account can be locked, so six bad passwords against `alice` and six against
`alicx` tells the attacker which one exists. No timing analysis needed, and the
dummy-hash fix does not help at all.

`src/ratelimit.py` keys on the **submitted username string** instead. Measured:

- Real account: statuses `[401 x5, 429 x20]`, first 429 after exactly 5 failures.
- Username that does not exist: statuses `[401 x5, 429 x20]`, first 429 after
  exactly 5 failures, identical prefix.

The cost of that choice, stated plainly: an attacker can lock a known username
out by spraying it. That is a real per-account denial of service and it is the
standard trade-off of any lockout. It is bounded by the 15-minute lockout duration
and by a successful login clearing the counter (measured: after one successful
login, a full threshold of 5 is available again). If locking a user out were worse
than the enumeration leak, the answer would be a proof-of-work or CAPTCHA step,
not a lockout keyed on resolved users.

## 3. Session fixation

Login issues a brand-new session identifier and **deletes** the old row. Asserted
three ways, because "the new id differs" alone would also be true of a server
that kept honouring the old one:

- The pre-login id differs from the post-login id.
- The pre-login row is gone from the `sessions` table (asserted by opening the
  SQLite file read-only and looking).
- Re-presenting the pre-login cookie by hand returns 401, while the victim's own
  new session returns 200.

Rotation happens at every privilege change, not just at login. With 2FA enabled a
login walks `anonymous` -> `pending_2fa` -> `authenticated`, and all three
identifiers are distinct, with each superseded row deleted and each superseded
cookie refused. A `pending_2fa` session cannot read the protected page: password
success alone is not authentication.

Enabling 2FA also destroys every other session for that account. Measured: a
second live session for the same user returns 200 before enrolment and 401 after,
with its row deleted. If an attacker already had a session, turning on a second
factor should evict them rather than leave them logged in.

Logout deletes the row server-side, then clears the cookie. A client that keeps
the cookie holds an identifier that resolves to nothing (measured: 401).

## 4. SQL injection

**Corpus:** 390 unique payloads, fetched at run time from SecLists:

| file | payloads |
|---|---|
| `Fuzzing/Databases/SQLi/Generic-SQLi.txt` | 267 |
| `Fuzzing/Databases/SQLi/sqli.auth.bypass.txt` | 96 |
| `Fuzzing/Databases/SQLi/quick-SQLi.txt` | 77 |
| deduplicated total | **390** |

The exact corpus fired is recorded percent-encoded in `sqli_payloads_fired.txt`.

Each payload was fired into the username field and into the password field, at two
targets: 780 requests per target, 1560 in total.

| target | requests | authenticated | 5xx | status codes |
|---|---|---|---|---|
| `POST /login` (parameterised, `?` placeholders) | 780 | **0** | **0** | all 401 |
| `POST /demo/vulnerable/login` (string-concatenated) | 780 | **52** | 206 driver errors | mixed 401/200/500 |

Working bypasses against the vulnerable endpoint included `a' or 1=1--`,
`' or 0=0 --`, `x' or 1=1 or 'x'='y`, `hi' or 'a'='a`. The same strings against
the real endpoint produced 401 and nothing else.

"No 5xx" is asserted as hard as "none authenticated". A 500 would mean a payload
reached something that could not cope with it, which is both an information leak
through the error text and a hint that input is being parsed where it should not
be. Rejecting cleanly is the bar, not just rejecting.

A fresh account registered and logged in successfully after the entire corpus, so
nothing was corrupted or dropped.

**Honest limitation of the vulnerable demo.** Python's `sqlite3.Cursor.execute()`
refuses to run more than one statement, so stacked payloads like
`'; DROP TABLE users; --` cannot destroy anything even though the injection itself
succeeds. That is a property of the driver, not evidence the code is safe. The
authentication bypass, which is what matters for a login form, works exactly as it
would anywhere else. 206 of the 780 requests produced a raw driver error, which in
a real application is its own finding.

**Why rate limiting was off for this suite.** With the lockout on, payload six
onwards would be answered 429 and the run would prove nothing about the SQL layer:
every payload would be "rejected" by the limiter rather than by parameterisation.
That is stated in the test file rather than quietly arranged.

**Why input validation is not the injection defence.** The login endpoint
deliberately does not reject quotes or reject on validation rules at all;
parameterised queries are the defence. Filtering at the edge says the data layer
is unsafe and we are compensating for it, which fails the moment one code path
forgets. The password field accepts any printable character and the suite fires
the whole corpus at it.

## 5. Argon2id parameters as a genuine trade-off

Parameters: **Argon2id, t=3, m=2^16 KiB (64 MiB), p=4, 128-bit salt, 256-bit
tag** - RFC 9106 section 4, the SECOND RECOMMENDED option, quoted verbatim in
`src/config.py`.

**Why not the first recommended option** (t=1, p=4, m=2^21 = 2 GiB): it cannot be
run concurrently on ordinary hardware. Two simultaneous logins would hold 4 GiB.
The measured curve below shows 256 MiB already costs 417 ms per hash on this
machine; 2 GiB is not a login latency, it is a timeout.

**Measured cost curves** (8 interleaved rounds, random order per round, seed
20260821):

| m (MiB), t=3 | mean ms | p95 ms | serial hashes/s |
|---|---|---|---|
| 8 | 21.69 | 28.19 | 46.1 |
| 16 | 35.54 | 40.83 | 28.1 |
| 32 | 59.37 | 73.82 | 16.8 |
| **64 (chosen)** | **117.17** | **151.44** | **8.5** |
| 128 | 194.74 | 218.08 | 5.1 |
| 256 | 416.96 | 564.49 | 2.4 |

| t, m=64 MiB | mean ms | p95 ms |
|---|---|---|
| 1 | 49.98 | 55.51 |
| 2 | 97.14 | 153.40 |
| **3 (chosen)** | **113.12** | **135.14** |
| 4 | 145.45 | 173.54 |
| 6 | 210.33 | 247.58 |

The two sweeps agree where they overlap (m=64/t=3 measured 117.17 ms on one axis
and 113.12 ms on the other, 3.5 % apart), which is the internal consistency check
that the design is sound. On an otherwise idle machine the same parameters
measured mean 76.78 ms, median 74.24 ms, min 66.4 ms.

**Concurrency and the DoS shape.** Peak transient memory is
`concurrent_hashes x 64 MiB`. Measured throughput on 8 logical CPUs:

| concurrent hashes | hashes/s | speedup over serial | mean ms | p95 ms | transient MiB |
|---|---|---|---|---|---|
| 1 | 9.22 | 0.94 | 108.27 | 116.89 | 64 |
| 2 | 14.72 | 1.54 | 135.59 | 167.45 | 128 |
| 4 | 10.73 | 1.14 | 365.77 | 597.81 | 256 |
| 8 | 14.51 | 1.62 | 540.76 | 727.14 | 512 |
| 16 | 13.41 | 1.71 | 1156.10 | 1506.23 | 1024 |

Threading buys at most about 1.7x on 8 logical cores, and the throughput column is
visibly noisy (the 4-thread row is below the 2-thread row, which is measurement
noise on a busy laptop, not a real dip). Latency, by contrast, rises cleanly and
steeply: 16 in flight means over a second per hash and 1 GiB held. The useful
reading is that **concurrency does not buy throughput here but does buy latency
and memory pressure**, which is what motivated the cap in finding 6.

## 6. The DoS mitigations did not do what I expected

An unauthenticated endpoint that allocates 64 MiB on demand is a DoS primitive. I
measured a legitimate user's login while attacker threads flooded `POST /login`
with wrong passwords for other usernames, across three arms.

| arm | 4 attacker threads | 16 attacker threads |
|---|---|---|
| No protection | p95 506.65 ms (3.67x baseline), served 100 % | p95 1354.52 ms (**9.82x**), served 100 % |
| Concurrency cap only | p95 386.54 ms (3.69x), served 100 % | p95 1758.10 ms (**16.79x**), served 100 % |
| Cap + rate limiting | p95 266.17 ms (2.48x), served 100 % | p95 100.35 ms (0.93x), **served 0 %** |

Two results here contradicted what I expected, and both are more interesting than
the result I wanted.

**First: the "best" latency number was a denial.** In the rate-limited arm at 16
attacker threads, the victim's p95 came out at 0.93x baseline - apparently perfect
protection. It was not. The victim was receiving **429**, 0 % of their logins
succeeded, and the low latency was the cost of being refused rather than served.
The per-IP limiter (30 failures per 300 s) had tripped on the attackers' traffic,
and because every request in this test comes from 127.0.0.1, the legitimate user
was inside the same bucket. This is the classic collateral damage of IP-based
limiting, the same thing that punishes users behind CGNAT or a corporate egress. I
only caught it because the benchmark was changed to record the victim's status
code and success rate, not just latency. Measuring latency alone would have
produced a confident and wrong conclusion.

**Second: the concurrency cap made latency worse, not better.** The cap
(`src/passwords.py`, `BoundedSemaphore` of 4 slots, 5 s queue timeout) bounds peak
transient memory to 4 x 64 MiB = 256 MiB regardless of offered load, down from
1 GiB at 16 in flight. That part works. But at 16 attacker threads the victim's
p95 went to 16.79x baseline, *worse* than the 9.82x with no protection at all,
because the cap makes the victim queue behind the attackers instead of competing
with them. The cap protects the server from being pushed into swap or OOM; it does
not protect an individual user's latency, and I am not going to claim it does.

**Honest conclusion for this trap.** None of the three arms preserves availability
for a legitimate user under flood from the same source address. The controls trade
the failure mode around rather than removing it: unbounded memory growth, or
bounded memory plus queuing latency, or a hard refusal. Doing better needs a
different shape of control than anything in this project's scope - per-IP
concurrency fairness rather than per-IP failure counting, a proof-of-work or
CAPTCHA step so an attempt costs the attacker something too, a separate queue for
requests already carrying a valid session, and moving the Argon2 work off the
request-handling loop entirely so it cannot starve it. The parameter choice is
defensible; the availability story at m=64 MiB is not solved, it is bounded and
documented.

The cap value of 4 is measurement-driven rather than chosen for tidiness: finding
5 shows throughput on this machine stops improving past roughly 2 to 4 concurrent
hashes while latency and memory keep climbing, so past that point extra
concurrency is pure cost.

## 7. Benchmark methodology, and a measurement I had to throw away

The first version of `bench/bench_argon2.py` measured each configuration to
completion before moving to the next. It produced numbers that were impossible:
t=1 at m=64 MiB came out at 56.36 ms while t=3 at the same memory cost had come
out at 54.12 ms in an earlier phase. Three passes over the same memory cannot be
faster than one.

The cause was drift. This is a mobile CPU; a few minutes of sustained Argon2 load
makes it throttle, and available RAM on this laptop moved between 8902 MiB and
4705 MiB across runs as other processes came and went. Running configurations in
sequence meant later ones were measured on a slower machine, so the parameter axis
and the wall-clock axis were confounded.

The rewrite measures one hash per configuration per round, in a fresh random order
each round, with a drift probe re-measuring the chosen parameters once per round.
Drift is then a reported number rather than a hidden one: 1.055x between the first
and second half of the final run, and 1.829x on an earlier run when the machine
was busier. The chosen parameters were also re-measured after the whole benchmark:
median 106.53 ms after load versus 74.24 ms before it.

The practical consequence, and it is relevant to finding 6 rather than being a
methodology footnote: **the cost of a login is not a constant.** It is a function
of what else the machine is doing, and making the machine busy is precisely the
attacker's goal. A capacity plan built on the idle-machine figure of 74 ms is
planning for a state that does not hold under attack.

## 8. TOTP

Implemented from `hmac`, `hashlib` and `struct` in `src/totp.py`; pyotp is not a
dependency. Validated against the published vectors, **92 of 92 checks passing**:

- RFC 4226 Appendix D, Table 1: all 10 intermediate HMAC-SHA-1 values.
- RFC 4226 Appendix D, Table 2: all 10 dynamic-truncation values (hex and decimal)
  and all 10 HOTP outputs. The truncation is recomputed independently in the test,
  so a wrong offset or a missing sign mask fails there and not only in the final
  digits.
- RFC 6238 Appendix B: all 18 TOTP values, 6 timestamps x SHA1/SHA256/SHA512, 8
  digits, plus the value of T in hex at each timestamp.

**RFC 6238 erratum.** The prose above Appendix B says the shared secret is the
20-byte ASCII string `12345678901234567890`, but the SHA256 and SHA512 rows in the
table were produced by the Java reference implementation in Appendix A, which uses
a 32-byte seed and a 64-byte seed (`seed32`/`seed64`). This is Errata ID 2866. The
test uses the reference implementation's seeds because those are what reproduce
the published numbers, and it *asserts the discrepancy explicitly* - two checks
confirm the 20-byte prose seed does **not** reproduce the SHA256 and SHA512 rows -
so the next person does not have to rediscover it.

**Replay prevention.** `totp_last_counter` per user; a counter less than or equal
to the last one used is refused. The check and the write are one atomic statement
(`UPDATE ... WHERE totp_last_counter IS NULL OR totp_last_counter < ?`) so two
concurrent requests carrying the same code cannot both win. Verified end-to-end:
reusing a code that had just authenticated returns 401.

**Skew window:** plus or minus one 30 s step, so a 90 s acceptance window. RFC 6238
section 5.2 tells validators to keep this as small as possible and warns that a
window of W steps multiplies an online guesser's per-attempt success probability
by (2W+1). One step covers a user typing a code as it rolls over and a phone clock
a few tens of seconds out; worse than that is a broken client clock and the fix is
NTP on the client, not a looser server.

**A real consequence of the replay guard, found by the test suite.** Confirming
enrolment consumes a code, which burns that counter. A login attempted within the
same 30 s step is therefore refused - and the first run of the end-to-end test
failed on exactly that, having assumed the login would succeed. The app was right
and the test was wrong; the test now waits for the counter to advance (measured
wait, recorded in `summary_stats.json`). It is documented here because this is
precisely the sort of correct behaviour that gets "fixed" by weakening the replay
check. In the product it is invisible: confirming enrolment already leaves the
user authenticated, so nobody needs to log in during those seconds.

## 9. Breach check and k-anonymity

Registration rejects passwords found in Have I Been Pwned, via the range API.

Measured: `"password"` has SHA-1 `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8`,
appears **52,372,427** times in the corpus, and its prefix bucket `5BAA6` returned
**1978 real candidate suffixes** plus **145 zero-count padding entries**. A
password unique to this project returned a bucket of comparable size and no match,
so a hit and a miss look the same from outside.

The privacy property: only the first 5 hex characters - 20 bits - leave the
machine. The server learns that someone asked about one of roughly 2000 passwords
sharing that prefix and cannot tell which; that is the *k* in k-anonymity, with k
measured at 1978 for this bucket. The remaining 35 characters are compared
locally, with `hmac.compare_digest`. Asserted in the suite: the full hash does not
appear in the request URL, and neither does the suffix.

`Add-Padding: true` is sent because response size would otherwise leak - buckets
differ in size, and an observer watching TLS record lengths could narrow down
which prefix was asked for without seeing the URL. Padding entries carry a count
of 0, which is why the parser drops zero counts; a genuinely breached password
always has a count of at least 1.

**Fail-open, deliberately.** If the API is unreachable, registration proceeds and
the app logs a warning. Failing closed would convert someone else's outage into
ours, and this check is defence in depth on top of a 12-character minimum and
Argon2id, not the thing holding the door. For a system where account takeover is
expensive I would fail closed and accept the outage. The caller can distinguish
the two cases via `BreachResult.available`.

## 10. Smaller decisions worth recording

- **Sessions are server-side.** Flask's default signed-cookie session cannot be
  revoked: the state lives in the cookie, so logout can only ask the browser
  nicely. The task requires server-side invalidation, so the cookie holds a
  256-bit opaque `secrets.token_urlsafe` value and the table holds everything
  else.
- **The table stores SHA-256 of the session id, not the id.** A leaked database,
  backup or log does not hand over live sessions. No work factor is needed because
  a 256-bit random value has no dictionary. It also means lookup is by primary key
  on a hash, so no comparison timing can leak.
- **Two timeouts, because they stop different things.** Idle 1800 s: an unattended
  browser stops being a way in. Absolute 28800 s: a stolen identifier expires even
  if the thief keeps it warm. Both verified against short configured values,
  including that activity refreshes the idle clock but does not extend the
  absolute one - a continuously polled session was still killed at the absolute
  limit after 9 successful polls.
- **Cookie flags:** `Secure` on by default, `HttpOnly`, `SameSite=Lax`, `Path=/`,
  no `Expires`/`Max-Age`. Lax rather than Strict because Strict breaks arriving
  from an emailed link while Lax already blocks the cross-site POST that CSRF
  needs, and a synchroniser token is carried as well. Verified that a `Secure`
  cookie is not returned over plain HTTP, which is why the test harness runs with
  `--insecure-cookies` and why that flag prints a warning.
- **CSRF** tokens are bound to the session and compared with
  `hmac.compare_digest`. The token rotates with the session, verified: a pre-login
  token is refused on a post-login action. `/logout` is POST only - a GET logout is
  forcible from any page with an `<img>` tag.
- **No composition rules.** NIST SP 800-63B section 5.1.1.2 says verifiers should
  not impose them; they push users to `Password1!` and buy nothing measurable. A
  12-character minimum, a 128-character maximum to bound Argon2's input, and a
  breach check instead. 64-character passphrases are accepted, as the same section
  requires.
- **NFKC normalisation** on usernames and passwords. Without it, `admin` can be
  spelled several ways that compare unequal as bytes but look identical to a
  human. Verified: a fullwidth spelling of `admin` normalises to `admin` and is
  then caught by the reserved list. Passwords are normalised but **not** stripped -
  a leading space is a legitimate character and silently removing it makes a
  password the user cannot reproduce elsewhere.
- **Parameter upgrades at login.** Login is the only moment the server holds the
  plaintext, so it is the only moment a stored hash can be re-hashed at stronger
  parameters. Verified that a hash made with weaker parameters is flagged for
  rehash and still verifies, so nobody is locked out by an upgrade.
- **The app's latency floor is about 25 ms**, measured: `GET /healthz` (no session
  work, no writes) averaged 24.9 ms and `GET /login` (session load plus a
  `last_seen_at` commit) 25.5 ms. So a lockout-rejected login attempt at 28.1 ms is
  essentially free of Argon2 work, but it is only 3.04x cheaper than a hashed
  attempt (85.6 ms) rather than the orders of magnitude I first assumed. The
  per-request SQLite commit dominates. I had asserted a 3x gap before measuring it
  and the first run failed at 2.8x; the assertion was replaced with one about the
  property that actually matters (the rejected path costs no more than the session
  baseline).
- **The secret key is never written to disk.** Generated at runtime with
  `secrets.token_bytes(32)` unless `SLS_SECRET_KEY` is set. Because auth state is
  not carried in a signed cookie, this key is not what protects a session - the
  256-bit identifier and the server-side table are. `/healthz` reports which
  source was used and never the value.
