# Thiranex Cyber Security Internship

**M Jaswanth Kumar** — four projects, built on real public data and real specifications.

Each project runs end to end, and every number in every README comes from an execution that
actually happened. Where a result contradicted what I expected, or where the tool turned out
to be wrong, that is written up rather than smoothed over — those sections are the ones worth
reading.

| # | Project | What it is | The finding that mattered |
|---|---|---|---|
| 1 | [Password Strength Analyzer](01-password-strength-analyzer) | Guess-number estimation over 1M real breached passwords, HIBP k-anonymity lookup, Argon2id re-use history | Matched on length and character classes, the signup-form meter and charset-entropy meter both score **exactly 0.500 AUC**. Unmatched, the composition meter scores **0.277** — worse than chance, because it rates breached passwords above real passphrases |
| 2 | [Vulnerability Scanner](02-vulnerability-scanner) | Pure-Python TCP/TLS/HTTP scanner with NVD + CISA KEV + FIRST EPSS correlation | 41 CVEs matched OpenSSH 6.6.1p1, **100% unconfirmed** (Ubuntu backports) and **0 in KEV**. The most likely-to-be-exploited one (EPSS 0.986) is only CVSS 5.3, so a CVSS-sorted report buries it |
| 3 | [Phishing Email Detection Model](03-phishing-email-detector) | scikit-learn over SpamAssassin ham + Nazario phishing, URL/keyword/TF-IDF features | The header `Status:` appears on **5,010 of 5,010** phishing and **0 of 4,150** legitimate messages — 1.0000 accuracy with no model at all. Hold MIME format constant and ROC-AUC falls to 0.9729 |
| 4 | [Secure Login System](04-secure-login-system) | Flask + SQLite, Argon2id (RFC 9106), TOTP from RFC 4226/6238, 272/272 checks | User enumeration by timing: an **88.9 ms** gap let one request identify accounts with 100% accuracy. And **neither** DoS mitigation worked — rate limiting's perfect-looking p95 was the victim getting 429s |

## What these four have in common

**Real inputs, never synthesised.** SecLists breach corpora and the live Have I Been Pwned API;
`scanme.nmap.org` and badssl.com with the NVD, KEV and EPSS feeds; the SpamAssassin and Nazario
mail archives; RFC 9106 parameters, the RFC 4226/6238 test vectors, and SecLists SQLi payload
lists. No `np.random` standing in for a dataset, no stubs.

**The interesting result is usually the negative one.** Project 1 reports that nine of fifteen
confirmed-breached passwords are rated "Strong" by its own estimator, which is the argument for
layering a breach lookup over it. Project 2 documents two false results the scanner produced
about itself. Project 3 measures how much of its own 0.9996 AUC is archive-discrimination
rather than phishing detection. Project 4 concludes that its availability controls move the
failure mode around instead of removing it.

**Reproducible.** Fixed seed 20260821, pinned `requirements.txt` per project, and an explicit
run command in each README. Projects 1 and 2 additionally regenerate byte-identical reports
across runs, verified by hash.

**Scope and privacy are handled in code, not in a disclaimer.** The scanner refuses any target
outside an allowlist, and separates "may be sent an HTTP request" from "may be port-scanned",
because those are different acts. The phishing project deliberately does not commit its parsed
message bodies: they are real 2002–2006 emails with live addresses and full `Received:` chains,
and republishing a parsed copy is not the same as citing the public archive.

## Layout

Each project is self-contained and follows the same shape:

```
NN-project-name/
  README.md            problem, data, decisions, findings, how to run
  requirements.txt     pinned
  src/                 importable modules, run with `python -m src.X`
  data/raw/            downloaded inputs (gitignored, re-fetchable)
  data/processed/      derived artifacts
  outputs/figures/     generated charts
  outputs/reports/     findings.md + summary_stats.json
```

Start with each project's `outputs/reports/findings.md` — it is generated from the run, so it
cannot drift from the numbers that produced it.
