# Phishing Email Detection Model

M Jaswanth Kumar — Cyber Security internship, project 3

A scikit-learn classifier that labels an email "Phishing" or "Safe" from its text and
its URLs, trained on two public corpora of real RFC822 mail. It reports accuracy and a
confusion matrix, as the brief asks, and then spends most of its effort arguing that
neither of those numbers means what it appears to mean.

**Headline result: 0.9895 accuracy, 0.9996 ROC-AUC** — random forest, subject and body
only with body-level collection artifacts removed, evaluated on a near-duplicate-grouped
split. Confusion matrix on the 2,290-message test fold: TN 1034, FP 3, FN 21, TP 1232.

**Headline caveat, also measured:** hold the MIME format constant (compare only messages
with no HTML part, on both sides) and ROC-AUC falls to **0.9729** with average precision
falling from 0.9997 to 0.9412. Score 1,897 held-out generic spam messages and **42.5% of
them are flagged as phishing**. Both of those say the same thing: a large part of the
0.9996 is the model telling two archives apart, not telling phishing from safe mail.

Everything below comes from real runs. `outputs/reports/findings.md` is generated
directly from `outputs/reports/summary_stats.json`, so no number in the write-up can
drift from the run that produced it.

---

## The problem, and why the obvious approach gives a wrong answer

There is no public dataset of "phishing and legitimate mail from the same mailbox". What
exists is a corpus of legitimate mail collected by one person and a corpus of phishing
collected by another, years apart, with different tooling. So the moment you concatenate
them you have built a dataset where the label is predictable from a hundred things that
have nothing to do with phishing.

This is not a hypothetical. In this corpus, the header field `Status:` appears on
5,010 of 5,010 phishing messages and 0 of 4,150 legitimate ones. That single boolean —
an IMAP read-flag written by the collector's own mail client — classifies the dataset
with **1.0000 accuracy**. No text, no features, no model.

So the project is organised around one question: how much of the score survives when you
take away the reasons that are not about phishing? The answer is produced by running the
same estimator over four progressively more restricted views of each message, crossed
with two split strategies:

| text view | what the model sees | ROC-AUC (grouped split) | accuracy |
| --- | --- | --- | --- |
| `full` | the whole file, every header plus body | 0.9998 | 0.9926 |
| `headers_scrubbed` | headers minus 40 known artifact fields, plus body | 0.9990 | 0.9803 |
| `content` | subject line and body only | 0.9987 | 0.9734 |
| `content_hardened` | subject and body, named body artifacts removed | 0.9987 | 0.9721 |

The full grid, both split strategies, and the coefficient tables that name the leaking
tokens are in `outputs/reports/findings.md`.

## What I found

Five findings, in the order they turned up. The third one is a negative result and is the
most interesting.

**1. The headers give away the label with no model at all.** `Status`, `X-Keywords`,
`X-UID`, `X-Status` are the collector's mail-client bookkeeping and appear on the
phishing side only. `Precedence`, `List-Id`, `Sender` appear on the ham side only,
because most of the SpamAssassin ham is mailing-list traffic. Given the whole file, the
model's strongest phishing indicators are `2006`, `aug 2006`, `2005`, `x-original-to:`,
`status:` — it is reading the clock and the collector's software.

**2. A header blocklist does not fix it.** Removing every field in
`config.COLLECTION_ARTIFACT_HEADERS` moves ROC-AUC from 0.9993 to 0.9988. The surviving
headers carry the same information, and the top coefficient is now
`to: undisclosed-recipients:` followed by `nobody@example.com` and
`username@domain.com` — Nazario anonymised the recipients in his archive, the ham has
real ones, and `To` is not on anybody's list of spam-filter artifacts.

**3. The body leaks too, and deleting the leaks changes nothing.** With headers gone the
model still scored 0.9987 AUC, using `url:`, `date:`, `2002`, `spambayes` as its
strongest "safe" signals. Those are archive properties: 15% of the ham are RSS digests
whose body literally begins `URL: http://...` / `Date: 2002-10-08T...`, 36% name their
own mailing list, 54% contain the string "2002" against 0.2% of the phishing. So I built
`content_hardened`, which deletes the RSS prefix and list-management lines, strips a
named list of corpus terms, and replaces URLs, email addresses, years and digit runs with
placeholders.

ROC-AUC went from 0.9987 to 0.9987.

The coefficients show why: the model dropped the artifacts and picked up `that`, `of`,
`it`, `and`, `in`, `is`, `which` — English function words. The ham is people writing
paragraphs on 2002 discussion lists; the phishing is short templated marketing copy. The
model replaced one perfect separator with another of equal strength. **Leakage in a
two-corpus dataset is redundant**: the archives differ in dozens of correlated ways at
once, and removing one channel just routes the model through the next. That is a stronger
claim than the one I set out to demonstrate, and it is the reason I do not present
`content_hardened` as clean.

**4. The largest single confound is MIME, not text.** 93.4% of the phishing messages
have an HTML part; 4.5% of the legitimate ones do. `has_html` used as the entire
classifier scores 0.9436 accuracy, and HTML-structure features hold the top five slots in
the random forest's importance ranking. This cannot be preprocessed away, because format
is a property of the message. The only clean measurement is to hold it constant:

| subset | class sizes | ROC-AUC | avg precision | recall @ FPR<=0.1% |
| --- | --- | --- | --- | --- |
| whole corpus | 1037 legit / 1253 phish in test | 0.9987 | 0.9997 | 0.9808 |
| plain-text only | 3962 legit / 329 phish | 0.9729 | 0.9412 | 0.1585 |

Recall at a 0.1% false-positive budget goes from 98% to 16%. That is the number I would
quote if asked how well this detects phishing rather than how well it separates two
archives. The plain-text subset is small and skewed, so treat it as directional — but a
noisy measurement of the right quantity beats a precise measurement of the wrong one.

**5. Near-duplicate campaigns inflate a random split — and ROC-AUC cannot see it.** The
5,010 phishing messages are only 1,948 distinct campaigns; 72.6% of them have a near-twin
in the corpus, against 11.0% of the ham. Under a random split, 70.5% of test phishing
messages have a near-duplicate sitting in training. Under the grouped split, none do.

| view | ROC-AUC delta | accuracy@0.5 delta | recall @ FPR<=0.5% delta |
| --- | --- | --- | --- |
| `full` | -0.0005 | +0.0026 | +0.0000 |
| `headers_scrubbed` | -0.0002 | +0.0057 | +0.0120 |
| `content` | -0.0005 | +0.0092 | +0.0207 |
| `content_hardened` | -0.0006 | +0.0087 | +0.0183 |

(delta = random minus grouped; positive means the random split flattered the model)

The AUC column is the wrong sign and far too small to resolve on a single fold, because
AUC and average precision are both pinned above 0.998 everywhere in this grid — there is
no headroom left in which to observe a difference. "The grouped split made no difference
to AUC" would have been a true statement and a wrong conclusion. Recall at the 0.5%
false-positive budget shows the effect plainly: campaign leakage is worth one to two
points of detection rate at a deployable threshold.

Note also that on the `full` view the split strategy is worth exactly nothing, on every
metric. Header leakage has already saturated the model, leaving no room for duplicate
leakage to contribute. **You cannot measure the second problem until you have fixed the
first**, which argues for doing leakage analysis in stages rather than from one summary
number.

The effect is still smaller than I expected. Three quarters of the phishing side is
duplicated, so I assumed campaign leakage would dominate; instead it is worth one or two
points where header leakage was worth twenty. Probably because these campaigns resemble
phishing in general and not only each other, so having seen 1,900 others already tells
the model most of what the exact duplicate would.

**And one more:** 42.5% of 1,897 held-out generic spam messages — bulk junk, not
credential phishing, never trained on — are flagged as phishing. The negative class here
is mailing-list and personal mail, so nothing in the training data distinguishes "bulk
commercial junk" from "credential theft". Part of what this model learned is a spam
filter.

## Feature engineering

65 hand-built numeric features alongside TF-IDF over the text (word 1-2 grams,
`min_df=3`, `sublinear_tf`, custom token pattern that keeps `x-keywords` and
`user@example.com` intact so the coefficient tables can name the real culprits).

Each feature is documented at its definition in `src/features.py` with the deception it
is meant to catch. The URL group:

- **`has_ip_url`, `n_ip_urls`** — a raw IP in place of a hostname means nobody registered
  a domain. Cheap and disposable. Fires on 28.4% of phishing and 0.12% of legitimate mail.
- **`has_at_in_url`** — `http://www.paypal.com@evil.ru/`. Everything before the `@` is
  userinfo and is ignored by the browser, so the visible brand is decoration.
- **`has_obfuscated_ip`** — decimal or hex-encoded addresses, which hide the destination
  from a reader who knows to look.
- **`has_punycode`** — `xn--` hosts, the homograph attack vector.
- **`max_subdomain_depth`** — labels in front of the registrable domain.
  `login.paypal.com.evil.ru` scores 3. Deep prefixes are how look-alike hosts are built.
- **`url_max_entropy`, `url_mean_entropy`, `url_max_len`** — Shannon entropy over URL
  characters. High entropy means a random-looking payload path or an encoded redirect.
- **`brand_host_abuse`** — a brand name appears in the URL but the registrable domain is
  not that brand's. 47.1% of phishing against 1.6% of legitimate mail.
- **`anchor_host_mismatch`, `anchor_mismatch_rate`** — anchors whose visible text names a
  different host than the `href`. The most direct tell in HTML mail: the text says
  paypal.com, the link goes elsewhere. 49.2% against 1.5%, the best of the URL features.
- **`has_shortener`, `has_nonstd_port`, `has_risky_path_ext`, `pct_encoding_count`,
  `max_host_hyphens`, `max_host_digits`, `frac_https`, `n_unique_tlds`,
  `hosts_per_url`** — the rest of the URL surface.

The HTML group covers `n_forms`, `n_password_inputs`, `form_action_external` (a form
inside an email is the whole attack: it harvests credentials without the victim leaving
their mail client), `has_javascript_uri`, `n_iframe`, `n_script`, `n_onevent`,
`n_remote_images`, `html_tag_ratio`. The text group covers length, digit and uppercase
ratios, and a 12-entry lexicon of credential-harvesting phrases (`kw_verify`,
`kw_suspend`, `kw_dear_customer`, `kw_ssn`, ...).

Four of the twelve I checked prevalence for do not work, and I am saying so rather than
quietly dropping them. `has_shortener` and `has_punycode` are near zero on both classes,
because URL shorteners and internationalised domains were barely in use in 2004-2007.
`has_at_in_url` is the textbook userinfo trick (`http://paypal.com@evil.ru/`) and appears
in 0.06% of the phishing. `n_forms` surprised me most: a credential form embedded in the
mail body is supposed to be the signature move, and it appears in 1.98% of phishing
against 1.25% of legitimate mail — essentially no discrimination. These kits linked out
to a hosted page instead. All four stay in the feature set because they cost nothing and
would matter on modern mail, but on this corpus they are not doing the work.

Ablation: for the logistic regression the engineered features do not help — TF-IDF alone
gets 0.9991 AUC against 0.9987 for the combination. Most likely a scaling artifact
(L2-normalised sparse text next to 65 standardised dense columns under one penalty). In
the random forest they hold 48.7% of total importance from 65 of 2,065 columns, so they
earn their place in the tree model and not in the linear one.

## Evaluation

Accuracy and a confusion matrix are reported because the brief asks for them. They are
not what I would use to decide whether to ship this.

A false positive is a legitimate message filed as an attack — an invoice, a password
reset, a note from a colleague, now in a quarantine folder nobody reads. A false negative
is one more phishing mail in an inbox that already gets them, in front of a user who is
the next control in the chain. Those costs differ by orders of magnitude and accuracy
weights them equally. On a realistic class balance — phishing well under 1% of mail —
accuracy is actively misleading, because predicting "Safe" for everything scores above
0.99. The balance here is 5,010 phishing to 4,150 legitimate, which is an artifact of how
the two archives happen to be sized and nothing like a mail stream.

So: **thresholds are chosen, not defaulted.** For each model the operating point is the
most sensitive threshold whose false-positive rate stays inside a 0.5% budget on
out-of-fold *training* scores, then applied unchanged to the test fold. The test set never
informs the threshold. LinearSVC is wrapped in Platt scaling because it has no native
probabilities and the operating point is defined on one.

Reported per configuration: accuracy, precision, recall, F1, confusion matrix, ROC-AUC,
average precision, and precision/recall at FPR <= 0.5% and <= 0.1%. Plus a breakdown of
which legitimate mail the model gets wrong, by archive — false-positive rate is 0.0000 on
`easy_ham`, 0.0032 on `easy_ham_2`, 0.0308 on `hard_ham`. That concentration is the
behaviour you want (the model fails on the genuinely ambiguous commercial mail) but it
also means the low overall FPR is partly a gift from the corpus, because a real inbox is
mostly hard_ham.

### Model comparison

All four on the same features, folds and seed:

| model | ROC-AUC | avg precision | accuracy | recall @ FPR<=0.5% | confusion matrix |
| --- | --- | --- | --- | --- | --- |
| `logreg` | 0.9987 | 0.9991 | 0.9721 | 0.9713 | TN 1035 / FP 2 / FN 62 / TP 1191 |
| `linear_svc_calibrated` | 0.9987 | 0.9991 | 0.9764 | 0.9713 | TN 1035 / FP 2 / FN 52 / TP 1201 |
| `sgd_modified_huber` | 0.9730 | 0.9646 | 0.9734 | 0.9769 | TN 1005 / FP 32 / FN 29 / TP 1224 |
| `random_forest` | 0.9996 | 0.9997 | 0.9895 | 0.9888 | TN 1034 / FP 3 / FN 21 / TP 1232 |

`sgd_modified_huber` is the instructive case. Its accuracy (0.9734) sits mid-table and
looks fine, while its AUC (0.9730) is 0.026 below everything else and its average
precision is 0.035 below. Modified-Huber produces clipped, poorly-spread scores, so its
ranking is weak even where its hard predictions are acceptable — and it pays for that
with 32 false positives against 2-3 for the others, at the same nominal FPR budget. If
you had picked a model on accuracy you would have picked the one that misfiles ten times
as much legitimate mail.

## Layout

```
src/config.py      paths, seed, corpus manifest, the two artifact blocklists
src/download.py    fetch + unpack into data/raw/, cached by Content-Length
src/parse.py       RFC822 -> records, keeping headers and body strictly separate
src/features.py    65 URL/HTML/text features + the four text views
src/dedupe.py      MinHash + banded LSH + union-find near-duplicate clustering
src/models.py      the four sklearn pipelines and the two ablations
src/evaluate.py    metrics and the fixed-FPR threshold search
src/train.py       the experiment: grid, comparison, ablations, controls, probe
src/report.py      renders findings.md from summary_stats.json
src/plots.py       the seven figures
```

## Running it

```
python -m pip install -r requirements.txt
python -m src.download   # ~50 MB into data/raw/, cached
python -m src.parse      # -> data/processed/emails.jsonl.gz
python -m src.dedupe     # -> data/processed/groups.csv
python -m src.train      # -> outputs/figures/, outputs/reports/
```

`src.train` takes about 19 minutes on this machine (a 4-view x 2-split grid plus four
models, two ablations and two subset controls, each with an inner 5-fold
cross-validation for threshold selection).

Seed 20260821 everywhere. Two consecutive runs of `src.train` produce a byte-identical
`summary_stats.json` — verified by hashing both, not assumed. Gzip output is written with
`mtime=0` so the processed artifacts are byte-stable too.

## Data

| source | messages | label |
| --- | --- | --- |
| SpamAssassin `20030228_easy_ham` | 2500 | legitimate |
| SpamAssassin `20030228_easy_ham_2` | 1400 | legitimate |
| SpamAssassin `20030228_hard_ham` | 250 | legitimate |
| Nazario `phishing0.mbox` | 414 | phishing |
| Nazario `phishing1.mbox` | 456 | phishing |
| Nazario `phishing2.mbox` | 1423 | phishing |
| Nazario `phishing3.mbox` | 2279 | phishing |
| Nazario `20051114.mbox` | 438 | phishing |

Real RFC822 mail with full headers, from
`https://spamassassin.apache.org/old/publiccorpus/` and
`https://monkey.org/~jose/phishing/`. Nothing synthetic; no random data standing in for
anything.

Choices about what went in:

- **Only the 2003-02-28 ham revision.** The 2002-10-10 archives are an earlier cut of
  largely the same messages. Including both would have added thousands of exact
  duplicates to the negative class.
- **Only the 2004-2007 phishing files.** `phishing-2015` through `phishing-2025` are
  reachable and would have roughly doubled the positive class, but the ham is all
  2002-2003 and pairing it with 2020s phishing widens the era gap that is the main
  confound. `private-phishing4.mbox` was left out for the same reason.
- **SpamAssassin's spam sets are downloaded but held out entirely.** They are used once,
  as the probe in Finding 6, and never for training.
- **110 phishing and 0 legitimate messages have no extractable subject or body** —
  attachment-only, or MIME too broken to decode. Kept, not dropped: they are real
  messages, dropping them would flatter the content-only models, and their effect shows
  up honestly as a ceiling on recall.
- **Subject is treated as content, not as a header.** It is written by the attacker and
  read by the victim, so excluding it would throw away genuine signal. It is still a
  header field, and a stricter reading of the experiment would drop it too.

`data/raw/` is gitignored (re-fetchable, with SHA-256 sums recorded in
`data/raw/MANIFEST.csv`). `data/processed/` is committed: `emails.jsonl.gz` (the parsed
corpus, bodies truncated at 20k characters), `spam_probe.jsonl.gz`, `groups.csv` (the
near-duplicate cluster assignment) and `features.csv.gz` (the 65-column engineered
feature table).

## Figures

`outputs/figures/`

- `fig1_leakage_comparison.png` — the 4-view x 2-split grid, three metrics
- `fig2_confusion_matrices.png` — leaky configuration against honest configuration
- `fig3_roc_pr.png` — ROC on a log FPR axis (the only part of the curve you can ship is
  the left edge) and precision-recall, all models plus the leaky reference
- `fig4_model_comparison.png` — the four estimators
- `fig5_numeric_feature_importance.png` — engineered features by forest importance
- `fig6_duplicate_clusters.png` — cluster-size distributions and the per-class
  duplication asymmetry
- `fig7_top_tokens.png` — top phishing-ward coefficients in three views side by side,
  with training document frequency, so you can watch the collection artifacts disappear
  and be replaced

## A note on reading coefficient tables

The first version of the feature-importance output was misleading and it took a second
look to notice. The unrestricted top-20 was dominated by tokens appearing in three
training messages: `beetapiale`, `c2report`, `pharmacy`, `evil gerald`. With `min_df=3` a
regularised linear model will happily assign a large weight to a token it saw three
times — that tells you about the regularisation, not about the corpus. All coefficient
tables in the report are therefore restricted to tokens appearing in at least 30 training
documents (8,831 of 82,055 features qualify), with the document frequency printed
alongside each one. The unrestricted list is kept in `summary_stats.json` under
`pushes_toward_phishing_unfiltered` so the difference stays visible.

## What I would do differently with more time

The single highest-value change is not a better model, it is a better negative class:
legitimate mail drawn from the same era, the same kind of mailbox, and the same MIME
format distribution as the phishing. Everything difficult in this project traces back to
not having that. Failing that, adding non-phishing spam as an explicit third class would
at least stop the model from treating "bulk" and "phishing" as synonyms, which the probe
in Finding 6 shows it currently does about 42% of the time.

Second: every number here is a single 25% test fold. The threshold is chosen by 5-fold
cross-validation inside the training set, but the headline metrics have no confidence
intervals, and differences below roughly 0.005 between rows of any table in this
repository should not be read as real.
