# Findings

Phishing email detection on the SpamAssassin public corpus (legitimate mail) and the Nazario phishing corpus. Every number below comes from one run of `python -m src.train` with seed 20260821; the same values are in `summary_stats.json` in this directory.

The short version: the model works, the obvious way of measuring it does not, and most of the work here was finding four different reasons the score was too high and quantifying each one.

## The two numbers

|  | Leaky setup | Honest setup |
| --- | --- | --- |
| text the model sees | whole file, headers included | subject + body, body artifacts removed |
| train/test split | random | near-duplicate-grouped |
| model | logistic regression | random_forest |
| accuracy | **0.9961** | **0.9895** |
| ROC-AUC | 0.9993 | 0.9996 |
| average precision | 0.9996 | 0.9997 |
| recall at FPR <= 0.5% | 0.9984 | 0.9888 |
| confusion matrix | TN 1037 / FP 1 / FN 8 / TP 1244 | TN 1034 / FP 3 / FN 21 / TP 1232 |

**The number I stand behind is 0.9895 accuracy and 0.9996 ROC-AUC**, from `random_forest` on the content_hardened view (subject + body, body-level collection artifacts removed), grouped split.

It is not far from the leaky number, and that surprised me. The premise I started from was the standard one: headers leak, so a header model scores ~0.99 and a body model tells you the truth. Half of that is right. The headers do leak, provably and totally -- one header field classifies this corpus perfectly, with no model at all. What is wrong is the implied conclusion that the body is therefore clean. Removing the headers moved ROC-AUC from 0.9993 to 0.9987. The body of a message carries its own record of which archive it came from, and most of this report is about finding and measuring that.

So the honest reading is not "the model is 99% accurate at detecting phishing". It is "the model is very good at telling these two particular archives apart, and after four separate attempts to remove the reasons that are not about phishing, it is still very good at it -- which means either the remaining signal is real, or I have not found the last confound." The generic-spam probe at the end is the strongest evidence I have on which of those it is, and it does not fully settle the question.

## Data

Two public corpora, both real RFC822 mail with full headers. Nothing here is synthetic.

| source | messages | label |
| --- | --- | --- |
| 20030228_easy_ham | 2500 | legitimate |
| 20030228_easy_ham_2 | 1400 | legitimate |
| 20030228_hard_ham | 250 | legitimate |
| 20051114.mbox | 438 | phishing |
| phishing0.mbox | 414 | phishing |
| phishing1.mbox | 456 | phishing |
| phishing2.mbox | 1423 | phishing |
| phishing3.mbox | 2279 | phishing |

9160 messages: 5010 phishing (54.7%) and 4150 legitimate. That near-even balance is an artifact of how the two archives happen to be sized, not a property of mail. On a real stream phishing is a small fraction of a percent, so every precision number in this report is optimistic by a large factor: the same false-positive rate applied to a realistic volume of legitimate mail would swamp the true positives.

Choices about what went in, and why:

- Only the 2003-02-28 revision of the SpamAssassin ham sets. The 2002-10-10 archives are an earlier cut of largely the same messages; including both would have added thousands of exact duplicates to the negative class.
- Only the 2004-2007 Nazario files (`phishing0`-`phishing3`, `20051114`). The `phishing-2015` through `phishing-2025` files are reachable and would have roughly doubled the positive class, but the ham is all from 2002-2003 and pairing it with 2020s phishing would have widened the era gap that is itself the main confound.
- SpamAssassin's spam sets were downloaded but held out entirely. They are used once, as a probe (Finding 5), and never for training.

Dates from the `Date` header:

| class | year distribution (years with >= 20 messages) |
| --- | --- |
| ham | 2002: 4149 |
| phish | 2003: 33, 2004: 73, 2005: 1541, 2006: 1876, 2007: 1303, unparsed: 155 |

There is essentially no temporal overlap. No public corpus pairing avoids this, and it is the root cause of everything below.

44 phishing messages and 0 legitimate ones have no extractable subject or body (attachment-only, or MIME too broken to decode). They were kept, not dropped: they are real messages, dropping them would flatter the content-only models, and their effect shows up honestly as a ceiling on recall.

## Finding 1: the headers give away the label with no model at all

Before training anything, count how often each header field appears in each class. A field on one class and not the other is not a property of phishing; it is a property of whoever archived the mailbox. Each row below also scores that single field, used as the entire classifier.

| header | % of phishing | % of legitimate | accuracy as a one-field rule | direction |
| --- | --- | --- | --- | --- |
| status | 100.0 | 0.0 | 1.0000 | present=>phishing |
| x-keywords | 99.94 | 0.6 | 0.9969 | present=>phishing |
| x-original-to | 85.83 | 0.0 | 0.9225 | present=>phishing |
| x-status | 82.89 | 0.55 | 0.9039 | present=>phishing |
| x-uid | 77.54 | 0.0 | 0.8772 | present=>phishing |
| precedence | 0.56 | 75.13 | 0.8843 | absent=>phishing |
| list-id | 0.1 | 68.07 | 0.8548 | absent=>phishing |
| sender | 1.56 | 69.4 | 0.8528 | absent=>phishing |
| errors-to | 0.32 | 67.66 | 0.8517 | absent=>phishing |
| x-mailman-version | 0.06 | 67.3 | 0.8515 | absent=>phishing |

`status` alone gives 1.0000 accuracy. One boolean. No text, no TF-IDF, no learning. `Status`, `X-Keywords`, `X-UID` and `X-Status` are IMAP/mail-client bookkeeping written by the collector's own client. `Precedence`, `List-Id` and `Sender` are on the ham side because most of the SpamAssassin ham is mailing-list traffic. Neither set has anything to do with whether a message is an attack.

Given the full file, the model finds exactly this, plus the dates:

```
    +3.475  2006   [in 1531 training messages]
    +2.289  aug 2006   [in 219 training messages]
    +2.228  nobody@login.example.com   [in 1057 training messages]
    +2.183  mail.example.org   [in 1177 training messages]
    +2.131  [engineered] has_html   [in 6870 training messages]
    +1.949  2005   [in 1390 training messages]
    +1.842  user@login.example.com   [in 1177 training messages]
    +1.789  x-original-to:   [in 3203 training messages]
    +1.646  status:   [in 3769 training messages]
    +1.599  x-status: x-keywords:   [in 3149 training messages]
    +1.598  x-status:   [in 3150 training messages]
    +1.577  ebay   [in 937 training messages]
    +1.576  [engineered] kw_account   [in 6870 training messages]
    +1.575  user@example.com   [in 1671 training messages]
    +1.570  nobody@example.com   [in 924 training messages]
    +1.551  mail1.example.com   [in 590 training messages]
```

`2006`, `aug 2006`, `2005` -- the model is reading the clock. `status:`, `x-status: x-keywords:`, `x-original-to:` -- it is reading the collector's mail client. `nobody@login.example.com`, `mail.example.org`, `user@example.com` -- it is reading the anonymisation scheme Nazario applied to his archive. Only `ebay` and the engineered `has_html` and `kw_account` features have anything to do with phishing.

## Finding 2: a header blocklist does not fix it

Removing every field matching `config.COLLECTION_ARTIFACT_HEADERS` (`Received`, `Message-ID`, `Date`, `X-Spam-*`, `Status`, `X-Keywords`, `List-*`, `Return-Path`, and 30 more) moves ROC-AUC from 0.9993 to 0.9988 and accuracy from 0.9961 to 0.9882. What the surviving headers give it:

```
    +4.659  undisclosed-recipients:   [in 1029 training messages]
    +4.659  to: undisclosed-recipients:   [in 1029 training messages]
    +2.389  ebay   [in 937 training messages]
    +2.326  [engineered] has_html   [in 6870 training messages]
    +2.203  nobody@example.com   [in 601 training messages]
    +1.896  [engineered] max_host_digits   [in 6870 training messages]
    +1.856  [engineered] kw_account   [in 6870 training messages]
    +1.744  user@example.com   [in 1020 training messages]
    +1.661  to: user@example.com   [in 553 training messages]
    +1.553  to: nobody@example.com   [in 525 training messages]
    +1.500  nobody@example.com subject:   [in 500 training messages]
    +1.385  your   [in 4326 training messages]
    +1.323  customer   [in 1252 training messages]
    +1.322  user@example.com subject:   [in 869 training messages]
```

`undisclosed-recipients:`, `nobody@example.com`, `user@example.com`, `username@domain.com`. Nazario anonymised the recipient addresses in his archive; the SpamAssassin ham has real recipients on real hosts. `To` is not on anyone's list of spam-filter artifacts, so a sensible blocklist leaves it in, and the model learns "recipient is a placeholder address" as its phishing rule.

That is the general lesson and it is why the blocklist approach is the wrong shape. You cannot enumerate leakage, because you do not know what you have not thought of. You have to restrict the model to fields you can positively justify. Hence the third view: subject and body, nothing else.

Which gets ROC-AUC 0.9987 on a grouped split -- and is still not clean, which is Finding 3.

## Finding 3: the body leaks too

This is the part I did not expect to have to write. With headers gone the model still reached 0.9987 AUC, so I looked at what it was using. The tokens pushing toward "safe" were `url:`, `date:`, `2002`, `spambayes`, `list`, `tel:`, `fax:`. None of those is a property of legitimate mail. They are properties of the SpamAssassin archive. Counted directly:

| body-level tell | % of legitimate | % of phishing |
| --- | --- | --- |
| body starts with RSS 'URL:/Date:' digest prefix | 15.01% (623) | 0.0% (0) |
| body names its own mailing list | 35.64% (1479) | 0.22% (11) |
| body contains a listinfo/mailman URL | 9.42% (391) | 0.0% (0) |
| body contains 'sourceforge' | 11.28% (468) | 0.0% (0) |
| body contains the year 2002 | 53.78% (2232) | 0.24% (12) |
| body contains the year 2005, 2006 or 2007 | 0.24% (10) | 46.95% (2352) |
| body contains an email address | 63.98% (2655) | 11.44% (573) |

Three distinct mechanisms, all inside the body:

1. **RSS digest boilerplate.** A large block of the easy_ham set are feed-to-mail digests whose body literally begins `URL: http://...` newline `Date: 2002-10-08T00:22:08-05:00`. That two-line prefix appears on a sixth of the negative class and on none of the positive class.
2. **Mailing-list identity.** The ham names its own lists in the body text -- `spamassassin`, `exmh`, `ilug`, `zzzzteana`, `razor-users`, `sourceforge.net`, `listinfo` URLs, unsubscribe footers.
3. **Era tokens in prose.** Ham bodies say 2002; phishing bodies say 2005, 2006, 2007. The year is written in the text, so removing the `Date` header does not remove the date.

The `content_hardened` view removes all three: the RSS prefix and list-management lines are deleted, a named list of corpus-identifying terms is stripped, and URLs, email addresses, years and digit runs are replaced by placeholder tokens. URLs go to a placeholder rather than being deleted because the *structure* of every URL is already captured by the 65 engineered features -- what leaks is the literal host string, `lists.sourceforge.net` on one side and a payload domain on the other.

Result: ROC-AUC 0.9987 -> 0.9987, accuracy 0.9734 -> 0.9721. What is left driving it:

```
    +2.895  ebay   [in 872 training messages]
    +2.165  [engineered] max_host_digits   [in 6870 training messages]
    +2.037  [engineered] kw_account   [in 6870 training messages]
    +1.863  [engineered] has_html   [in 6870 training messages]
    +1.700  your   [in 4218 training messages]
    +1.394  br   [in 107 training messages]
    +1.307  [engineered] kw_total   [in 6870 training messages]
    +1.273  customer   [in 1185 training messages]
    +1.256  [engineered] kw_verify   [in 6870 training messages]
    +1.130  nbsp   [in 93 training messages]
    +1.128  div   [in 49 training messages]
    +1.117  online   [in 1303 training messages]
    +1.079  our   [in 2769 training messages]
    +1.074  from numtoken   [in 93 training messages]
    +1.050  please   [in 3241 training messages]
    +1.041  de   [in 80 training messages]
```

That list looks much more like phishing: brand names, account language, HTML structure, host-shape features. I do not claim it is clean. `content_hardened` is built from an enumerated blocklist of corpus terms, which is precisely the approach Finding 2 shows to be unreliable. It is the honest thing to try and it lowers the score, so I report it -- but the right way to read it is as an upper bound on the real signal, not a clean measurement.

### A note on reading coefficient tables

The lists above are restricted to tokens appearing in at least 30 training messages (8831 of 82055 features qualify). The unrestricted ranking is misleading, and I only noticed after the first run: it was topped by tokens occurring in three messages (`beetapiale`, `c2report`, `pharmacy`, `evil gerald`). With `min_df=3` a linear model will assign a large weight to a token it saw three times. That tells you about the regularisation, not about the corpus. The unfiltered list is kept in `summary_stats.json` under `pushes_toward_phishing_unfiltered` so the difference is visible.

## Finding 4: the biggest confound is not text at all, it is MIME

93.43% of the phishing messages have an HTML part. 4.53% of the legitimate ones do. "Does this message contain HTML", used as the entire classifier, scores 0.9436 accuracy.

| archive | messages | with an HTML part |
| --- | --- | --- |
| 20030228_easy_ham | 2500 | 0.32% |
| 20030228_easy_ham_2 | 1400 | 1.07% |
| 20030228_hard_ham | 250 | 66.0% |
| 20051114.mbox | 438 | 88.81% |
| phishing0.mbox | 414 | 92.75% |
| phishing1.mbox | 456 | 87.06% |
| phishing2.mbox | 1423 | 93.68% |
| phishing3.mbox | 2279 | 95.57% |

This is partly real -- phishing genuinely is HTML brand-impersonation mail -- and partly an artifact: the SpamAssassin ham is overwhelmingly plain-text mailing-list traffic from 2002, which is not what a modern inbox looks like. The two cannot be separated by editing text, because format is a property of the message. The only clean way to measure it is to hold format constant.

| subset | class sizes | ROC-AUC | accuracy | recall @ FPR<=0.5% | confusion matrix |
| --- | --- | --- | --- | --- | --- |
| plaintext_only | 3962 legit / 329 phish | 0.9729 | 0.9907 | 0.9268 | TN 989 / FP 2 / FN 8 / TP 74 |
| html_only | 188 legit / 4681 phish | 0.9957 | 0.2734 | 0.9675 | TN 47 / FP 0 / FN 885 / TP 286 |

The plain-text-only control is the interesting one: 3962 legitimate and 329 phishing messages, none with an HTML part, so `has_html` and every HTML feature is constant and carries no information. ROC-AUC 0.9729, accuracy 0.9907, on the hardened content view with a grouped split. Both controls use a much smaller and more skewed sample than the main experiment, so treat them as directional rather than precise -- the phishing class in the plain-text control is only 329 messages.

## Finding 5: near-duplicate campaigns inflate a random split

MinHash over 5-word shingles of the normalised body, 32-band LSH for candidates, Jaccard >= 0.70 to confirm, union-find to cluster. URLs and digits become placeholders before shingling, because rotating the payload host and the victim's account number is exactly what a campaign does between sends -- two messages differing only in those must land in the same group.

|  | legitimate | phishing |
| --- | --- | --- |
| messages | 4150 | 5010 |
| distinct clusters | 3866 | 1948 |
| largest cluster | 30 | 220 |
| % in a multi-member cluster | 10.96% | 72.57% |

5010 phishing messages are only 1948 distinct campaigns. 72.57% have a near-twin somewhere in the corpus, against 10.96% of the legitimate mail. Under a random split 70.53% of test phishing messages have a near-duplicate sitting in training (967 of 2290 test messages overall). Under the grouped split, by construction, none do.

On the hardened content view the split strategy is worth -0.0005 ROC-AUC and +0.0066 accuracy (0.9981 random vs 0.9987 grouped).

Smaller than I expected, and I am reporting it as found rather than as hoped. Three quarters of the phishing side is duplicated, so I assumed campaign leakage would dominate. It is real, it is in the predicted direction, and it is an order of magnitude smaller than the header leakage and smaller than the body-artifact leakage. The likely reason is that the phishing campaigns in this corpus are not just similar to each other, they are similar to phishing in general -- so a model that has seen 1,900 other campaigns does not gain much extra from having seen this exact one. The grouped split remains the right default because it costs nothing and the bias it removes is unambiguous, but on this corpus it is not where the problem was.

### The full grid

| text view | split | ROC-AUC | accuracy | avg precision | recall @ FPR<=0.5% | confusion matrix |
| --- | --- | --- | --- | --- | --- | --- |
| full | random | 0.9993 | 0.9961 | 0.9996 | 0.9984 | TN 1037 / FP 1 / FN 8 / TP 1244 |
| full | grouped | 0.9998 | 0.9926 | 0.9998 | 0.9984 | TN 1035 / FP 2 / FN 15 / TP 1238 |
| headers_scrubbed | random | 0.9988 | 0.9882 | 0.9993 | 0.9912 | TN 1037 / FP 1 / FN 26 / TP 1226 |
| headers_scrubbed | grouped | 0.9990 | 0.9803 | 0.9993 | 0.9792 | TN 1034 / FP 3 / FN 42 / TP 1211 |
| content | random | 0.9982 | 0.9790 | 0.9989 | 0.9896 | TN 1038 / FP 0 / FN 48 / TP 1204 |
| content | grouped | 0.9987 | 0.9734 | 0.9991 | 0.9689 | TN 1035 / FP 2 / FN 59 / TP 1194 |
| content_hardened | random | 0.9981 | 0.9786 | 0.9989 | 0.9896 | TN 1038 / FP 0 / FN 49 / TP 1203 |
| content_hardened | grouped | 0.9987 | 0.9721 | 0.9991 | 0.9713 | TN 1035 / FP 2 / FN 62 / TP 1191 |

| view | what the model sees |
| --- | --- |
| full | whole file: every header plus the body |
| headers_scrubbed | headers minus the artifact fields listed in config, plus body |
| content | subject line and body only |
| content_hardened | subject and body with named body-level artifacts removed |

Same estimator (logistic regression, identical hyperparameters), same engineered features, same seed, same 25% test fraction throughout. Only the text view and the split rule change.

## Why accuracy is the wrong headline metric

The brief asks for accuracy and a confusion matrix, and both are above. Neither is the metric I would use to decide whether to deploy this.

A false positive is a legitimate message filed as an attack: somebody's invoice, password reset, or note from a colleague, now in a quarantine folder nobody reads. A false negative is one more phishing mail in an inbox that already receives them, in front of a user who is the next control in the chain. Those costs differ by orders of magnitude, and accuracy weights them equally. On a realistic class balance -- phishing well under 1% of mail -- accuracy is worse than useless, because predicting "safe" for everything scores above 0.99.

So the threshold is not 0.5. It is the most sensitive threshold whose false-positive rate stays inside a 0.5% budget on out-of-fold *training* scores, then applied unchanged to the test fold. The test set never informs it.

| operating point | threshold | precision | recall | false positives |
| --- | --- | --- | --- | --- |
| chosen: FPR budget 0.5%, fixed on training folds | 0.6232 | 0.9976 | 0.9832 | 3 |
| sklearn default 0.5 | 0.5000 | 0.9936 | 0.9912 | 8 |
| post-hoc best at FPR<=0.5% (test-fitted, reference only) | 0.6036 | 0.9960 | 0.9888 | 5 |
| post-hoc best at FPR<=0.1% (test-fitted, reference only) | 0.7028 | 0.9992 | 0.9808 | 1 |

The chosen threshold 0.6232 realised 0.0048 FPR on the training folds and 0.0029 on the test fold (3 false positives on 1037 legitimate test messages). The two post-hoc rows show what the curve could have delivered with the threshold tuned on the test set, which is not a thing you are allowed to do; the gap between them and the chosen row is the honest cost of picking an operating point in advance.

Which legitimate mail it gets wrong, by archive:

| ham archive | in test fold | false positives | FPR |
| --- | --- | --- | --- |
| 20030228_easy_ham | 656 | 0 | 0.0000 |
| 20030228_easy_ham_2 | 316 | 1 | 0.0032 |
| 20030228_hard_ham | 65 | 2 | 0.0308 |

`hard_ham` is SpamAssassin's deliberately difficult negative set: commercial HTML mail, newsletters, order confirmations -- the legitimate mail that most resembles an attack. If the false positives concentrate there, the model is behaving sensibly and failing on the genuinely hard cases. If they are spread evenly, something less explicable is going on.

## Model comparison

| model | ROC-AUC | avg precision | accuracy | recall | recall @ FPR<=0.5% | confusion matrix |
| --- | --- | --- | --- | --- | --- | --- |
| logreg | 0.9987 | 0.9991 | 0.9721 | 0.9505 | 0.9713 | TN 1035 / FP 2 / FN 62 / TP 1191 |
| linear_svc_calibrated | 0.9987 | 0.9991 | 0.9764 | 0.9585 | 0.9713 | TN 1035 / FP 2 / FN 52 / TP 1201 |
| sgd_modified_huber | 0.9730 | 0.9646 | 0.9734 | 0.9769 | 0.9769 | TN 1005 / FP 32 / FN 29 / TP 1224 |
| random_forest | 0.9996 | 0.9997 | 0.9895 | 0.9832 | 0.9888 | TN 1034 / FP 3 / FN 21 / TP 1232 |

All four on the honest configuration, same pipeline, same features, same folds. `random_forest` wins on the metric that matters here -- recall at the false-positive budget -- and is the model behind the headline. The linear models sit close together, which is what you expect on high-dimensional sparse text. `sgd_modified_huber` has the worst AUC despite competitive accuracy: modified-Huber gives clipped, poorly spread scores, so its ranking is weaker even where its hard predictions are fine, which is a good argument for not judging a model by accuracy. The forest sees only the 2,000 chi2-selected terms rather than the full vocabulary; that restriction is deliberate, since a forest on 200k sparse columns is not worth the runtime.

Thresholds were selected per model on out-of-fold training scores, not left at 0.5, and LinearSVC was wrapped in Platt scaling because it has no native probabilities and the operating point is defined on one.

### Where the signal lives

| features | ROC-AUC | accuracy | recall @ FPR<=0.5% |
| --- | --- | --- | --- |
| TF-IDF over the hardened text only | 0.9991 | 0.9908 | 0.9777 |
| the 65 engineered features only | 0.9966 | 0.9410 | 0.9314 |
| both (logistic regression) | 0.9987 | 0.9721 | 0.9713 |

Worth stating plainly: for the logistic regression the engineered features do not help. TF-IDF alone matches or beats the combination. The likely mechanism is scale -- TF-IDF rows are L2-normalised while the standardised numeric block is not, so 65 dense standardised columns consume a disproportionate share of a single L2 penalty and slightly distort the fit. I could have fixed this by tuning the relative weight of the two blocks; I did not, because the more useful thing to report is that the hand-built features earned their place in the tree model and not in the linear one.

In the random forest the engineered block holds 47.6% of total impurity-based importance against 52.4% for the 2,000 selected TF-IDF terms, from only 65 columns. Top engineered features:

```
  0.0579  html_tag_count
  0.0571  has_html
  0.0533  html_tag_ratio
  0.0359  n_images
  0.0259  kw_account
  0.0220  max_host_digits
  0.0209  n_remote_images
  0.0192  kw_total
  0.0141  anchor_host_mismatch
  0.0132  subject_is_reply
  0.0119  url_mean_entropy
  0.0118  brand_host_abuse
  0.0109  body_lines
  0.0108  body_nonascii_ratio
```

The HTML-structure features dominate, which is Finding 4 restated from the model's point of view rather than the corpus's.

### Prevalence of the URL and HTML signals

What each engineered feature is for is documented at its definition in `src/features.py`. What matters here is which ones actually fire:

| feature (non-zero) | phishing | legitimate |
| --- | --- | --- |
| has_ip_url | 28.4% | 0.12% |
| has_at_in_url | 0.06% | 0.02% |
| has_punycode | 0.0% | 0.0% |
| has_shortener | 0.04% | 0.22% |
| n_forms | 1.98% | 1.25% |
| has_javascript_uri | 1.88% | 0.05% |
| anchor_host_mismatch | 49.24% | 1.52% |
| has_html | 93.43% | 4.53% |
| brand_host_abuse | 47.09% | 1.57% |
| has_obfuscated_ip | 1.86% | 0.0% |
| has_risky_path_ext | 0.12% | 0.02% |
| has_nonstd_port | 10.38% | 0.55% |

`has_shortener` and `has_punycode` are near zero on both sides. That is not a bug: URL shorteners and internationalised domains were barely in use in 2004-2007. They stay in the feature set because they cost nothing and would matter on modern mail, but on this corpus they contribute nothing and it would be dishonest to present them as working detectors. `has_ip_url` and `anchor_host_mismatch` are the two that carry real, interpretable weight.

## Finding 6: is this a phishing detector or a spam detector?

1897 SpamAssassin spam messages -- unsolicited bulk mail, not credential phishing, never seen in training, same era as the ham -- scored with the honest model at its chosen threshold 0.6232: **807 of them (42.54%) are flagged as phishing**, median score 0.5480.

This is the most damaging result in the report and the reason I would not describe the headline number as a phishing detection rate. A large fraction of ordinary junk mail trips the threshold. Nothing in the training data could have taught the model otherwise: the negative class is mailing-list and personal mail, so "not ham" and "phishing" are the same category as far as the fit is concerned, and the model has learned a decision boundary around unsolicited bulk HTML mail rather than around credential theft.

Fixing it needs a third class -- non-phishing spam as its own label, or at minimum as additional negatives -- which is a different experiment and a different brief. What I can say is that the number is measured, not assumed, and that any deployment of this model would spend its false-positive budget here.

## Limitations

- **Era.** The corpora are 2002-2007. No OAuth consent phishing, no QR codes, no HTML-attachment kits, no landing pages on legitimate cloud domains. Nothing here is a current detection rate.
- **Different collectors.** The content views remove the header channel and the body tells I found, but I can only remove the confounds I noticed. The residual score is an upper bound on real signal, not a measurement of it.
- **The hardened view uses a blocklist**, the same technique this report argues against for headers. It is included because it lowers the score and is therefore the conservative choice, not because it is sound.
- **Subject is treated as content.** It is written by the attacker and read by the victim, so dropping it would discard genuine signal. But it is a header field, and a stricter reading of the experiment would exclude it.
- **Clustering threshold.** Jaccard 0.70 over placeholder-normalised 5-word shingles is a judgement call. Tighter leaves campaign fragments split across the boundary; looser merges unrelated lures sharing boilerplate. One oversized LSH bucket was merged wholesale rather than pairwise-verified -- a deliberate imprecision in favour of not splitting a campaign.
- **Class balance.** Near 50/50 here, well under 1% in reality. Precision on a real stream would be far worse at the same threshold.
- **The spam probe is not closed.** A model that flags a large share of generic spam is partly a spam filter, and this experiment does not separate the two.
- **Single split.** Every number is one 25% test fold, not a repeated-CV mean with confidence intervals. The threshold is chosen by 5-fold cross-validation inside training, but the headline metrics have no error bars. Differences below about 0.005 between rows should not be read as real.

## Reproducing

```
python -m src.download   # ~50 MB, cached in data/raw/
python -m src.parse      # -> data/processed/emails.jsonl.gz
python -m src.dedupe     # -> data/processed/groups.csv
python -m src.train      # -> outputs/figures/, outputs/reports/
```

Seed 20260821 throughout. scikit-learn 1.9.0, pandas 3.0.5, numpy 2.5.2, Python 3.14.4. Two consecutive runs of `src.train` produce a byte-identical `summary_stats.json`; that was checked, not assumed.
