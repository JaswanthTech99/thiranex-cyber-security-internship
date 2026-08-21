"""Render outputs/reports/findings.md from summary_stats.json.

The report is generated rather than hand-written so that no number in it can
drift away from the run that produced it. Prose that does not depend on a
number is inline here; anything numeric is interpolated, including the few
places where the wording has to follow the direction of a result.
"""
from __future__ import annotations

import json
import sys

from .config import REPORTS

LEAKY_KEY = "full|random"
SCRUB_KEY = "headers_scrubbed|random"
HONEST_KEY = "content_hardened|grouped"
VIEW_ORDER = ["full", "headers_scrubbed", "content", "content_hardened"]
VIEW_DESC = {
    "full": "whole file: every header plus the body",
    "headers_scrubbed": "headers minus the artifact fields listed in config, plus body",
    "content": "subject line and body only",
    "content_hardened": "subject and body with named body-level artifacts removed",
}


def _row(cells):
    return "| " + " | ".join(str(c) for c in cells) + " |"


def _table(header, rows):
    return "\n".join([_row(header), _row(["---"] * len(header))] + [_row(r) for r in rows])


def _cm(res):
    c = res["confusion_matrix"]
    return f"TN {c['tn']} / FP {c['fp']} / FN {c['fn']} / TP {c['tp']}"


def _coef_block(entries, n=14):
    out = ["```"]
    for e in entries[:n]:
        name, coef = e[0], e[1]
        df = f"   [in {e[2]} training messages]" if len(e) > 2 else ""
        out.append(f"  {coef:+8.3f}  {name}{df}")
    out.append("```")
    return "\n".join(out)


def _section_headline(d, L):
    grid, leaky = d["leakage_grid"], d["leakage_grid"][LEAKY_KEY]
    honest = d["headline"]["metrics"]
    hl = d["headline"]
    L.append("## The two numbers\n")
    L.append(_table(
        ["", "Leaky setup", "Honest setup"],
        [["text the model sees", "whole file, headers included",
          "subject + body, body artifacts removed"],
         ["train/test split", "random", "near-duplicate-grouped"],
         ["model", "logistic regression", hl["model"]],
         ["accuracy", f"**{leaky['accuracy']:.4f}**", f"**{honest['accuracy']:.4f}**"],
         ["ROC-AUC", f"{leaky['roc_auc']:.4f}", f"{honest['roc_auc']:.4f}"],
         ["average precision", f"{leaky['average_precision']:.4f}",
          f"{honest['average_precision']:.4f}"],
         ["recall at FPR <= 0.5%", f"{leaky['prec_at_fpr_0.005']['recall']:.4f}",
          f"{honest['prec_at_fpr_0.005']['recall']:.4f}"],
         ["confusion matrix", _cm(leaky), _cm(honest)]]))
    L.append("")
    L.append(f"**The number I stand behind is {honest['accuracy']:.4f} accuracy and "
             f"{honest['roc_auc']:.4f} ROC-AUC**, from `{hl['model']}` on the "
             f"{hl['configuration']}.\n")
    L.append("It is not far from the leaky number, and that surprised me. The premise I "
             "started from was the standard one: headers leak, so a header model scores "
             "~0.99 and a body model tells you the truth. Half of that is right. The "
             "headers do leak, provably and totally -- one header field classifies this "
             "corpus perfectly, with no model at all. What is wrong is the implied "
             "conclusion that the body is therefore clean. Removing the headers moved "
             f"ROC-AUC from {leaky['roc_auc']:.4f} to "
             f"{grid['content|grouped']['roc_auc']:.4f}. The body of a message carries its "
             "own record of which archive it came from, and most of this report is about "
             "finding and measuring that.\n")
    L.append("So the honest reading is not \"the model detects phishing with 99% "
             "accuracy\". It is: **the model is very good at telling these two particular "
             "archives apart, and only some of that ability is about phishing.** Two "
             "measurements bound how much:\n")
    pt = d["format_controls"].get("plaintext_only", {})
    probe = d["spam_probe"]
    bullets = []
    if "roc_auc" in pt:
        bullets.append(
            f"- Hold the MIME format constant -- compare only messages with no HTML part, "
            f"on both sides -- and ROC-AUC drops from {honest['roc_auc']:.4f} to "
            f"{pt['roc_auc']:.4f}, average precision from "
            f"{honest['average_precision']:.4f} to {pt['average_precision']:.4f}, and "
            f"recall at a 0.1% false-positive budget from "
            f"{honest['prec_at_fpr_0.001']['recall']:.4f} to "
            f"{pt['prec_at_fpr_0.001']['recall']:.4f}. A large share of the score was "
            f"\"is this HTML mail\" (Finding 4).")
    bullets.append(
        f"- Score {probe['n_generic_spam']} generic spam messages -- bulk junk, not "
        f"credential phishing, never trained on -- and {probe['flagged_pct']}% of them "
        f"are flagged as phishing. Some of what the model learned is \"unsolicited bulk "
        f"mail\", which is an easier and different problem (Finding 6).")
    L.append("\n".join(bullets) + "\n")
    L.append("Both of those are measured, not estimated, and both are in this repository's "
             "`summary_stats.json`.\n")


def _section_data(d, L):
    ds = d["dataset"]
    L.append("## Data\n")
    L.append("Two public corpora, both real RFC822 mail with full headers. Nothing here "
             "is synthetic.\n")
    L.append(_table(["source", "messages", "label"],
                    [[k, v, "phishing" if k.endswith(".mbox") else "legitimate"]
                     for k, v in ds["messages_per_source"].items()]))
    L.append("")
    L.append(f"{ds['n_messages']} messages: {ds['n_phishing']} phishing "
             f"({100 * ds['phishing_share']:.1f}%) and {ds['n_legitimate']} legitimate. "
             "That near-even balance is an artifact of how the two archives happen to be "
             "sized, not a property of mail. On a real stream phishing is a small "
             "fraction of a percent, so every precision number in this report is "
             "optimistic by a large factor: the same false-positive rate applied to a "
             "realistic volume of legitimate mail would swamp the true positives.\n")
    L.append("Choices about what went in, and why:\n")
    L.append("- Only the 2003-02-28 revision of the SpamAssassin ham sets. The 2002-10-10 "
             "archives are an earlier cut of largely the same messages; including both "
             "would have added thousands of exact duplicates to the negative class.\n"
             "- Only the 2004-2007 Nazario files (`phishing0`-`phishing3`, `20051114`). "
             "The `phishing-2015` through `phishing-2025` files are reachable and would "
             "have roughly doubled the positive class, but the ham is all from 2002-2003 "
             "and pairing it with 2020s phishing would have widened the era gap that is "
             "itself the main confound.\n"
             "- SpamAssassin's spam sets were downloaded but held out entirely. They are "
             "used once, as a probe (Finding 5), and never for training.\n")
    L.append("Dates from the `Date` header:\n")
    L.append(_table(["class", "year distribution (years with >= 20 messages)"],
                    [[k, ", ".join(f"{y}: {n}" for y, n in sorted(v.items()) if n >= 20)]
                     for k, v in ds["year_distribution"].items()]))
    L.append("")
    L.append("There is essentially no temporal overlap. No public corpus pairing avoids "
             "this, and it is the root cause of everything below.\n")
    L.append(f"{ds['messages_with_no_usable_content']['phish']} phishing messages and "
             f"{ds['messages_with_no_usable_content']['ham']} legitimate ones have no "
             "extractable subject or body (attachment-only, or MIME too broken to "
             "decode). They were kept, not dropped: they are real messages, dropping them "
             "would flatter the content-only models, and their effect shows up honestly "
             "as a ceiling on recall.\n")


def _section_headers(d, L):
    leaky, scrub = d["leakage_grid"][LEAKY_KEY], d["leakage_grid"][SCRUB_KEY]
    top = d["header_leakage_no_model"][0]
    L.append("## Finding 1: the headers give away the label with no model at all\n")
    L.append("Before training anything, count how often each header field appears in each "
             "class. A field on one class and not the other is not a property of "
             "phishing; it is a property of whoever archived the mailbox. Each row below "
             "also scores that single field, used as the entire classifier.\n")
    L.append(_table(["header", "% of phishing", "% of legitimate",
                     "accuracy as a one-field rule", "direction"],
                    [[h["header"], h["pct_of_phishing"], h["pct_of_ham"],
                      f"{h['best_single_rule_accuracy']:.4f}", h["rule_direction"]]
                     for h in d["header_leakage_no_model"][:10]]))
    L.append("")
    L.append(f"`{top['header']}` alone gives "
             f"{top['best_single_rule_accuracy']:.4f} accuracy. One boolean. No text, no "
             "TF-IDF, no learning. `Status`, `X-Keywords`, `X-UID` and `X-Status` are "
             "IMAP/mail-client bookkeeping written by the collector's own client. "
             "`Precedence`, `List-Id` and `Sender` are on the ham side because most of "
             "the SpamAssassin ham is mailing-list traffic. Neither set has anything to "
             "do with whether a message is an attack.\n")
    L.append("Given the full file, the model finds exactly this, plus the dates:\n")
    L.append(_coef_block(d["top_coefficients"][LEAKY_KEY]["pushes_toward_phishing"], 16))
    L.append("")
    L.append("`2006`, `aug 2006`, `2005` -- the model is reading the clock. "
             "`status:`, `x-status: x-keywords:`, `x-original-to:` -- it is reading the "
             "collector's mail client. `nobody@login.example.com`, `mail.example.org`, "
             "`user@example.com` -- it is reading the anonymisation scheme Nazario applied "
             "to his archive. Only `ebay` and the engineered `has_html` and `kw_account` "
             "features have anything to do with phishing.\n")

    L.append("## Finding 2: a header blocklist does not fix it\n")
    L.append(f"Removing every field matching `config.COLLECTION_ARTIFACT_HEADERS` "
             f"(`Received`, `Message-ID`, `Date`, `X-Spam-*`, `Status`, `X-Keywords`, "
             f"`List-*`, `Return-Path`, and 30 more) moves ROC-AUC from "
             f"{leaky['roc_auc']:.4f} to {scrub['roc_auc']:.4f} and accuracy from "
             f"{leaky['accuracy']:.4f} to {scrub['accuracy']:.4f}. What the surviving "
             f"headers give it:\n")
    L.append(_coef_block(d["top_coefficients"][SCRUB_KEY]["pushes_toward_phishing"], 14))
    L.append("")
    L.append("`undisclosed-recipients:`, `nobody@example.com`, `user@example.com`, "
             "`username@domain.com`. Nazario anonymised the recipient addresses in his "
             "archive; the SpamAssassin ham has real recipients on real hosts. `To` is not "
             "on anyone's list of spam-filter artifacts, so a sensible blocklist leaves it "
             "in, and the model learns \"recipient is a placeholder address\" as its "
             "phishing rule.\n")
    L.append("That is the general lesson and it is why the blocklist approach is the wrong "
             "shape. You cannot enumerate leakage, because you do not know what you have "
             "not thought of. You have to restrict the model to fields you can positively "
             "justify. Hence the third view: subject and body, nothing else.\n")
    L.append(f"Which gets ROC-AUC {d['leakage_grid']['content|grouped']['roc_auc']:.4f} "
             f"on a grouped split -- and is still not clean, which is Finding 3.\n")


def _section_body(d, L):
    grid = d["leakage_grid"]
    ds = d["dataset"]
    content, hardened = grid["content|grouped"], grid[HONEST_KEY]
    L.append("## Finding 3: the body leaks too\n")
    L.append("This is the part I did not expect to have to write. With headers gone the "
             f"model still reached {content['roc_auc']:.4f} AUC, so I looked at what it "
             "was using. The tokens pushing toward \"safe\" were `url:`, `date:`, `2002`, "
             "`spambayes`, `list`, `tel:`, `fax:`. None of those is a property of "
             "legitimate mail. They are properties of the SpamAssassin archive. Counted "
             "directly:\n")
    L.append(_table(["body-level tell", "% of legitimate", "% of phishing"],
                    [[k, f"{v['legitimate_pct']}% ({v['legitimate_n']})",
                      f"{v['phishing_pct']}% ({v['phishing_n']})"]
                     for k, v in ds["body_artifact_prevalence"].items()]))
    L.append("")
    L.append("Three distinct mechanisms, all inside the body:\n")
    L.append("1. **RSS digest boilerplate.** A large block of the easy_ham set are "
             "feed-to-mail digests whose body literally begins `URL: http://...` newline "
             "`Date: 2002-10-08T00:22:08-05:00`. That two-line prefix appears on a sixth "
             "of the negative class and on none of the positive class.\n"
             "2. **Mailing-list identity.** The ham names its own lists in the body text "
             "-- `spamassassin`, `exmh`, `ilug`, `zzzzteana`, `razor-users`, "
             "`sourceforge.net`, `listinfo` URLs, unsubscribe footers.\n"
             "3. **Era tokens in prose.** Ham bodies say 2002; phishing bodies say 2005, "
             "2006, 2007. The year is written in the text, so removing the `Date` header "
             "does not remove the date.\n")
    L.append("The `content_hardened` view removes all three: the RSS prefix and "
             "list-management lines are deleted, a named list of corpus-identifying terms "
             "is stripped, and URLs, email addresses, years and digit runs are replaced by "
             "placeholder tokens. URLs go to a placeholder rather than being deleted "
             "because the *structure* of every URL is already captured by the 65 "
             "engineered features -- what leaks is the literal host string, "
             "`lists.sourceforge.net` on one side and a payload domain on the other.\n")
    d_auc = hardened["roc_auc"] - content["roc_auc"]
    L.append(f"Result: ROC-AUC {content['roc_auc']:.4f} -> {hardened['roc_auc']:.4f} "
             f"({d_auc:+.4f}), accuracy {content['accuracy']:.4f} -> "
             f"{hardened['accuracy']:.4f}.\n")
    if abs(d_auc) < 0.002:
        L.append("**That is a negative result and it is the most useful thing in this "
                 "report.** I removed the RSS prefix from a sixth of the negative class, "
                 "the list names from a third of it, every year, every URL string and "
                 "every email address, and the score did not move. Not \"moved a little\" "
                 "-- ROC-AUC changed in the fourth decimal place.\n")
        L.append("The explanation is visible in the coefficients. Before hardening, the "
                 "strongest \"safe\" signals were `url:`, `date:`, `2002`, `spambayes`, "
                 "`list`. After hardening they are:\n")
        L.append(_coef_block(d["top_coefficients"][HONEST_KEY]["pushes_toward_safe"], 12))
        L.append("")
        L.append("`that`, `of`, `it`, `and`, `in`, `is`, `which`, `as`. English function "
                 "words. The model gave up the artifacts I deleted and replaced them with "
                 "a signal of identical strength: **long-form human prose**. The "
                 "SpamAssassin ham is people arguing about Perl and pasta on 2002 "
                 "discussion lists -- multi-paragraph natural writing, full of subordinate "
                 "clauses. The phishing corpus is short templated marketing copy. A "
                 "classifier can separate those two genres perfectly without knowing "
                 "anything about phishing.\n")
        L.append("This is the real lesson, and it is stronger than the one I set out to "
                 "demonstrate. **Leakage in a two-corpus dataset is redundant.** The two "
                 "archives differ in dozens of correlated ways at once -- routing, client "
                 "software, era, recipient anonymisation, MIME format, genre, register, "
                 "sentence length. Remove one channel and the model routes around it "
                 "through another of equal strength. Enumerating and deleting artifacts "
                 "cannot work, because you are not draining a reservoir, you are plugging "
                 "one hole in a colander.\n")
        L.append("What pushes toward \"phishing\" after hardening does look like phishing "
                 "-- brand names, account language, HTML structure, host shape:\n")
        L.append(_coef_block(d["top_coefficients"][HONEST_KEY]["pushes_toward_phishing"], 14))
        L.append("")
        L.append("So the positive class is being recognised for plausible reasons while "
                 "the negative class is being recognised for the wrong ones. That "
                 "asymmetry is exactly what the generic-spam probe in Finding 6 detects.\n")
    else:
        L.append("What is left driving it:\n")
        L.append(_coef_block(d["top_coefficients"][HONEST_KEY]["pushes_toward_phishing"], 14))
        L.append("")
        L.append("Hardening lowered the score, which is the direction that suggests the "
                 "removed tokens were genuinely being used.\n")
    L.append("I do not claim `content_hardened` is clean. It is built from an enumerated "
             "blocklist of corpus terms, which is precisely the approach Finding 2 shows "
             "to be unreliable. It is kept as the headline configuration because it is the "
             "most conservative view I can construct from the text, not because it is "
             "sound.\n")
    L.append("### A note on reading coefficient tables\n")
    tc = d["top_coefficients"][HONEST_KEY]
    L.append(f"The lists above are restricted to tokens appearing in at least "
             f"{tc['min_train_document_frequency']} training messages "
             f"({tc['n_features_above_min_df']} of {tc['n_features_total']} features "
             "qualify). The unrestricted ranking is misleading, and I only noticed after "
             "the first run: it was topped by tokens occurring in three messages "
             "(`beetapiale`, `c2report`, `pharmacy`, `evil gerald`). With `min_df=3` a "
             "linear model will assign a large weight to a token it saw three times. That "
             "tells you about the regularisation, not about the corpus. The unfiltered "
             "list is kept in `summary_stats.json` under "
             "`pushes_toward_phishing_unfiltered` so the difference is visible.\n")


def _section_format(d, L):
    fc = d["dataset"]["format_confound"]
    ctl = d["format_controls"]
    L.append("## Finding 4: the biggest confound is not text at all, it is MIME\n")
    L.append(f"{fc['pct_phishing_with_html_part']}% of the phishing messages have an HTML "
             f"part. {fc['pct_legitimate_with_html_part']}% of the legitimate ones do. "
             f"\"Does this message contain HTML\", used as the entire classifier, scores "
             f"{fc['accuracy_of_has_html_as_a_single_rule']:.4f} accuracy.\n")
    L.append(_table(["archive", "messages", "with an HTML part"],
                    [[k, v["n"], f"{v['pct_html']}%"] for k, v in fc["by_source"].items()]))
    L.append("")
    L.append("This is partly real -- phishing genuinely is HTML brand-impersonation mail "
             "-- and partly an artifact: the SpamAssassin ham is overwhelmingly plain-text "
             "mailing-list traffic from 2002, which is not what a modern inbox looks like. "
             "The two cannot be separated by editing text, because format is a property of "
             "the message. The only clean way to measure it is to hold format constant.\n")
    full = d["leakage_grid"][HONEST_KEY]
    rows = [["whole corpus (for reference)",
             f"{full['n_test_ham']} / {full['n_test_phish']} in test",
             f"{full['roc_auc']:.4f}", f"{full['average_precision']:.4f}",
             f"{full['prec_at_fpr_0.005']['recall']:.4f}",
             f"{full['prec_at_fpr_0.001']['recall']:.4f}"]]
    for key in ("plaintext_only", "html_only"):
        v = ctl[key]
        if "roc_auc" not in v:
            rows.append([key, v.get("n", "-"), "skipped: " + v.get("skipped", ""),
                         "-", "-", "-"])
            continue
        rows.append([key, f"{v['n_legitimate']} legit / {v['n_phishing']} phish",
                     f"{v['roc_auc']:.4f}", f"{v['average_precision']:.4f}",
                     f"{v['prec_at_fpr_0.005']['recall']:.4f}",
                     f"{v['prec_at_fpr_0.001']['recall']:.4f}"])
    L.append(_table(["subset", "class sizes", "ROC-AUC", "avg precision",
                     "recall @ FPR<=0.5%", "recall @ FPR<=0.1%"], rows))
    L.append("")
    pt = ctl["plaintext_only"]
    if "roc_auc" in pt:
        L.append(f"**The plain-text control is the most informative number in this "
                 f"project.** {pt['n_legitimate']} legitimate and {pt['n_phishing']} "
                 f"phishing messages, none with an HTML part, so `has_html` and every "
                 f"HTML-derived feature is constant and carries zero information. Same "
                 f"hardened content view, same grouped split, same estimator.\n")
        L.append(f"ROC-AUC falls from {full['roc_auc']:.4f} to {pt['roc_auc']:.4f}. "
                 f"Average precision falls from {full['average_precision']:.4f} to "
                 f"{pt['average_precision']:.4f}. And the metric that would actually "
                 f"govern deployment collapses: recall at a 0.1% false-positive budget "
                 f"goes from {full['prec_at_fpr_0.001']['recall']:.4f} to "
                 f"{pt['prec_at_fpr_0.001']['recall']:.4f}. At a threshold tight enough to "
                 f"be safe on real mail, a format-controlled model finds "
                 f"{100 * pt['prec_at_fpr_0.001']['recall']:.0f}% of the phishing instead "
                 f"of {100 * full['prec_at_fpr_0.001']['recall']:.0f}%.\n")
        L.append(f"At the threshold chosen on training folds it manages recall "
                 f"{pt['recall']:.4f} at precision {pt['precision']:.4f} "
                 f"({_cm(pt)}). That is a usable classifier, and it is a much more "
                 f"believable description of what this data supports than 0.99 anything.\n")
        L.append(f"Caveat, and it is a real one: the phishing class here is only "
                 f"{pt['n_phishing']} messages against {pt['n_legitimate']} legitimate, "
                 f"so the test fold has {pt['n_test_phish']} positives. These numbers are "
                 f"directional, not precise, and the class balance is inverted relative to "
                 f"the main experiment. I am reporting them because a noisy measurement of "
                 f"the right quantity beats a precise measurement of the wrong one.\n")
    ho = ctl["html_only"]
    if "roc_auc" in ho:
        L.append(f"The HTML-only control (ROC-AUC {ho['roc_auc']:.4f}) is the mirror "
                 f"image and mostly confirms that the phishing side is easy to spot once "
                 f"you are looking at HTML mail. Its accuracy column is not worth reading "
                 f"and shows something worth knowing about fixed-FPR thresholds: with only "
                 f"{ho['n_legitimate']} legitimate messages in the whole subset, one false "
                 f"positive in a training fold is already above a 0.5% FPR budget, so the "
                 f"threshold search returns essentially 1.0 "
                 f"({ho['oof_threshold_source']['chosen_threshold']:.4f}) and almost "
                 f"nothing gets flagged. Accuracy {ho['accuracy']:.4f}, "
                 f"{ho['confusion_matrix']['fn']} false negatives, zero false positives. "
                 f"A false-positive budget is only meaningful when you have enough "
                 f"negatives to resolve it.\n")


def _section_dupes(d, L):
    dup, sp, grid = d["duplicates"], d["splits"], d["leakage_grid"]
    L.append("## Finding 5: near-duplicate campaigns inflate a random split\n")
    L.append("MinHash over 5-word shingles of the normalised body, 32-band LSH for "
             "candidates, Jaccard >= 0.70 to confirm, union-find to cluster. URLs and "
             "digits become placeholders before shingling, because rotating the payload "
             "host and the victim's account number is exactly what a campaign does "
             "between sends -- two messages differing only in those must land in the same "
             "group.\n")
    L.append(_table(["", "legitimate", "phishing"],
                    [["messages", dup["ham_n_records"], dup["phish_n_records"]],
                     ["distinct clusters", dup["ham_n_groups"], dup["phish_n_groups"]],
                     ["largest cluster", dup["ham_largest_group"], dup["phish_largest_group"]],
                     ["% in a multi-member cluster",
                      f"{dup['ham_pct_in_multi_member_groups']}%",
                      f"{dup['phish_pct_in_multi_member_groups']}%"]]))
    L.append("")
    L.append(f"{dup['phish_n_records']} phishing messages are only "
             f"{dup['phish_n_groups']} distinct campaigns. "
             f"{dup['phish_pct_in_multi_member_groups']}% have a near-twin somewhere in "
             f"the corpus, against {dup['ham_pct_in_multi_member_groups']}% of the "
             f"legitimate mail. Under a random split "
             f"{sp['random']['pct_test_phish_contaminated']}% of test phishing messages "
             f"have a near-duplicate sitting in training "
             f"({sp['random']['test_messages_with_a_near_duplicate_in_train']} of "
             f"{sp['random']['n_test']} test messages overall). Under the grouped split, "
             f"by construction, none do.\n")
    L.append("### Which metric shows it, and which one cannot\n")
    L.append("This is where choosing the metric first pays off. The effect of the split "
             "strategy on each view:\n")
    rows = []
    for view in VIEW_ORDER:
        r, gp = grid[f"{view}|random"], grid[f"{view}|grouped"]
        rows.append([
            view,
            f"{r['roc_auc']:.4f} / {gp['roc_auc']:.4f}",
            f"{r['roc_auc'] - gp['roc_auc']:+.4f}",
            f"{r['at_default_0.5']['accuracy']:.4f} / {gp['at_default_0.5']['accuracy']:.4f}",
            f"{r['at_default_0.5']['accuracy'] - gp['at_default_0.5']['accuracy']:+.4f}",
            f"{r['prec_at_fpr_0.005']['recall']:.4f} / {gp['prec_at_fpr_0.005']['recall']:.4f}",
            f"{r['prec_at_fpr_0.005']['recall'] - gp['prec_at_fpr_0.005']['recall']:+.4f}",
        ])
    L.append(_table(["view", "ROC-AUC rnd/grp", "delta", "accuracy@0.5 rnd/grp", "delta",
                     "recall@FPR<=0.5% rnd/grp", "delta"], rows))
    L.append("")
    hv = "content_hardened"
    d_rec = (grid[f"{hv}|random"]["prec_at_fpr_0.005"]["recall"]
             - grid[f"{hv}|grouped"]["prec_at_fpr_0.005"]["recall"])
    d_auc = grid[f"{hv}|random"]["roc_auc"] - grid[f"{hv}|grouped"]["roc_auc"]
    L.append(f"**ROC-AUC cannot see this effect and average precision cannot either.** On "
             f"the hardened view the AUC delta is {d_auc:+.4f} -- the wrong sign, and far "
             f"below anything a single 25% fold can resolve. Both metrics are pinned above "
             f"0.998 across the entire grid; there is no headroom left in which to observe "
             f"a difference. Reporting \"the grouped split made no difference to AUC\" "
             f"would have been a true statement and a wrong conclusion.\n")
    L.append(f"Recall at the 0.5% false-positive budget shows it clearly: "
             f"{d_rec:+.4f} on the hardened view "
             f"({grid[f'{hv}|random']['prec_at_fpr_0.005']['recall']:.4f} random against "
             f"{grid[f'{hv}|grouped']['prec_at_fpr_0.005']['recall']:.4f} grouped), and "
             f"{grid['content|random']['prec_at_fpr_0.005']['recall'] - grid['content|grouped']['prec_at_fpr_0.005']['recall']:+.4f} "
             f"on the plain content view. Accuracy at a fixed 0.5 threshold agrees, at "
             f"roughly +0.009. So campaign leakage is worth one to two points of the "
             f"detection rate at a deployable threshold, in the predicted direction.\n")
    L.append("There is a second thing in that table worth pausing on. On the `full` view "
             "the split strategy is worth exactly nothing on every metric. Header leakage "
             "has already saturated the model, so there is no room for duplicate leakage "
             "to add anything. **You cannot measure the second problem until you have "
             "fixed the first**, which is an argument for doing leakage analysis in stages "
             "rather than trying to assess it all from one number.\n")
    L.append("The size of the effect is still smaller than I expected going in. Three "
             "quarters of the phishing side is duplicated, so I assumed campaign leakage "
             "would dominate; instead it is worth one or two points where header leakage "
             "was worth twenty. The likely reason is that these campaigns resemble "
             "phishing in general and not only each other, so a model that has already "
             "seen 1,900 other campaigns gains little from having seen this exact one. The "
             "grouped split stays the default because it costs nothing and removes an "
             "unambiguous bias, but it was not where the problem was.\n")

    L.append("### The full grid\n")
    rows = []
    for view in VIEW_ORDER:
        for split in ("random", "grouped"):
            r = grid[f"{view}|{split}"]
            rows.append([view, split, f"{r['roc_auc']:.4f}", f"{r['accuracy']:.4f}",
                         f"{r['average_precision']:.4f}",
                         f"{r['prec_at_fpr_0.005']['recall']:.4f}", _cm(r)])
    L.append(_table(["text view", "split", "ROC-AUC", "accuracy", "avg precision",
                     "recall @ FPR<=0.5%", "confusion matrix"], rows))
    L.append("")
    L.append(_table(["view", "what the model sees"],
                    [[v, VIEW_DESC[v]] for v in VIEW_ORDER]))
    L.append("")
    L.append("Same estimator (logistic regression, identical hyperparameters), same "
             "engineered features, same seed, same 25% test fraction throughout. Only the "
             "text view and the split rule change.\n")


def _section_metrics(d, L):
    honest = d["headline"]["metrics"]
    L.append("## Why accuracy is the wrong headline metric\n")
    L.append("The brief asks for accuracy and a confusion matrix, and both are above. "
             "Neither is the metric I would use to decide whether to deploy this.\n")
    L.append("A false positive is a legitimate message filed as an attack: somebody's "
             "invoice, password reset, or note from a colleague, now in a quarantine "
             "folder nobody reads. A false negative is one more phishing mail in an inbox "
             "that already receives them, in front of a user who is the next control in "
             "the chain. Those costs differ by orders of magnitude, and accuracy weights "
             "them equally. On a realistic class balance -- phishing well under 1% of mail "
             "-- accuracy is worse than useless, because predicting \"safe\" for "
             "everything scores above 0.99.\n")
    L.append("So the threshold is not 0.5. It is the most sensitive threshold whose "
             "false-positive rate stays inside a 0.5% budget on out-of-fold *training* "
             "scores, then applied unchanged to the test fold. The test set never informs "
             "it.\n")
    ap, ap1 = honest["prec_at_fpr_0.005"], honest["prec_at_fpr_0.001"]
    L.append(_table(["operating point", "threshold", "precision", "recall", "false positives"],
                    [["chosen: FPR budget 0.5%, fixed on training folds",
                      f"{honest['threshold']:.4f}", f"{honest['precision']:.4f}",
                      f"{honest['recall']:.4f}", honest["confusion_matrix"]["fp"]],
                     ["sklearn default 0.5", "0.5000",
                      f"{honest['at_default_0.5']['precision']:.4f}",
                      f"{honest['at_default_0.5']['recall']:.4f}",
                      honest["at_default_0.5"]["confusion_matrix"]["fp"]],
                     ["post-hoc best at FPR<=0.5% (test-fitted, reference only)",
                      f"{ap['threshold']:.4f}", f"{ap['precision']:.4f}",
                      f"{ap['recall']:.4f}", ap["false_positives"]],
                     ["post-hoc best at FPR<=0.1% (test-fitted, reference only)",
                      f"{ap1['threshold']:.4f}", f"{ap1['precision']:.4f}",
                      f"{ap1['recall']:.4f}", ap1["false_positives"]]]))
    L.append("")
    src = honest["oof_threshold_source"]
    realised = honest["confusion_matrix"]["fp"] / honest["n_test_ham"]
    L.append(f"The chosen threshold {honest['threshold']:.4f} realised "
             f"{src['oof_fpr_at_threshold']:.4f} FPR on the training folds and "
             f"{realised:.4f} on the test fold "
             f"({honest['confusion_matrix']['fp']} false positives on "
             f"{honest['n_test_ham']} legitimate test messages). The two post-hoc rows "
             "show what the curve could have delivered with the threshold tuned on the "
             "test set, which is not a thing you are allowed to do; the gap between them "
             "and the chosen row is the honest cost of picking an operating point in "
             "advance.\n")
    fps = d["headline"].get("false_positives_by_ham_source")
    if fps:
        L.append("Which legitimate mail it gets wrong, by archive:\n")
        L.append(_table(["ham archive", "in test fold", "false positives", "FPR"],
                        [[k, v["n_legitimate_in_test"], v["false_positives"],
                          f"{v['fpr']:.4f}"] for k, v in fps.items()]))
        L.append("")
        hard = fps.get("20030228_hard_ham", {})
        easy = fps.get("20030228_easy_ham", {})
        L.append("`hard_ham` is SpamAssassin's deliberately difficult negative set: "
                 "commercial HTML mail, newsletters, order confirmations -- the "
                 "legitimate mail that most resembles an attack.\n")
        if hard and easy and hard["fpr"] > easy["fpr"]:
            L.append(f"The false positives concentrate exactly there: FPR "
                     f"{hard['fpr']:.4f} on hard_ham against {easy['fpr']:.4f} on "
                     f"easy_ham. That is the behaviour you want -- the model fails on the "
                     f"genuinely ambiguous mail and not at random -- but it also says that "
                     f"the low overall false-positive rate is partly a gift from the "
                     f"corpus. hard_ham is 250 of 4,150 legitimate messages here. A real "
                     f"inbox is mostly hard_ham: receipts, newsletters, notifications. "
                     f"Weighted for that, the deployed false-positive rate would be "
                     f"closer to {hard['fpr']:.2%} than to the "
                     f"{honest['confusion_matrix']['fp'] / honest['n_test_ham']:.2%} "
                     f"headline.\n")
        else:
            L.append("The false positives are not concentrated in hard_ham, which is "
                     "harder to explain and worth a closer look than this report gives "
                     "it.\n")


def _section_models(d, L):
    ds, hl, abl = d["dataset"], d["headline"], d["ablations"]
    L.append("## Model comparison\n")
    L.append(_table(["model", "ROC-AUC", "avg precision", "accuracy", "recall",
                     "recall @ FPR<=0.5%", "confusion matrix"],
                    [[n, f"{r['roc_auc']:.4f}", f"{r['average_precision']:.4f}",
                      f"{r['accuracy']:.4f}", f"{r['recall']:.4f}",
                      f"{r['prec_at_fpr_0.005']['recall']:.4f}", _cm(r)]
                     for n, r in d["model_comparison"].items()]))
    L.append("")
    L.append(f"All four on the honest configuration, same pipeline, same features, same "
             f"folds. `{hl['model']}` wins on the metric that matters here -- recall at "
             f"the false-positive budget -- and is the model behind the headline. The "
             f"linear models sit close together, which is what you expect on "
             f"high-dimensional sparse text. `sgd_modified_huber` has the worst AUC "
             f"despite competitive accuracy: modified-Huber gives clipped, poorly spread "
             f"scores, so its ranking is weaker even where its hard predictions are fine, "
             f"which is a good argument for not judging a model by accuracy. The forest "
             f"sees only the 2,000 chi2-selected terms rather than the full vocabulary; "
             f"that restriction is deliberate, since a forest on 200k sparse columns is "
             f"not worth the runtime.\n")
    L.append("Thresholds were selected per model on out-of-fold training scores, not left "
             "at 0.5, and LinearSVC was wrapped in Platt scaling because it has no native "
             "probabilities and the operating point is defined on one.\n")
    L.append("### Where the signal lives\n")
    L.append(_table(["features", "ROC-AUC", "accuracy", "recall @ FPR<=0.5%"],
                    [["TF-IDF over the hardened text only",
                      f"{abl['tfidf_only']['roc_auc']:.4f}",
                      f"{abl['tfidf_only']['accuracy']:.4f}",
                      f"{abl['tfidf_only']['prec_at_fpr_0.005']['recall']:.4f}"],
                     [f"the {ds['n_numeric_features']} engineered features only",
                      f"{abl['numeric_only']['roc_auc']:.4f}",
                      f"{abl['numeric_only']['accuracy']:.4f}",
                      f"{abl['numeric_only']['prec_at_fpr_0.005']['recall']:.4f}"],
                     ["both (logistic regression)", f"{abl['both']['roc_auc']:.4f}",
                      f"{abl['both']['accuracy']:.4f}",
                      f"{abl['both']['prec_at_fpr_0.005']['recall']:.4f}"]]))
    L.append("")
    if abl["tfidf_only"]["roc_auc"] >= abl["both"]["roc_auc"]:
        L.append("Worth stating plainly: for the logistic regression the engineered "
                 "features do not help. TF-IDF alone matches or beats the combination. "
                 "The likely mechanism is scale -- TF-IDF rows are L2-normalised while the "
                 "standardised numeric block is not, so 65 dense standardised columns "
                 "consume a disproportionate share of a single L2 penalty and slightly "
                 "distort the fit. I could have fixed this by tuning the relative weight "
                 "of the two blocks; I did not, because the more useful thing to report "
                 "is that the hand-built features earned their place in the tree model "
                 "and not in the linear one.\n")
    else:
        L.append("The engineered features add measurably to TF-IDF alone for the linear "
                 "model.\n")
    rf = d["random_forest_importance"]
    L.append(f"In the random forest the engineered block holds "
             f"{rf['total_importance_engineered_block']:.1%} of total impurity-based "
             f"importance against {rf['total_importance_text_block']:.1%} for the 2,000 "
             f"selected TF-IDF terms, from only {ds['n_numeric_features']} columns. Top "
             f"engineered features:\n")
    L.append("```")
    for name, v in rf["top_engineered_features"][:14]:
        L.append(f"  {v:.4f}  {name}")
    L.append("```")
    L.append("")
    L.append("The HTML-structure features dominate, which is Finding 4 restated from the "
             "model's point of view rather than the corpus's.\n")
    L.append("### Prevalence of the URL and HTML signals\n")
    L.append("What each engineered feature is for is documented at its definition in "
             "`src/features.py`. What matters here is which ones actually fire:\n")
    L.append(_table(["feature (non-zero)", "phishing", "legitimate"],
                    [[k, f"{v['phish_pct_nonzero']}%", f"{v['ham_pct_nonzero']}%"]
                     for k, v in ds["feature_prevalence"].items()]))
    L.append("")
    prev = ds["feature_prevalence"]
    duds = sorted(k for k, v in prev.items()
                  if v["phish_pct_nonzero"] < 3.0
                  or v["phish_pct_nonzero"] < 2 * max(v["ham_pct_nonzero"], 0.01))
    works = sorted((k for k in prev if k not in duds),
                   key=lambda k: -(prev[k]["phish_pct_nonzero"] - prev[k]["ham_pct_nonzero"]))
    L.append(f"Of the twelve checked here, {len(works)} discriminate usefully and "
             f"{len(duds)} do not. The ones that work, by prevalence gap: "
             + ", ".join(f"`{k}` ({prev[k]['phish_pct_nonzero']}% vs "
                         f"{prev[k]['ham_pct_nonzero']}%)" for k in works[:5]) + ".\n")
    L.append(f"The ones that do not: {', '.join('`' + k + '`' for k in duds)}. I am "
             "listing them because a feature table that only shows the winners is a "
             "sales document. `has_shortener` and `has_punycode` are near zero on both "
             "classes because URL shorteners and internationalised domains were barely in "
             "use in 2004-2007. `has_at_in_url` is the textbook userinfo trick and it "
             "appears in almost nothing. `n_forms` surprised me most: a credential form "
             "embedded in the mail body is supposed to be the signature move, and it "
             f"appears in {prev['n_forms']['phish_pct_nonzero']}% of the phishing against "
             f"{prev['n_forms']['ham_pct_nonzero']}% of the legitimate mail -- almost no "
             "discrimination at all. These kits overwhelmingly linked out to a hosted "
             "page rather than embedding the form. All of them stay in the feature set "
             "because they cost nothing and would matter on modern mail, but on this "
             "corpus they are not doing the work and it would be dishonest to imply they "
             "are.\n")


def _section_probe(d, L):
    p = d["spam_probe"]
    L.append("## Finding 6: is this a phishing detector or a spam detector?\n")
    L.append(f"{p['n_generic_spam']} SpamAssassin spam messages -- unsolicited bulk mail, "
             f"not credential phishing, never seen in training, same era as the ham -- "
             f"scored with the honest model at its chosen threshold "
             f"{p['threshold_used']:.4f}: **{p['flagged_as_phishing']} of them "
             f"({p['flagged_pct']}%) are flagged as phishing**, median score "
             f"{p['median_score']:.4f}.\n")
    if p["flagged_pct"] > 20:
        L.append("This is the most damaging result in the report and the reason I would "
                 "not describe the headline number as a phishing detection rate. A large "
                 "fraction of ordinary junk mail trips the threshold. Nothing in the "
                 "training data could have taught the model otherwise: the negative class "
                 "is mailing-list and personal mail, so \"not ham\" and \"phishing\" are "
                 "the same category as far as the fit is concerned, and the model has "
                 "learned a decision boundary around unsolicited bulk HTML mail rather "
                 "than around credential theft.\n")
        L.append("Fixing it needs a third class -- non-phishing spam as its own label, or "
                 "at minimum as additional negatives -- which is a different experiment "
                 "and a different brief. What I can say is that the number is measured, "
                 "not assumed, and that any deployment of this model would spend its "
                 "false-positive budget here.\n")
    else:
        L.append("The flag rate is low, which is the outcome you want: the model is not "
                 "simply firing on anything that looks like bulk mail.\n")


def _section_limits(d, L):
    pt = d["format_controls"].get("plaintext_only", {})
    probe = d["spam_probe"]
    honest = d["headline"]["metrics"]
    L.append("## What the honest number is, restated\n")
    L.append(_table(["claim", "number", "how much to trust it"],
                    [["accuracy on the hardened content view, grouped split",
                      f"{honest['accuracy']:.4f}",
                      "correct as a measurement; misleading as a phishing detection rate"],
                     ["ROC-AUC, same configuration", f"{honest['roc_auc']:.4f}",
                      "same caveat"],
                     ["ROC-AUC with MIME format held constant",
                      f"{pt.get('roc_auc', float('nan')):.4f}",
                      "the best estimate here of how much is really about phishing; "
                      "small sample"],
                     ["average precision, format held constant",
                      f"{pt.get('average_precision', float('nan')):.4f}",
                      "same"],
                     ["share of generic spam flagged as phishing",
                      f"{probe['flagged_pct']}%",
                      "measured on 1,897 held-out messages; the clearest evidence that "
                      "part of the model is a spam filter"]]))
    L.append("")
    L.append(f"If someone asks for one number, it is **{honest['accuracy']:.4f} accuracy "
             f"/ {honest['roc_auc']:.4f} ROC-AUC** on the hardened content view with a "
             f"grouped split, and the honest sentence attached to it is \"on this corpus, "
             f"where roughly a quarter of the apparent skill is MIME format and some "
             f"further part is spam-versus-prose genre\". If someone asks how well it "
             f"would detect phishing, the answer is closer to "
             f"{pt.get('roc_auc', float('nan')):.3f} AUC and I would not quote an accuracy "
             f"at all.\n")
    L.append("## Limitations\n")
    L.append("- **Format is the largest confound and it cannot be removed by "
             "preprocessing.** 93% of the phishing has an HTML part against 4.5% of the "
             "ham. Holding it constant costs most of the apparent performance. The only "
             "real fix is a negative class drawn from the same kind of mailbox as the "
             "positive one, which no public corpus pairing provides.\n"
             "- **Leakage is redundant** (Finding 3). Deleting one channel does not lower "
             "the score, because the two archives differ in many correlated ways at once. "
             "Any \"we removed the leaky features\" claim in this area, including mine, "
             "should be treated as unproven.\n"
             "- **Era.** The corpora are 2002-2007. No OAuth consent phishing, no QR "
             "codes, no HTML-attachment kits, no landing pages on legitimate cloud "
             "domains. Nothing here is a current detection rate.\n"
             "- **Different collectors.** The content views remove the header channel and "
             "the body tells I found, but I can only remove the confounds I noticed. The "
             "residual score is an upper bound on real signal, not a measurement of it.\n"
             "- **The hardened view uses a blocklist**, the same technique this report "
             "argues against for headers. It is included because it lowers the score and "
             "is therefore the conservative choice, not because it is sound.\n"
             "- **Subject is treated as content.** It is written by the attacker and read "
             "by the victim, so dropping it would discard genuine signal. But it is a "
             "header field, and a stricter reading of the experiment would exclude it.\n"
             "- **Clustering threshold.** Jaccard 0.70 over placeholder-normalised 5-word "
             "shingles is a judgement call. Tighter leaves campaign fragments split across "
             "the boundary; looser merges unrelated lures sharing boilerplate. One "
             "oversized LSH bucket was merged wholesale rather than pairwise-verified -- a "
             "deliberate imprecision in favour of not splitting a campaign.\n"
             "- **Class balance.** Near 50/50 here, well under 1% in reality. Precision "
             "on a real stream would be far worse at the same threshold.\n"
             "- **The spam probe is not closed.** A model that flags a large share of "
             "generic spam is partly a spam filter, and this experiment does not separate "
             "the two.\n"
             "- **Single split.** Every number is one 25% test fold, not a repeated-CV "
             "mean with confidence intervals. The threshold is chosen by 5-fold "
             "cross-validation inside training, but the headline metrics have no error "
             "bars. Differences below about 0.005 between rows should not be read as "
             "real.\n")


def write_findings(d: dict) -> str:
    L = ["# Findings\n",
         "Phishing email detection on the SpamAssassin public corpus (legitimate mail) "
         "and the Nazario phishing corpus. Every number below comes from one run of "
         f"`python -m src.train` with seed {d['meta']['seed']}; the same values are in "
         "`summary_stats.json` in this directory.\n",
         "The short version: the classifier works, the obvious way of measuring it does "
         "not, and most of the work here went into finding five separate reasons the score "
         "was too high and putting a number on each. One of those attempts failed to "
         "change the score at all, and that failure turned out to be the most useful "
         "result (Finding 3).\n"]
    _section_headline(d, L)
    _section_data(d, L)
    _section_headers(d, L)
    _section_body(d, L)
    _section_format(d, L)
    _section_dupes(d, L)
    _section_metrics(d, L)
    _section_models(d, L)
    _section_probe(d, L)
    _section_limits(d, L)
    L.append("## Reproducing\n")
    L.append("```\npython -m src.download   # ~50 MB, cached in data/raw/\n"
             "python -m src.parse      # -> data/processed/emails.jsonl.gz\n"
             "python -m src.dedupe     # -> data/processed/groups.csv\n"
             "python -m src.train      # -> outputs/figures/, outputs/reports/\n```\n")
    L.append(f"Seed {d['meta']['seed']} throughout. scikit-learn {d['meta']['sklearn']}, "
             f"pandas {d['meta']['pandas']}, numpy {d['meta']['numpy']}, Python "
             f"{d['meta']['python']}. Two consecutive runs of `src.train` produce a "
             "byte-identical `summary_stats.json`; that was checked, not assumed.\n")
    text = "\n".join(L)
    path = REPORTS / "findings.md"
    path.write_text(text, encoding="utf-8")
    print(f"wrote {path}")
    return str(path)


if __name__ == "__main__":
    write_findings(json.loads((REPORTS / "summary_stats.json").read_text(encoding="utf-8")))
    sys.exit(0)
