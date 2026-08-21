"""Hand-built URL / HTML / text features, plus the three text views.

Every feature here is something a security analyst would actually look at when
triaging a suspicious mail. Each block has a comment saying what deception it
is meant to catch, because a feature you cannot justify is a feature you cannot
defend when it turns out to be the one doing all the work.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import unquote, urlsplit

from .config import CORPUS_ARTIFACT_TERMS

# ---------------------------------------------------------------- URL finding
URL_RE = re.compile(
    r"(?i)\b(?:https?://|ftp://|www\d{0,3}\.)[^\s<>\"'`)\]\}]{2,600}"
)
HREF_RE = re.compile(r"""(?is)<a\b[^>]*?href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>(.*?)</a\s*>""")
IMG_SRC_RE = re.compile(r"""(?is)<img\b[^>]*?src\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""")
FORM_RE = re.compile(r"""(?is)<form\b([^>]*)>""")
INPUT_RE = re.compile(r"""(?is)<input\b([^>]*)>""")
TAG_RE = re.compile(r"<[^>]{0,4000}>")

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
HEXIP_RE = re.compile(r"^(?:0x[0-9a-f]+|\d{8,10})$", re.IGNORECASE)

# Multi-label public suffixes that appear in these corpora. Without a real
# public-suffix list, treating "co.uk" as a TLD keeps subdomain depth honest.
TWO_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au",
    "org.au", "co.nz", "co.jp", "co.kr", "com.br", "com.mx", "com.ar",
    "co.za", "com.cn", "com.tw", "com.hk", "com.sg", "co.in", "com.tr",
    "com.my", "com.ph", "co.th", "com.pl", "com.ua", "co.il", "com.ru",
}

# URL shorteners. In a 2002-2007 corpus these are nearly absent; the feature is
# kept because it costs nothing and the reported coefficient tells us so.
SHORTENERS = {
    "tinyurl.com", "bit.ly", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "j.mp", "tr.im", "snipurl.com", "shorturl.at", "cutt.ly",
    "rb.gy", "rebrand.ly", "tiny.cc", "makeashorterlink.com",
}

RISKY_PATH_EXT = (".exe", ".scr", ".pif", ".zip", ".rar", ".bat", ".cmd",
                  ".vbs", ".js", ".jar", ".hta", ".chm")

# Brands impersonated in the Nazario corpus. Used only for the
# "brand token appears in the URL but the registrable domain is not the
# brand's" check, which is the classic look-alike-host trick.
BRANDS = {
    "paypal", "ebay", "citibank", "citi", "wellsfargo", "wamu", "chase",
    "barclays", "halifax", "lloyds", "natwest", "hsbc", "abbey", "usbank",
    "bankofamerica", "amazon", "visa", "mastercard", "westpac", "nationwide",
    "suntrust", "regions", "fifththird", "keybank", "desjardins", "poste",
    "aol", "msn", "microsoft", "apple", "irs", "hmrc", "volksbank",
}

# Credential-harvesting language. The TF-IDF model will find these on its own;
# the explicit counts exist so the numeric-only model has something to work
# with and so the README can quote a rate rather than a coefficient.
LEXICON = {
    "kw_verify": r"\bverif(?:y|ication|ied)\b",
    "kw_account": r"\baccount\b",
    "kw_suspend": r"\bsuspend(?:ed|ing|sion)?\b|\bdeactivat|\brestrict(?:ed|ion)?\b",
    "kw_click": r"\bclick (?:here|below|the link)\b",
    "kw_login": r"\b(?:log ?in|sign ?in|logon)\b",
    "kw_password": r"\bpass(?:word|code)\b|\bp\s?i\s?n\b",
    "kw_security": r"\bsecurity\b|\bsecure\b",
    "kw_update": r"\bupdate your\b|\bconfirm your\b|\bupdate the\b",
    "kw_urgent": r"\burgent\b|\bimmediat(?:e|ely)\b|\bwithin \d+ (?:hours|days)\b|\bexpire",
    "kw_ssn": r"\bsocial security\b|\bssn\b|\bmother'?s maiden\b|\bdate of birth\b",
    "kw_card": r"\bcredit card\b|\bdebit card\b|\bcard number\b|\bcvv\b|\bATM\b",
    "kw_dear_customer": r"\bdear (?:valued )?(?:customer|user|member|client|account holder)\b",
}
LEXICON_RE = {k: re.compile(v, re.IGNORECASE) for k, v in LEXICON.items()}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _normalise_url(u: str) -> str:
    u = u.rstrip(".,;:)]}'\"")
    if u.lower().startswith("www"):
        u = "http://" + u
    return u


def host_of(url: str) -> str:
    try:
        netloc = urlsplit(url).netloc
    except ValueError:
        return ""
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
    if netloc.startswith("["):  # IPv6 literal
        return netloc
    return netloc.split(":")[0].lower().strip(".")


def registrable(host: str) -> str:
    """Approximate registrable domain: last two labels, or three when the last
    two are a known country suffix like co.uk."""
    if not host or IPV4_RE.match(host):
        return host
    labels = host.split(".")
    if len(labels) < 2:
        return host
    if ".".join(labels[-2:]) in TWO_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def tld_of(host: str) -> str:
    if not host or IPV4_RE.match(host):
        return "_ip"
    return host.rsplit(".", 1)[-1] if "." in host else "_none"


def extract_urls(body_text: str, body_html: str) -> "list[str]":
    urls = [_normalise_url(m.group(0)) for m in URL_RE.finditer(body_text)]
    for m in HREF_RE.finditer(body_html):
        href = (m.group(1) or m.group(2) or m.group(3) or "").strip()
        if href and not href.lower().startswith(("mailto:", "#")):
            urls.append(_normalise_url(href))
    return urls


def _anchor_mismatches(body_html: str) -> "tuple[int, int]":
    """Count anchors whose visible text names a different host than the href.

    This is the single most direct phishing tell in HTML mail: the text says
    www.paypal.com, the href goes somewhere else. Returns
    (mismatches, anchors_whose_text_looked_like_a_host)."""
    mismatch = 0
    checkable = 0
    for m in HREF_RE.finditer(body_html):
        href = (m.group(1) or m.group(2) or m.group(3) or "").strip()
        text = TAG_RE.sub(" ", m.group(4) or "")
        text = re.sub(r"\s+", "", text)
        if not href or href.lower().startswith(("mailto:", "#", "javascript:")):
            continue
        cand = URL_RE.search(text)
        if not cand:
            # Bare host in the anchor text, e.g. "paypal.com/login"
            bare = re.match(r"^[\w.-]+\.(?:com|net|org|co\.uk|de|fr|it|info|biz)\b", text, re.I)
            if not bare:
                continue
            shown_host = registrable(bare.group(0).split("/")[0].lower())
        else:
            shown_host = registrable(host_of(_normalise_url(cand.group(0))))
        real_host = registrable(host_of(_normalise_url(href)))
        if not shown_host or not real_host:
            continue
        checkable += 1
        if shown_host != real_host:
            mismatch += 1
    return mismatch, checkable


def url_features(urls: "list[str]") -> dict:
    hosts = [host_of(u) for u in urls]
    hosts = [h for h in hosts if h]
    regs = [registrable(h) for h in hosts]
    lengths = [len(u) for u in urls]
    ents = [shannon_entropy(u) for u in urls]

    def depth(h):
        # Labels in front of the registrable domain. "login.paypal.com.evil.ru"
        # scores 3; deep prefixes are how look-alike hosts are built.
        if not h or IPV4_RE.match(h):
            return 0
        return max(0, len(h.split(".")) - len(registrable(h).split(".")))

    depths = [depth(h) for h in hosts]
    n = len(urls)
    brand_abuse = 0
    for u, h in zip(urls, hosts):
        low = (h + " " + unquote(u).lower())
        reg = registrable(h)
        for b in BRANDS:
            if b in low and not reg.startswith(b + "."):
                brand_abuse += 1
                break

    return {
        "n_urls": n,
        "n_unique_urls": len(set(urls)),
        "n_unique_hosts": len(set(hosts)),
        "n_unique_tlds": len({tld_of(h) for h in hosts}),
        # A long or high-entropy URL usually means a random-looking payload
        # path or an encoded redirect chain.
        "url_max_len": max(lengths, default=0),
        "url_mean_len": (sum(lengths) / n) if n else 0.0,
        "url_max_entropy": max(ents, default=0.0),
        "url_mean_entropy": (sum(ents) / n) if n else 0.0,
        # A raw IP in place of a hostname means no domain was registered:
        # cheap, disposable, and near-universal in early phishing kits.
        "n_ip_urls": sum(1 for h in hosts if IPV4_RE.match(h)),
        "has_ip_url": int(any(IPV4_RE.match(h) for h in hosts)),
        # Decimal/hex encoded IPs hide the address from a casual reader.
        "has_obfuscated_ip": int(any(HEXIP_RE.match(h.replace(".", "")) and not IPV4_RE.match(h) for h in hosts)),
        # xn-- is an internationalised domain: a homograph attack vector.
        "has_punycode": int(any("xn--" in h for h in hosts)),
        # http://www.paypal.com@evil.ru/ -- everything before @ is userinfo and
        # is ignored by the browser, so the visible brand is a decoration.
        "has_at_in_url": int(any("@" in urlsplit(u).netloc for u in urls if "//" in u)),
        "max_subdomain_depth": max(depths, default=0),
        "mean_subdomain_depth": (sum(depths) / len(depths)) if depths else 0.0,
        "max_host_hyphens": max((h.count("-") for h in hosts), default=0),
        "max_host_digits": max((sum(c.isdigit() for c in h) for h in hosts), default=0),
        "has_shortener": int(any(r in SHORTENERS for r in regs)),
        # A non-standard port is a tell for a kit running on a compromised box.
        "has_nonstd_port": int(any(re.search(r":\d{2,5}(?:/|$)", u.split("//", 1)[-1]) for u in urls)),
        "pct_encoding_count": sum(u.count("%") for u in urls),
        "frac_https": (sum(1 for u in urls if u.lower().startswith("https")) / n) if n else 0.0,
        "has_risky_path_ext": int(any(urlsplit(u).path.lower().endswith(RISKY_PATH_EXT) for u in urls)),
        "brand_host_abuse": brand_abuse,
        # Many distinct hosts behind few links is unusual for real bulk mail.
        "hosts_per_url": (len(set(hosts)) / n) if n else 0.0,
    }


def html_features(body_html: str) -> dict:
    forms = FORM_RE.findall(body_html)
    inputs = INPUT_RE.findall(body_html)
    n_pw = sum(1 for a in inputs if re.search(r"""type\s*=\s*["']?password""", a, re.I))
    n_hidden = sum(1 for a in inputs if re.search(r"""type\s*=\s*["']?hidden""", a, re.I))
    form_ext = 0
    for a in forms:
        m = re.search(r"""action\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", a, re.I)
        if m:
            act = (m.group(1) or m.group(2) or m.group(3) or "")
            if act.lower().startswith(("http://", "https://")):
                form_ext += 1
    imgs = IMG_SRC_RE.findall(body_html)
    remote_imgs = sum(
        1 for t in imgs
        if (t[0] or t[1] or t[2] or "").lower().startswith(("http://", "https://"))
    )
    mismatch, checkable = _anchor_mismatches(body_html)
    tags = TAG_RE.findall(body_html)
    return {
        "has_html": int(bool(body_html.strip())),
        "html_tag_count": len(tags),
        "html_tag_ratio": (len("".join(tags)) / len(body_html)) if body_html else 0.0,
        # A form inside an email is the whole attack: it collects the
        # credentials without the victim ever leaving their mail client.
        "n_forms": len(forms),
        "n_password_inputs": n_pw,
        "n_hidden_inputs": n_hidden,
        "form_action_external": form_ext,
        "n_inputs": len(inputs),
        "n_iframe": len(re.findall(r"(?i)<iframe\b", body_html)),
        "n_script": len(re.findall(r"(?i)<script\b", body_html)),
        "has_javascript_uri": int(bool(re.search(r"(?i)javascript\s*:", body_html))),
        "n_onevent": len(re.findall(r"(?i)\bon(?:click|load|mouseover|submit|error)\s*=", body_html)),
        "n_images": len(imgs),
        "n_remote_images": remote_imgs,
        "anchor_host_mismatch": mismatch,
        "anchor_host_checkable": checkable,
        "anchor_mismatch_rate": (mismatch / checkable) if checkable else 0.0,
    }


def text_features(subject: str, body_text: str) -> dict:
    n = max(len(body_text), 1)
    letters = [c for c in body_text if c.isalpha()]
    out = {
        "body_len": len(body_text),
        "body_lines": body_text.count("\n") + 1,
        "body_digit_ratio": sum(c.isdigit() for c in body_text) / n,
        "body_upper_ratio": (sum(c.isupper() for c in letters) / len(letters)) if letters else 0.0,
        "body_nonascii_ratio": sum(ord(c) > 127 for c in body_text) / n,
        "n_exclaim": body_text.count("!"),
        "n_dollar": body_text.count("$"),
        "subject_len": len(subject),
        "subject_upper_ratio": (
            sum(c.isupper() for c in subject if c.isalpha())
            / max(sum(c.isalpha() for c in subject), 1)
        ),
        "subject_is_reply": int(bool(re.match(r"(?i)\s*(re|fw|fwd)\s*:", subject))),
        "subject_n_exclaim": subject.count("!"),
    }
    blob = subject + "\n" + body_text
    for name, rx in LEXICON_RE.items():
        out[name] = len(rx.findall(blob))
    out["kw_total"] = sum(out[k] for k in LEXICON_RE)
    return out


def featurise(rec: dict) -> dict:
    urls = extract_urls(rec["body_text"], rec["body_html"])
    f = {}
    f.update(url_features(urls))
    f.update(html_features(rec["body_html"]))
    f.update(text_features(rec["subject"], rec["body_text"]))
    return f


# ------------------------------------------------------------- text views
def view_full(rec: dict) -> str:
    """Everything the file contained. This is the view that leaks."""
    return rec["headers_full"] + "\n\n" + rec["body_text"]


def view_headers_scrubbed(rec: dict) -> str:
    """Headers minus the fields listed in config.COLLECTION_ARTIFACT_HEADERS,
    plus the body. Tests whether removing the obvious collection artifacts is
    enough (it is not)."""
    return rec["headers_scrubbed"] + "\n\n" + rec["body_text"]


def view_content(rec: dict) -> str:
    """Subject line and body only.

    Subject is kept even though it is technically a header: it is content the
    recipient reads and it is written by the attacker, not by whoever archived
    the mailbox. No routing, no client, no timestamps, no X-* fields."""
    return "SUBJECT: " + rec["subject"] + "\n\n" + rec["body_text"]


# --------------------------------------------------------- hardened content
# Added after the first run. The content-only view still scored 0.998 AUC, and
# inspecting its coefficients showed why: the body text carries its own
# collection fingerprints. Each substitution below targets one of them.

# 620 of the 4,150 ham messages are RSS-feed digests whose body literally
# begins "URL: http://...\nDate: 2002-10-08T...". Zero phishing messages do.
# That two-line prefix alone identifies 15% of the negative class.
RSS_PREFIX_RE = re.compile(r"(?im)^[ \t]*URL:[ \t]*\S+[ \t]*$\n^[ \t]*Date:[ \t]*\S+[ \t]*$\n?")

# Mailing-list plumbing. 35% of ham bodies name their own list; 0.2% of phish
# do. These lines say "this message came from the SpamAssassin corpus", not
# "this message is safe".
LIST_LINE_RE = re.compile(
    r"(?im)^.*\b(?:listinfo|majordomo|mailing list|to unsubscribe|"
    r"unsubscribe:|list-help|list-unsubscribe|yahoo!? ?groups|"
    r"you are subscribed|manage your subscription)\b.*$\n?"
)

EMAIL_RE = re.compile(r"[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63})+")
DATEISH_RE = re.compile(r"\b(?:19|20)\d\d(?:-\d\d-\d\d)?(?:t\d\d:\d\d:\d\d)?\b", re.IGNORECASE)
DIGITS_RE = re.compile(r"\d+")
ARTIFACT_TERMS_RE = re.compile(
    r"(?i)(?:" + "|".join(re.escape(t) for t in CORPUS_ARTIFACT_TERMS) + r")"
)


def harden(text: str) -> str:
    """Strip the collection fingerprints out of body text.

    The substitutions, and the reason for each:
      RSS prefix / list lines -- present on one corpus and not the other, and
        nothing to do with whether a message is an attack.
      URL strings -> placeholder -- stops TF-IDF memorising specific hosts
        (lists.sourceforge.net on one side, a payload domain on the other).
        The *structure* of every URL is still available: that is what the 65
        engineered features measure.
      Email addresses -> placeholder -- the phishing corpus was anonymised to
        username@domain.com and user@example.com; the ham has real list
        addresses. Either way the literal address is a corpus tell.
      Years and dates -> placeholder -- ham bodies say 2002, phishing bodies
        say 2005-2007. That is a fact about when each archive was collected.
      Digit runs -> placeholder -- account numbers, prices and message counts
        are memorisable and the useful part (how many digits, where) is
        already in the engineered features.
    """
    t = RSS_PREFIX_RE.sub(" ", text)
    t = LIST_LINE_RE.sub(" ", t)
    t = ARTIFACT_TERMS_RE.sub(" ", t)
    t = NORM_URL.sub(" urltoken ", t)
    t = EMAIL_RE.sub(" emailtoken ", t)
    t = DATEISH_RE.sub(" datetoken ", t)
    t = DIGITS_RE.sub(" numtoken ", t)
    return NORM_WS.sub(" ", t).strip()


def view_content_hardened(rec: dict) -> str:
    """Subject + body, with the body-level collection fingerprints removed.

    This is the view the headline number comes from."""
    return harden("SUBJECT: " + rec["subject"] + "\n\n" + rec["body_text"])


VIEWS = {
    "full": view_full,
    "headers_scrubbed": view_headers_scrubbed,
    "content": view_content,
    "content_hardened": view_content_hardened,
}

NORM_WS = re.compile(r"\s+")
NORM_URL = re.compile(r"(?i)(?:https?://|www\.)\S+")
NORM_NUM = re.compile(r"\d+")
NORM_PUNCT = re.compile(r"[^a-z0-9 ]+")


def normalised_body(rec: dict) -> str:
    """Body reduced to its skeleton for near-duplicate detection.

    URLs and numbers become placeholders because a phishing campaign rotates
    exactly those between sends while the prose stays identical. Two messages
    that differ only in the victim's account number must land in the same
    group."""
    t = rec["body_text"].lower()
    t = NORM_URL.sub(" url ", t)
    t = NORM_NUM.sub(" 0 ", t)
    t = NORM_PUNCT.sub(" ", t)
    return NORM_WS.sub(" ", t).strip()
