"""Input validation with explicit, stated rules.

Two things this file is careful about:

  1. Validation is not the SQL-injection defence. Parameterised queries are.
     Rejecting quotes at the edge is the wrong mental model -- it says the data
     layer is unsafe and we are filtering on its behalf, which fails the moment
     one code path forgets to filter. The username charset below is narrow for
     other reasons (impersonation, log injection, display), and the app would
     still be injection-proof with the charset wide open. There is a test for
     that: tests/test_sqli.py fires payloads at BOTH the username and password
     fields, and the password field accepts any printable character.

  2. Unicode normalisation happens before anything else. Without it "admin" can
     be spelled several ways that compare unequal as byte strings but look
     identical to a human, so an attacker registers a lookalike. NFKC folds
     compatibility variants together. NIST SP 800-63B section 5.1.1.2 requires
     NFKC or NFC normalisation for memorised secrets too, otherwise a password
     typed on a different keyboard/IME stops matching.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

from .config import Config

# Lowercase letters, digits, and the three separators. No uppercase, so
# "Admin" and "admin" cannot both exist. No spaces, so a username cannot be
# padded to look like another one.
USERNAME_RE = re.compile(r"^[a-z0-9._-]+$")

# Reserved names. Not a security control on its own, but "admin" and "root"
# being unavailable to the public removes the easiest impersonation.
RESERVED_USERNAMES = frozenset({
    "admin", "administrator", "root", "system", "support", "security",
    "moderator", "operator", "postmaster", "webmaster", "test", "null",
    "undefined", "me", "you", "sls",
})


@dataclass
class ValidationResult:
    ok: bool
    value: str = ""
    errors: list[str] = field(default_factory=list)


def normalise_username(raw: str) -> str:
    return unicodedata.normalize("NFKC", raw or "").strip().lower()


def normalise_password(raw: str) -> str:
    # NFKC on the password too, per SP 800-63B. Note that we do NOT strip: a
    # leading or trailing space is a legitimate character in a passphrase and
    # silently removing it makes a password the user cannot reproduce elsewhere.
    return unicodedata.normalize("NFKC", raw or "")


def validate_username(raw: str, config: Config) -> ValidationResult:
    value = normalise_username(raw)
    errors: list[str] = []

    if not value:
        errors.append("Username is required.")
    else:
        if len(value) < config.username_min_length:
            errors.append(
                f"Username must be at least {config.username_min_length} characters.")
        if len(value) > config.username_max_length:
            errors.append(
                f"Username must be at most {config.username_max_length} characters.")
        if not USERNAME_RE.match(value):
            errors.append("Username may contain only lowercase letters, digits, "
                          "dot, underscore and hyphen.")
        if value[0] in "._-" or value[-1] in "._-":
            # Leading/trailing separators make near-duplicates easy to hide.
            errors.append("Username must start and end with a letter or digit.")
        if ".." in value or "__" in value or "--" in value:
            errors.append("Username must not contain repeated separators.")
        if value in RESERVED_USERNAMES:
            errors.append("That username is reserved.")

    return ValidationResult(not errors, value, errors)


def validate_password(raw: str, config: Config) -> ValidationResult:
    value = normalise_password(raw)
    errors: list[str] = []

    if not value:
        errors.append("Password is required.")
    else:
        # Length in characters, not bytes: telling a user with an emoji
        # passphrase that their 12 characters are only 11 is nonsense.
        if len(value) < config.password_min_length:
            errors.append(
                f"Password must be at least {config.password_min_length} characters.")
        if len(value) > config.password_max_length:
            errors.append(
                f"Password must be at most {config.password_max_length} characters.")
        if "\x00" in value:
            # A NUL would be a truncation hazard on any C string boundary.
            errors.append("Password must not contain null bytes.")
        if any(unicodedata.category(ch) == "Cc" for ch in value):
            errors.append("Password must not contain control characters.")

    return ValidationResult(not errors, value, errors)


def validate_totp_code(raw: str, config: Config) -> ValidationResult:
    value = (raw or "").strip().replace(" ", "").replace("-", "")
    errors: list[str] = []
    if not value:
        errors.append("Authentication code is required.")
    elif not value.isdigit() or len(value) != config.totp_digits:
        errors.append(f"Authentication code must be {config.totp_digits} digits.")
    return ValidationResult(not errors, value, errors)
