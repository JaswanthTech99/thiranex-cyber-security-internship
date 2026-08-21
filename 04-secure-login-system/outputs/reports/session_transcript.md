# Live session transcript

Produced by `python tests/test_e2e.py`. Every exchange below is a real HTTP request against a freshly started instance of the app with a throwaway SQLite database. Session identifiers, CSRF tokens, TOTP secrets and passwords are redacted; status lines, headers and everything else are verbatim.

Generated: 2026-08-21 18:26:00 local time.
Server started with default security settings, except the session cookie's Secure flag, which is cleared because this harness speaks plain HTTP over loopback and a Secure cookie is not sent to an http:// origin. Everything else is production default.



Effective configuration:

```json

{
  "argon2": {
    "bounded_peak_transient_mib": 256.0,
    "hash_bytes": 32,
    "max_concurrent": 4,
    "memory_cost_kib": 65536,
    "memory_cost_mib": 64.0,
    "parallelism_p": 4,
    "queue_timeout_s": 5.0,
    "salt_bytes": 16,
    "source": "RFC 9106 section 4, second recommended option",
    "time_cost_t": 3,
    "type": "Argon2id"
  },
  "demo_vulnerable_endpoint_mounted": false,
  "enum_mitigation": true,
  "policy": {
    "breach_check": true,
    "composition_rules": false,
    "password_max_length": 128,
    "password_min_length": 12
  },
  "rate_limit": {
    "enabled": true,
    "ip_threshold": 30,
    "ip_window_s": 300,
    "lockout_duration_s": 900,
    "lockout_threshold": 5,
    "lockout_window_s": 900
  },
  "secret_key_source": "generated at runtime (secrets.token_bytes)",
  "session": {
    "absolute_timeout_s": 28800,
    "cookie_httponly": true,
    "cookie_samesite": "Lax",
    "cookie_secure": false,
    "id_bits": 256,
    "idle_timeout_s": 1800
  },
  "totp": {
    "acceptance_window_s": 90,
    "algorithm": "sha1",
    "digits": 6,
    "skew_steps": 1,
    "step_s": 30
  }
}

```


## Registration


### Step 1: POST /register

```http
POST /register
form: {"username": "jaswanth.demo", "password": "<redacted>", "confirm": "<redacted>", "csrf_token": "<redacted>"}

HTTP/1.1 201 CREATED
Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'
Cache-Control: no-store, no-cache, must-revalidate
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer

{
  "breach": {
    "available": true,
    "breached": false,
    "candidates_returned": 1908,
    "count": 0,
    "error": null,
    "prefix": "52D5E"
  },
  "created": true,
  "user_id": 1,
  "username": "jaswanth.demo"
}
```

### Step 2: POST /register

```http
POST /register
form: {"username": "breach.probe", "password": "<redacted>", "confirm": "<redacted>", "csrf_token": "<redacted>"}

HTTP/1.1 400 BAD REQUEST
Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'
Cache-Control: no-store, no-cache, must-revalidate
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer

{
  "breach": {
    "available": true,
    "breached": true,
    "candidates_returned": 1950,
    "count": 295389,
    "error": null,
    "prefix": "49EFE"
  },
  "created": false,
  "errors": [
    "This password appears 295,389 times in known breach corpora. Choose a different one."
  ]
}
```

## Login, password only (no second factor yet)


### Step 3: POST /login

```http
POST /login
form: {"username": "jaswanth.demo", "password": "<redacted>", "csrf_token": "<redacted>"}

HTTP/1.1 200 OK
Set-Cookie: sls_sid=<redacted-256-bit-value>; HttpOnly; Path=/; SameSite=Lax
Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'
Cache-Control: no-store, no-cache, must-revalidate
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer

{
  "authenticated": true,
  "csrf_token": "<redacted>",
  "totp_required": false,
  "username": "jaswanth.demo"
}
```

Session id rotated on login: pre-login and post-login identifiers differ (yes).


## Protected page


### Step 4: GET /dashboard

```http
GET /dashboard

HTTP/1.1 200 OK
Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'
Cache-Control: no-store, no-cache, must-revalidate
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer

{
  "absolute_timeout_s": 28800,
  "idle_timeout_s": 1800,
  "session_age_s": 0.013,
  "session_idle_s": 0.002,
  "totp_enabled": false,
  "username": "jaswanth.demo"
}
```

## TOTP enrolment


### Step 5: GET /2fa/enrol

```http
GET /2fa/enrol

HTTP/1.1 200 OK
Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'
Cache-Control: no-store, no-cache, must-revalidate
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer

{
  "csrf_token": "<redacted>",
  "otpauth_uri": "<redacted>",
  "secret_b32": "<redacted>"
}
```

The base32 secret and otpauth:// URI are redacted above. The secret is 160 bits, the length RFC 4226 section 4 recommends.


### Step 6: POST /2fa/enrol

```http
POST /2fa/enrol
form: {"code": "<current 6-digit code>", "csrf_token": "<redacted>"}

HTTP/1.1 200 OK
Set-Cookie: sls_sid=<redacted-256-bit-value>; HttpOnly; Path=/; SameSite=Lax
Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'
Cache-Control: no-store, no-cache, must-revalidate
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer

{
  "csrf_token": "<redacted>",
  "enabled": true
}
```

## Logout and a fresh login through the second factor


### Step 7: POST /logout

```http
POST /logout
form: {"csrf_token": "<redacted>"}

HTTP/1.1 200 OK
Set-Cookie: sls_sid=<redacted-256-bit-value>; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/
Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'
Cache-Control: no-store, no-cache, must-revalidate
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer

{
  "logged_out": true
}
```

### Step 8: POST /login

```http
POST /login
form: {"username": "jaswanth.demo", "password": "<redacted>", "csrf_token": "<redacted>"}

HTTP/1.1 200 OK
Set-Cookie: sls_sid=<redacted-256-bit-value>; HttpOnly; Path=/; SameSite=Lax
Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'
Cache-Control: no-store, no-cache, must-revalidate
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer

{
  "authenticated": false,
  "csrf_token": "<redacted>",
  "totp_required": true
}
```

### Step 9: GET /dashboard

```http
GET /dashboard

HTTP/1.1 401 UNAUTHORIZED
Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'
Cache-Control: no-store, no-cache, must-revalidate
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer

{
  "error": "authentication required"
}
```

Waited 27.1s for the TOTP counter to advance past the one consumed during enrolment. The replay guard refuses a spent counter, so a code from the enrolment step would be rejected here -- correctly.


### Step 10: POST /login/2fa

```http
POST /login/2fa
form: {"code": "<current 6-digit code>", "csrf_token": "<redacted>"}

HTTP/1.1 200 OK
Set-Cookie: sls_sid=<redacted-256-bit-value>; HttpOnly; Path=/; SameSite=Lax
Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'
Cache-Control: no-store, no-cache, must-revalidate
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer

{
  "authenticated": true,
  "csrf_token": "<redacted>",
  "username": "jaswanth.demo"
}
```

### Step 11: POST /login/2fa

```http
POST /login/2fa
form: {"code": "<the code just used>", "csrf_token": "<redacted>"}

HTTP/1.1 401 UNAUTHORIZED
Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'
Cache-Control: no-store, no-cache, must-revalidate
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer

{
  "authenticated": false,
  "error": "Invalid authentication code."
}
```

### Step 12: GET /dashboard

```http
GET /dashboard

HTTP/1.1 200 OK
Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'
Cache-Control: no-store, no-cache, must-revalidate
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer

{
  "absolute_timeout_s": 28800,
  "idle_timeout_s": 1800,
  "session_age_s": 0.181,
  "session_idle_s": 0.004,
  "totp_enabled": true,
  "username": "jaswanth.demo"
}
```

## Logout invalidates the session server-side


### Step 13: POST /logout

```http
POST /logout
form: {"csrf_token": "<redacted>"}

HTTP/1.1 200 OK
Set-Cookie: sls_sid=<redacted-256-bit-value>; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/
Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'
Cache-Control: no-store, no-cache, must-revalidate
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer

{
  "logged_out": true
}
```

### Step 14: GET /dashboard

```http
GET /dashboard

HTTP/1.1 401 UNAUTHORIZED
Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'
Cache-Control: no-store, no-cache, must-revalidate
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer

{
  "error": "authentication required"
}
```

The request above deliberately re-presents the pre-logout session cookie. It is refused because logout deleted the server-side row, not merely asked the browser to forget it.


## Session table sweep


### Step 15: POST /admin/maintenance

```http
POST /admin/maintenance

HTTP/1.1 200 OK
Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'
Cache-Control: no-store, no-cache, must-revalidate
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer

{
  "purged_sessions": 0,
  "stats": {
    "attempts": 5,
    "sessions": 2,
    "users": 1
  }
}
```

Captured 15 HTTP exchanges at 2026-08-21 18:26:00 local time.

