# Adversarial review of PR #3: OpenMed-inspired PII/PHI toolkit

Reviewed commit `1512a5df143d477402ee4aa1626d2887117fa89a` on `claude/openmed-tools-integration-1xmm5i` ([PR #3](https://github.com/grysukuza/anonymize/pull/3)).
Scope is `anonymize_data/openmed_tools.py`, `anonymize_data/core.py`, `presidio_service/app.py`, the Dockerfile, `.replit`, and the tests.
Every probe input is synthetic. No real patient data was read or used.

## Summary

The toolkit masks common direct identifiers (SSN, phone, fax, email, URL, IP) reliably.
It does not meet HIPAA Safe Harbor, and two of its four methods leak or are reversible with their defaults.

| # | Severity | Finding |
|---|----------|---------|
| 1 | Critical | `shift_dates` returns any `DATE_TIME` span it cannot parse verbatim, which leaks ZIP codes, ages over 89, most date formats, and (depending on hash seed) SSNs |
| 2 | High | `date_shift_days` defaults to 0 in the library and the API, so `shift_dates` leaves every date unchanged |
| 3 | High | `hash` uses a fixed public salt and a 32-bit truncated SHA-256, so tokens reverse by enumeration |
| 4 | High | `replace` uses a fixed public seed, so synthetic values reverse by dictionary lookup |
| 5 | High | 7 of the 18 Safe Harbor categories are missing and 6 are partial; `mask` leaked 13 of 37 synthetic probes |
| 6 | High | Default credentials `admin` / `anonymize123`, pre-filled in the login form, with no login rate limit and public binding in `.replit` |
| 7 | Medium | The random per-process session secret breaks login under the shipped `gunicorn -w 2` command |
| 8 | High | `BatchProcessor` returns a bare string unredacted, discards all completed results when one document fails, and its memory bound claim is false |
| 9 | Medium | Unvalidated `lang`, unbounded `date_shift_days`, and no request size limit produce HTML 500s |
| 10 | Low | Container runs as root, cookies lack `Secure`, raw PHI responses lack `Cache-Control: no-store` |

Some checks came back clean, all measured. The 22 existing tests pass. Neither the package nor the service logs raw input text. The 500 error bodies and `BatchProcessor` exception messages contain no input text. Flask debug mode is off.

## How this was verified

- `pytest tests/` returned `22 passed in 2.49s` (presidio-analyzer 2.2.364, spaCy 3.8.16, `en_core_web_lg`, Faker 40.43.0, Python 3.12).
- The probe in the appendix runs every finding below against the real Presidio engine. Rerun it with `python probe.py` from any directory once the dependencies are installed.
- Finding 7 was reproduced against a live `gunicorn -w 2` process with `curl`.
- A second reviewer on a different model read the same files independently, without running Presidio. It agreed on findings 1 to 6, 8, and 10. Its extra points (the pre-filled credentials, the bare-string batch input, and the re-identification code rule) were checked by execution or against the rule text and added.
- The probe ran twice. The two runs differed in one row, which finding 1 explains and which was then pinned with `PYTHONHASHSEED` 1 to 6.

## Findings

### 1. Critical. `shift_dates` passes unparseable date spans through unchanged

`deidentify(method="shift_dates")` masks every non-date entity. For `DATE_TIME` entities it calls `_shift_date_string` (`openmed_tools.py:180-187`), which tries five `strptime` formats and returns the raw string when none match. spaCy labels many non-date identifiers as `DATE_TIME`, so they fall through unredacted.

Measured with `date_shift_days=30`:

| Input (synthetic) | `mask` output | `shift_dates` output |
|---|---|---|
| `SSN 219-09-9931 verified.` (`PYTHONHASHSEED=1`) | `SSN [DATE_TIME] verified.` | `SSN 219-09-9931 verified.` |
| `Mailing ZIP 60614-3302 on file.` | `Mailing ZIP [DATE_TIME] on file.` | `Mailing ZIP 60614-3302 on file.` |
| `A 93-year-old woman presented.` | `A [DATE_TIME] woman presented.` | `A 93-year-old woman presented.` |
| `Patient aged 97 reports fatigue.` | `Patient aged [DATE_TIME] reports fatigue.` | `Patient aged 97 reports fatigue.` |
| `DOB 14.03.1957 per chart.` | `DOB [DATE_TIME] per chart.` | `DOB 14.03.1957 per chart.` |
| `Discharged on 3 March 2021.` | `Discharged on [DATE_TIME].` | `Discharged on 3 March 2021.` |

The SSN row is nondeterministic. Presidio returns both `US_SSN` and `DATE_TIME` for `219-09-9931`, with the same span and the same 0.85 score. `_resolve_overlaps` (`openmed_tools.py:120`) breaks ties only on score and length, so the winner is whichever result Presidio lists first, and that order follows Python's string hash seed. With `PYTHONHASHSEED` 1, 4, and 5 the SSN leaked under `shift_dates`. With 2, 3, and 6 it was masked as `[US_SSN]` (measured). Hash randomization is on by default, so every gunicorn worker and every restart picks its own winner.

Across the 37-probe corpus, `shift_dates` leaked 19 or 20 identifiers, depending on that SSN row. `mask` leaked 13 in both runs.
Under Safe Harbor (45 CFR 164.514(b)(2)(i)(C)), date shifting does not count as removal, so this method cannot be a Safe Harbor method even when it works. That is my reading of the rule, not legal advice.

Fix. Mask any `DATE_TIME` span that fails to parse. Break overlap ties with a fixed label priority that ranks pattern recognizers such as `US_SSN` above spaCy's `DATE_TIME`. Document `shift_dates` as an Expert Determination technique, not Safe Harbor.

### 2. High. `date_shift_days` defaults to 0

`deidentify` defaults `date_shift_days=0` (`openmed_tools.py:232`). The API passes `_parse_int(None)`, which returns 0 (`app.py:213`). Both paths return dates unchanged. `POST /pii/deidentify {"method": "shift_dates", "text": "Admitted 03/14/2021"}` returned `Admitted 03/14/2021` (measured).
The API also truncates floats silently, so `2.9` shifts by 2 days.

Fix. Require a nonzero shift, or derive a per-patient random shift from a server-side secret as `core._shift_dates` already does.

### 3. High. `hash` tokens reverse by enumeration

`_hash_token` (`openmed_tools.py:175-177`) computes unkeyed `sha256(f"{salt}:{label}:{value}")` with the default salt `"openmed"` and keeps 8 hex characters (32 bits). The API exposes no salt parameter, so every deployment shares the published salt.
The probe recovered `219-09-9999` from `[US_SSN_de8ee015]` after about 10^5 candidate hashes in 0.1 s of single-threaded CPython (measured). At that rate the full 10^9 SSN space takes about 17 minutes on one core (inferred). It also recovered a name from a candidate list.
The docstring calls the token "irreversible" (`openmed_tools.py:248`). It is not, for any low-entropy identifier.

Stable tokens derived from the identifier also conflict with the re-identification code rule (45 CFR 164.514(c)), which says such a code must not be derived from information about the individual. That is my reading of the rule, not legal advice.

Fix. Use HMAC-SHA-256 with a per-deployment secret key loaded from the environment, keep at least 128 bits, and remove the default salt.

### 4. High. `replace` values reverse by dictionary lookup

`_fake_value` seeds Faker with `sha256(f"{seed}:{original}")` and the default seed is `"default"` (`openmed_tools.py:199`, `:234`). The API cannot set the seed. Anyone with the source can map candidate names to their synthetic output and invert it. The probe recovered `Patient Zelda Quintrell` from the output `Martha Jones` (measured).

Fix. Derive the seed from a secret key (HMAC), not a constant.

### 5. High. Safe Harbor coverage gaps

The analyzer is stock Presidio plus two custom regex recognizers (`core.py:34-55`). Results for `method="mask"`, measured with the probe:

| Safe Harbor category | Status | Evidence |
|---|---|---|
| A. Names | Partial | `Zelda Quintrell` alone is not detected; names with sentence context are |
| B. Geography below state | Partial | City `Fairbourne` and street name `Willowmere Lane` leak. ZIP is masked only because spaCy mislabels it `DATE_TIME`; there is no ZIP recognizer |
| C. Dates and ages over 89 | Partial | Dates masked. `Age: 93.` leaks; other ages are caught only through the `DATE_TIME` mislabel |
| D. Phone | Covered | `PHONE_NUMBER` |
| E. Fax | Covered | `PHONE_NUMBER` |
| F. Email | Covered | `EMAIL_ADDRESS` |
| G. SSN | Covered | `US_SSN`, with and without dashes |
| H. Medical record numbers | Partial | Regex needs an `MRN` prefix and 6 to 12 characters; `MRN 48213` leaks. `MR# 00482133` is caught only as `US_BANK_NUMBER` |
| I. Health plan beneficiary numbers | Missing | Member ID and Medicare MBI leak |
| J. Account numbers | Partial | `US_BANK_NUMBER`, which depends on context words |
| K. Certificate and license numbers | Partial | `US_DRIVER_LICENSE` and `MEDICAL_LICENSE` caught the probes; there is no generic certificate pattern |
| L. Vehicle identifiers and plates | Missing | VIN and plate leak |
| M. Device identifiers and serials | Missing | Pacemaker serial leaks |
| N. URLs | Covered | `URL` |
| O. IP addresses | Covered | `IP_ADDRESS` |
| P. Biometric identifiers | Missing | Fingerprint template ID leaks |
| Q. Full-face photographs | Not applicable | Text-only toolkit |
| R. Other unique codes | Missing | `SUBJ-00917` leaks |

Facility names leak unless they match one of the five hard-coded names in `HospitalRecognizer` (`core.py:39`). `Lakeshore Mercy Hospital` leaked.
`core.py:1` and `:143` describe the pipeline as "HIPAA-oriented" and "aligned with HIPAA safe-harbor goals". `/anonymize` uses the same analyzer, so it has the same gaps.

Fix. Add pattern recognizers for ZIP, age over 89, health plan and member IDs, MBI, VIN, plate, device serial, and labelled generic IDs. Widen the MRN pattern. Treat these as a recall floor with a regression corpus, and remove the Safe Harbor wording until the corpus passes.

### 6. High. Default credentials and public exposure

`VALID_USERS` falls back to `admin` / `anonymize123` when the environment variables are unset (`app.py:31-35`). The login form pre-fills both values (`templates/index.html:279-280`), so anyone who loads the page sees working credentials. The tests log in with these values. Thirty consecutive bad passwords all returned 401 with no lockout or delay (measured).
The `.replit` workflow runs `python app.py`, which binds `0.0.0.0:5000` (`app.py:228`), and maps port 5000 to external port 80. The `.replit` deployment and the Dockerfile also bind `0.0.0.0`.
[PR #4](https://github.com/grysukuza/anonymize/pull/4) ("Require explicit anonymizer auth secrets") targets this. I did not check whether it rebases cleanly onto PR #3.

Fix. Fail at startup when credentials or `SESSION_SECRET` are unset. Bind `127.0.0.1` in the dev entry point. Add login rate limiting.

### 7. Medium. Sessions break under multi-worker gunicorn

`app.secret_key` falls back to `secrets.token_hex(32)` at import (`app.py:27`). Gunicorn without `--preload` imports the app once per worker, so each worker signs cookies with a different key. With one valid login cookie against `gunicorn -w 2`, `/session` returned authenticated on 6 of 20 requests and unauthenticated on 14 (measured).
The Dockerfile, the `.replit` deployment, and the README all use `-w 2`. Operators are likely to fix the flapping by hard-coding a secret.
Flask cookie sessions are also not revoked by `/logout`. A copied cookie stays valid until the key rotates.

Fix. Require `SESSION_SECRET` (see finding 6). Set `PERMANENT_SESSION_LIFETIME` and mark sessions permanent so cookies expire.

### 8. High. `BatchProcessor` input and error handling

`process_texts` (`openmed_tools.py:328-338`) builds one list and has no input validation or per-document error handling.

- A bare string is a valid `Iterable[str]`, so `process_texts("Contact Zelda Quintrell today.")` processes 30 one-character documents. No entity is detected, and joining the output returns the original text unredacted (measured). This misuse fails silently, with no error raised.
- A single `None` in a 4-document batch raised `ValueError: [E1041] Expected a string...` and discarded the completed results (measured).
- A document over spaCy's 1,000,000-character limit raises `ValueError` the same way (measured).
- An invalid `method` passes `__init__` and fails only on the first document (measured).
- With `operation="extract_pii"`, `method` and all `deidentify_kwargs` are ignored without a warning (measured). `model_name` is stored and never used.
- The docstring says chunking "bounds peak memory". Input is consumed lazily, but every output is accumulated in one list (`results.extend`), so peak memory still grows with the corpus.
- Exception messages did not contain document text (measured). Callers that log `repr(doc)` on failure would still leak it.

Fix. Reject a `str` passed as the collection and non-`str` items. Return a per-document result or error record (index, ok, value or error type), validate `method` in `__init__`, reject kwargs that the chosen operation ignores, and offer a generator variant that yields results.

### 9. Medium. API input validation

- `lang` is passed straight to Presidio. `"xx"` and `["en"]` both returned an HTML 500 (measured).
- `date_shift_days` has no bound. `10**12` raised `OverflowError` in `timedelta` and returned 500 (measured).
- `MAX_CONTENT_LENGTH` is unset. Large bodies are parsed in full, and text over 1,000,000 characters fails in spaCy with a 500.
- `/pii/extract` returns the raw PHI spans in the response by design. Proxies and browser caches can keep them.

Fix. Allow-list `lang`, bound `date_shift_days` (for example to 3650), set `MAX_CONTENT_LENGTH`, add a JSON error handler, and send `Cache-Control: no-store` on every `/pii/*` and `/anonymize` response.

### 10. Low. Hardening

- The Dockerfile has no `USER` directive, so gunicorn runs as root.
- `SESSION_COOKIE_SECURE` is unset, so the cookie travels over plain HTTP.
- `/login` runs `hmac.compare_digest` only when the username exists (`app.py:103-104`), so response timing can reveal valid usernames.
- There is no CSRF token. `SameSite=Lax` blocks cross-site POSTs in current browsers, so the risk is low.
- `_resolve_overlaps` drops lower-score overlapping spans. The only partial leak in the probe corpus was one `-` character, which is negligible.
- `adjust_numbers` adds a constant to every remaining number. It is reversible and is not a de-identification step.

### Test gaps

The tests check one happy-path sample per method. They do not cover the Safe Harbor categories, `shift_dates` with unparseable or mislabelled dates, the default `date_shift_days`, hash reversibility, `BatchProcessor` failures, or API 500 paths. The tests that log in with the default password will need updating when finding 6 is fixed.

## Appendix. Probe script

Requires `presidio-analyzer`, `presidio-anonymizer`, `faker`, `flask`, and `en_core_web_lg`. Set the `REPO` environment variable to the checkout path.

<details>
<summary><code>probe.py</code></summary>

```python
"""Adversarial probe for PR #3. All identifiers below are synthetic."""
import hashlib
import io
import json
import logging
import os
import sys
from pathlib import Path

REPO = Path(os.environ.get("REPO", "."))
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "presidio_service"))

from anonymize_data import BatchProcessor, deidentify, extract_pii  # noqa: E402
from anonymize_data.core import get_analyzer  # noqa: E402
from anonymize_data.openmed_tools import _hash_token, _fake_value, _get_faker  # noqa: E402

SAFE_HARBOR = [
    ("A names", "Seen today: Zelda Quintrell-Abernathy, age 44.", "Quintrell-Abernathy"),
    ("A names (lowercase)", "pt name: marcus oyelaran, follow up.", "oyelaran"),
    ("A name without context", "Zelda Quintrell", "Quintrell"),
    ("B street address", "Lives at 4821 Willowmere Lane, Apt 7.", "Willowmere Lane"),
    ("B city", "Transferred from Fairbourne, Ohio last week.", "Fairbourne"),
    ("B ZIP code", "Mailing ZIP 60614-3302 on file.", "60614"),
    ("B county", "Resident of Hallstead County.", "Hallstead"),
    ("C admission date (slash)", "Admitted 03/14/2021 for observation.", "03/14/2021"),
    ("C birth date (dotted)", "DOB 14.03.1957 per chart.", "14.03.1957"),
    ("C date (day month year)", "Discharged on 3 March 2021.", "3 March 2021"),
    ("C date (month day, no year)", "Surgery scheduled March 14th.", "March 14th"),
    ("C age over 89", "A 93-year-old woman presented with dyspnea.", "93-year-old"),
    ("C age over 89 (aged)", "Patient aged 97 reports fatigue.", "aged 97"),
    ("C age over 89 (Age:)", "Age: 93. Chief complaint cough.", "93"),
    ("G SSN (DATE_TIME-labelled)", "SSN 219-09-9931 verified.", "219-09-9931"),
    ("D phone", "Call (312) 555-0187 after 5pm.", "555-0187"),
    ("E fax", "Fax: 312-555-0199", "555-0199"),
    ("F email", "Reach her at z.quintrell@example.org", "z.quintrell@example.org"),
    ("G SSN", "SSN 219-09-9999 verified.", "219-09-9999"),
    ("G SSN no dashes", "SSN 219099999 verified.", "219099999"),
    ("H MRN (prefixed, 8)", "MRN: 48213377 assigned.", "48213377"),
    ("H MRN (short)", "MRN 48213 assigned.", "48213"),
    ("H MRN (MR# form)", "MR# 00482133 on wristband.", "00482133"),
    ("H MRN (lowercase)", "mrn 48213377 assigned.", "48213377"),
    ("I health plan ID", "Member ID: XQH448812093 (BlueRiver Health).", "XQH448812093"),
    ("I Medicare MBI", "Medicare MBI 1EG4-TE5-MK73 on file.", "1EG4-TE5-MK73"),
    ("J account number", "Billing account #77120934551.", "77120934551"),
    ("K license number", "Driver license D1234-56789-01234 (IL).", "D1234-56789-01234"),
    ("K DEA/cert number", "Prescriber DEA AB1234563.", "AB1234563"),
    ("L VIN", "Vehicle VIN 1HGCM82633A004352 involved.", "1HGCM82633A004352"),
    ("L license plate", "Plate number IL 7KXR221.", "7KXR221"),
    ("M device serial", "Pacemaker serial PMX-8832-1190-Q implanted.", "PMX-8832-1190-Q"),
    ("N URL", "Portal: https://patients.example.org/u/zquintrell", "patients.example.org/u/zquintrell"),
    ("O IP address", "Login from 203.0.113.77 flagged.", "203.0.113.77"),
    ("P biometric ref", "Fingerprint template ID FP-99812-AX stored.", "FP-99812-AX"),
    ("R other unique code", "Study subject code SUBJ-00917.", "SUBJ-00917"),
    ("Facility (not in list)", "Treated at Lakeshore Mercy Hospital.", "Lakeshore Mercy"),
]


def section(title):
    print(f"\n## {title}")


def leak(out, needle):
    return needle in out


def safe_harbor():
    section("Safe Harbor coverage: mask | shift_dates(days=30)")
    mask_leaks = shift_leaks = 0
    for cat, text, needle in SAFE_HARBOR:
        masked = deidentify(text, method="mask")
        shifted = deidentify(text, method="shift_dates", date_shift_days=30)
        labels = [e.label for e in extract_pii(text)]
        m, s = leak(masked, needle), leak(shifted, needle)
        mask_leaks += m
        shift_leaks += s
        print(f"{'LEAK' if m else 'ok':4} | {'LEAK' if s else 'ok':4} | {cat:28} | {labels} | {masked}")
    print(f"mask leaked {mask_leaks}/{len(SAFE_HARBOR)}; shift_dates leaked {shift_leaks}/{len(SAFE_HARBOR)}")


def shift_dates():
    section("shift_dates")
    text = "Admitted 03/14/2021, discharged 3 March 2021, DOB 14.03.1957, seen March 14th."
    print("default days :", deidentify(text, method="shift_dates"))
    print("days=30      :", deidentify(text, method="shift_dates", date_shift_days=30))


def hash_reversal():
    section("hash reversal with default salt")
    import time
    ssn = "219-09-9999"
    out = deidentify(f"SSN {ssn} verified.", method="hash")
    print("hash output:", out)
    token = out.split("SSN ")[1].split(" verified")[0]
    label = token[1:].rsplit("_", 1)[0]
    t0 = time.perf_counter()
    found = next((f"219-{n // 10000:02d}-{n % 10000:04d}" for n in range(10**6)
                  if _hash_token(f"219-{n // 10000:02d}-{n % 10000:04d}", label, "openmed") == token), None)
    dt = time.perf_counter() - t0
    print(f"recovered {found} by scanning area 219 (10^6 candidates) in {dt:.1f}s single-threaded CPython")
    print("token bits:", (len(token) - len(label) - 3) * 4)

    text = "Patient Zelda Quintrell was seen."
    span = extract_pii(text)[0].text
    tok = deidentify(text, method="hash")
    for nm in ["Ada Lovelace", f"Patient Zelda Quintrell", "Marcus Oyelaran"]:
        if _hash_token(nm, "PERSON", "openmed") in tok:
            print(f"name recovered by dictionary: {nm!r} (span={span!r})")


def replace_reversal():
    section("replace reversal with default seed")
    out = deidentify("Patient Zelda Quintrell was seen.", method="replace")
    print("replace output:", out)
    faker = _get_faker()
    for nm in ["Patient Ada Lovelace", "Patient Zelda Quintrell", "Patient Marcus Oyelaran"]:
        fake = _fake_value("PERSON", nm, faker, seed=f"default:{nm}")
        if fake in out:
            print(f"name recovered by dictionary: {nm} -> {fake}")


def overlap_leaks():
    section("partial leaks from _resolve_overlaps (raw spans not fully covered)")
    corpus = [t for _, t, _ in SAFE_HARBOR] + [
        "Contact Dr. Zelda Quintrell at zq@example.org or 312-555-0187 on 03/14/2021.",
        "Patient John Smith, born on 01/02/1980, resides at 123 Main St. MRN123459.",
        "Seen 2021-03-14 08:30 by Dr. Abernathy; callback 312.555.0187.",
        "SSN 219-09-9999 and account 77120934551 and https://ex.example.org/zq",
    ]
    analyzer = get_analyzer()
    count = 0
    for text in corpus:
        raw = analyzer.analyze(text=text, language="en")
        kept = extract_pii(text)
        covered = set()
        for e in kept:
            covered.update(range(e.start, e.end))
        for r in raw:
            missing = [i for i in range(r.start, r.end) if i not in covered]
            if missing and r.score >= 0.4:
                count += 1
                print(f"{r.entity_type} {text[r.start:r.end]!r} score={r.score:.2f} "
                      f"uncovered={text[min(missing):max(missing)+1]!r}")
    print("partial leaks (raw score >= 0.4):", count)


def batch():
    section("BatchProcessor error handling")
    docs = ["Patient Zelda Quintrell.", "Email z@example.org", None, "SSN 219-09-9999"]
    bp = BatchProcessor(operation="deidentify", method="mask", batch_size=2)
    try:
        print(bp.process_texts(docs))
    except Exception as exc:
        print(f"None mid-batch -> {type(exc).__name__}: {str(exc)[:160]!r}; earlier results lost")

    try:
        BatchProcessor(operation="deidentify", method="nope").process_texts(["x"])
    except Exception as exc:
        print(f"bad method surfaces only at processing time -> {type(exc).__name__}")

    try:
        BatchProcessor(operation="deidentify", lang="en", **{"method_": 1}).process_texts(["x"])
    except Exception as exc:
        print(f"unknown kwarg -> {type(exc).__name__}: {exc}")

    big = "Zelda Quintrell " * 70000
    try:
        BatchProcessor(operation="deidentify").process_texts(["ok", big])
    except Exception as exc:
        msg = str(exc)
        print(f"oversized doc -> {type(exc).__name__}; message contains raw text: {'Quintrell' in msg}")

    ex = BatchProcessor(operation="extract_pii", method="hash", hash_salt="s")
    print("extract_pii silently ignores method/kwargs:", ex.process_texts(["Contact Zelda Quintrell today."])[0][0].label)

    gen = (f"Patient Zelda Quintrell number {i}." for i in range(200))
    out = BatchProcessor(operation="deidentify", batch_size=4).process_texts(gen)
    print("results returned as list of", len(out), "(all outputs held in memory)")


def api():
    section("Flask API")
    from app import app
    import app as appmod
    print("VALID_USERS default keys:", list(appmod.VALID_USERS))
    print("SESSION_COOKIE_SECURE:", app.config.get("SESSION_COOKIE_SECURE"))
    print("MAX_CONTENT_LENGTH:", app.config.get("MAX_CONTENT_LENGTH"))

    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    logging.getLogger().addHandler(handler)
    app.logger.addHandler(handler)
    app.config["TESTING"] = False
    app.config["PROPAGATE_EXCEPTIONS"] = False
    c = app.test_client()
    statuses = [c.post("/login", json={"username": "admin", "password": f"x{i}"}).status_code for i in range(30)]
    print("30 bad logins statuses:", set(statuses), "-> no lockout/rate limit")
    print("default creds login:", c.post("/login", json={"username": "admin", "password": "anonymize123"}).status_code)

    phi = "Patient Zelda Quintrell SSN 219-09-9999"
    r = c.post("/pii/deidentify", json={"text": phi, "lang": "xx"})
    print("unsupported lang ->", r.status_code, "| JSON:", r.is_json, "| body echoes PHI:", "Quintrell" in r.get_data(as_text=True))
    r = c.post("/pii/extract", json={"text": phi, "lang": ["en"]})
    print("non-string lang ->", r.status_code)
    r = c.post("/pii/deidentify", json={"text": "Admitted 03/14/2021, Zelda Quintrell", "method": "shift_dates", "date_shift_days": 10**12})
    print("huge date_shift_days ->", r.status_code)
    r = c.post("/pii/deidentify", json={"text": "Admitted 03/14/2021", "method": "shift_dates"})
    print("shift_dates via API with no days ->", r.get_json())
    r = c.post("/pii/deidentify", json={"text": "Admitted 03/14/2021", "method": "shift_dates", "date_shift_days": 2.9})
    print("float days silently truncated ->", r.get_json())
    r = c.post("/pii/extract", json={"text": phi})
    print("/pii/extract echoes raw PHI in response:", "219-09-9999" in r.get_data(as_text=True))
    logged = buf.getvalue()
    print("log captured chars:", len(logged), "| raw PHI in logs:", "Quintrell" in logged or "219-09-9999" in logged)


if __name__ == "__main__":
    for fn in (safe_harbor, shift_dates, hash_reversal, replace_reversal, overlap_leaks, batch, api):
        try:
            fn()
        except Exception as exc:
            print(f"PROBE ERROR in {fn.__name__}: {type(exc).__name__}: {exc}")
```

</details>
