"""OpenMed-inspired PII tooling built on the Presidio backend.

This module ports the clean, method-oriented de-identification API of
`maziyarpanahi/openmed` (https://github.com/maziyarpanahi/openmed) onto this
project's lightweight Presidio backend. OpenMed itself ships 1,000+ Hugging Face
/ MLX clinical models; here we keep the same ergonomic surface — structured PII
extraction with smart merging, a single ``deidentify`` entry point with four
strategies (mask / replace / hash / shift_dates), and a ``BatchProcessor`` for
high-throughput document processing — without the heavy ML dependencies.

Public API
----------
- ``PiiEntity``        : structured detection result (label, text, span, score).
- ``extract_pii``      : detect PII and return merged ``PiiEntity`` objects.
- ``deidentify``       : remove/replace PII via mask | replace | hash | shift_dates.
- ``BatchProcessor``   : run extract/deidentify over many documents.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
import hashlib
import hmac
from itertools import islice
import os
import secrets
import threading
from typing import Iterable, Iterator, Sequence

from .core import get_analyzer

try:  # Faker powers locale-aware, format-preserving synthetic replacement.
    from faker import Faker

    _FAKER_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    Faker = None  # type: ignore[assignment]
    _FAKER_AVAILABLE = False


# OpenMed exposes friendly de-identification method names; we keep the same set.
DEIDENTIFY_METHODS: tuple[str, ...] = ("mask", "replace", "hash", "shift_dates")

# Date formats we know how to parse for the ``shift_dates`` strategy.
_DATE_FORMATS: tuple[str, ...] = (
    "%m/%d/%Y", "%m/%d/%y", "%Y-%m-%d", "%d-%m-%Y",
    "%B %d, %Y", "%b %d, %Y", "%d %B %Y", "%d %b %Y",
)

# Presidio entity types that represent dates (used by ``shift_dates``).
_DATE_LABELS: frozenset[str] = frozenset({"DATE_TIME", "DATE"})


@dataclass(frozen=True)
class PiiEntity:
    """A single detected PII span.

    Mirrors the entity shape returned by OpenMed (``label``, ``text``,
    ``start``, ``end``, ``score``) so downstream code can be model-agnostic.
    """

    label: str
    text: str
    start: int
    end: int
    score: float

    def to_dict(self) -> dict:
        return asdict(self)


# Faker instances are moderately expensive to construct, so each thread keeps
# one. Not shared across threads: _fake_value reseeds then draws, and another
# thread reseeding in between would break per-value determinism.
_FAKER_LOCAL = threading.local()


def _get_faker():
    if not _FAKER_AVAILABLE:
        return None
    faker = getattr(_FAKER_LOCAL, "faker", None)
    if faker is None:
        faker = _FAKER_LOCAL.faker = Faker()
    return faker


# Secret key for hash tokens. A public salt would let anyone hash candidate
# SSNs or birth dates and match released tokens, so the key comes from the
# deployment; without one, a random per-process key keeps tokens unguessable
# (but they then only stay stable for the life of the process).
_HASH_KEY = (os.environ.get("ANONYMIZE_HASH_KEY") or secrets.token_hex(32)).encode("utf-8")


def _smart_merge(entities: list[PiiEntity], text: str) -> list[PiiEntity]:
    """Merge fragmented/overlapping spans of the same label.

    Transformer tokenizers (and Presidio's per-token recognizers) frequently
    split a single logical entity — e.g. a full name — into adjacent fragments.
    OpenMed calls reassembling them "smart merging"; we merge same-label spans
    that overlap or are separated only by whitespace, keeping the max score.
    """
    if not entities:
        return []

    ordered = sorted(entities, key=lambda e: (e.start, e.end))
    merged: list[PiiEntity] = [ordered[0]]

    for current in ordered[1:]:
        last = merged[-1]
        gap = text[last.end : current.start]
        overlapping = current.start <= last.end
        # Two dates separated only by whitespace (a column of visit dates) are
        # separate values; joining them would make them unshiftable.
        whitespace_gap = gap.strip() == "" and current.label not in _DATE_LABELS
        if current.label == last.label and (overlapping or whitespace_gap):
            new_end = max(last.end, current.end)
            merged[-1] = PiiEntity(
                label=last.label,
                text=text[last.start : new_end],
                start=last.start,
                end=new_end,
                score=max(last.score, current.score),
            )
        else:
            merged.append(current)

    return merged


def _resolve_overlaps(entities: list[PiiEntity], text: str) -> list[PiiEntity]:
    """Collapse overlapping spans into one entity covering their union.

    Presidio recognizers routinely emit overlapping detections of *different*
    labels (e.g. a low-confidence ``URL`` over a high-confidence ``EMAIL``).
    Span-replacement requires disjoint regions, but dropping a losing span
    would leak whatever part of it the winner doesn't cover, so each cluster of
    overlapping spans becomes a single span over all of them, labelled by its
    most trustworthy member (highest score, tie-break: longest span).
    """
    resolved: list[PiiEntity] = []
    cluster: list[PiiEntity] = []

    def flush() -> None:
        if not cluster:
            return
        best = max(cluster, key=lambda e: (e.score, e.end - e.start))
        start = min(e.start for e in cluster)
        end = max(e.end for e in cluster)
        resolved.append(PiiEntity(best.label, text[start:end], start, end, best.score))
        cluster.clear()

    for ent in sorted(entities, key=lambda e: (e.start, e.end)):
        if cluster and ent.start >= max(e.end for e in cluster):
            flush()
        cluster.append(ent)
    flush()
    return resolved


def extract_pii(
    text: str,
    *,
    lang: str = "en",
    use_smart_merging: bool = True,
    entities: Sequence[str] | None = None,
    score_threshold: float = 0.0,
) -> list[PiiEntity]:
    """Detect PII in ``text`` and return structured :class:`PiiEntity` objects.

    Port of OpenMed's ``extract_pii``. ``model_name`` is intentionally omitted
    because detection is delegated to Presidio rather than a named ML model.

    Parameters
    ----------
    text:
        Document to scan.
    lang:
        Language code passed to Presidio (default ``"en"``).
    use_smart_merging:
        Reassemble fragmented same-label spans (default ``True``).
    entities:
        Optional whitelist of entity labels to keep.
    score_threshold:
        Drop detections below this confidence.
    """
    results = get_analyzer().analyze(text=text, language=lang)

    found = [
        PiiEntity(
            label=r.entity_type,
            text=text[r.start : r.end],
            start=r.start,
            end=r.end,
            score=float(r.score),
        )
        for r in results
        if r.score >= score_threshold
        and (entities is None or r.entity_type in entities)
    ]

    if use_smart_merging:
        found = _resolve_overlaps(found, text)
        found = _smart_merge(found, text)

    return sorted(found, key=lambda e: e.start)


def _hash_token(value: str, label: str, key: bytes, length: int = 32) -> str:
    # 32 hex chars = 128 bits; 32 bits collided on real SSNs at batch scale.
    digest = hmac.new(key, f"{label}:{value}".encode("utf-8"), hashlib.sha256).hexdigest()
    return f"[{label}_{digest[:length]}]"


def _parse_date(raw: str) -> tuple[datetime, str] | None:
    """Parse ``raw`` with a known format, returning the date and that format."""
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(raw.strip(), fmt), fmt
        except ValueError:
            continue
    return None


def _shift_date_string(raw: str, shift_days: int) -> str | None:
    """Shift a date by ``shift_days``, or return None when it can't be shifted."""
    parsed = _parse_date(raw)
    if parsed is None:
        return None
    date, fmt = parsed
    try:
        shifted = date + timedelta(days=shift_days)
    except OverflowError:
        return None
    return raw.replace(raw.strip(), shifted.strftime(fmt))


def _preserve_digit_layout(original: str, generated: str) -> str:
    """Pour ``generated``'s digits into ``original``'s layout of separators."""
    digits = iter(c for c in generated if c.isdigit())
    return "".join(next(digits, "0") if c.isdigit() else c for c in original)


def _fake_value(label: str, original: str, faker, seed: str) -> str:
    """Produce deterministic, locale-aware synthetic data for a label.

    Seeding per-original-value keeps replacements consistent within and across
    documents (the same name always maps to the same synthetic name).
    """
    if faker is None:
        return f"[{label}]"

    faker.seed_instance(int(hashlib.sha256(seed.encode("utf-8")).hexdigest(), 16) % (2**32))

    upper = label.upper()
    if upper in {"PERSON", "NAME"}:
        return faker.name()
    if upper in {"EMAIL_ADDRESS", "EMAIL"}:
        return faker.email()
    if upper in {"PHONE_NUMBER", "PHONE"}:
        return faker.phone_number()
    if upper in {"LOCATION", "ADDRESS", "GPE"}:
        return faker.city()
    if upper in {"US_SOCIAL_SECURITY_NUMBER", "US_SSN", "SSN"}:
        return faker.ssn()
    if upper == "CREDIT_CARD":
        return _preserve_digit_layout(original, faker.credit_card_number())
    if upper in {"DATE_TIME", "DATE"}:
        parsed = _parse_date(original)
        return faker.date(pattern=parsed[1] if parsed else "%m/%d/%Y")
    if upper == "URL":
        return faker.url()
    if upper == "IP_ADDRESS":
        return faker.ipv6() if ":" in original else faker.ipv4()
    if upper in {"MEDICAL_RECORD_NUMBER", "MRN"}:
        return f"MRN{faker.numerify('######')}"
    if upper in {"HOSPITAL", "ORGANIZATION", "ORG"}:
        return f"{faker.last_name()} Medical Center"
    return faker.word()


def deidentify(
    text: str,
    *,
    method: str = "mask",
    lang: str = "en",
    date_shift_days: int = 0,
    hash_key: bytes | str | None = None,
    seed: str = "default",
    entities: Sequence[str] | None = None,
) -> str:
    """De-identify ``text`` using one of OpenMed's four strategies.

    Methods
    -------
    ``mask``
        Replace each span with a ``[LABEL]`` placeholder.
    ``replace``
        Substitute realistic, format-preserving synthetic data (Faker-backed;
        falls back to ``[LABEL]`` when Faker is not installed).
    ``hash``
        Replace with a keyed one-way token ``[LABEL_<hmac>]`` (HMAC-SHA256,
        128 bits) — irreversible but stable, so equal inputs collapse to equal
        tokens. The key is ``hash_key``, else ``ANONYMIZE_HASH_KEY``, else a
        random per-process key; set one of the first two for tokens that stay
        stable across runs.
    ``shift_dates``
        Offset detected dates by ``date_shift_days`` while masking other PII,
        preserving relative chronology for longitudinal analysis. With no
        offset (``0``) dates are masked, since an unshifted date isn't
        de-identified.
    """
    if method not in DEIDENTIFY_METHODS:
        raise ValueError(
            f"Unknown method {method!r}; expected one of {', '.join(DEIDENTIFY_METHODS)}"
        )

    detected = extract_pii(text, lang=lang, entities=entities)
    if not detected:
        return text

    faker = _get_faker() if method == "replace" else None
    if isinstance(hash_key, str):
        hash_key = hash_key.encode("utf-8")
    key = hash_key or _HASH_KEY

    # Rebuild the string right-to-left so earlier offsets stay valid.
    out = text
    for ent in sorted(detected, key=lambda e: e.start, reverse=True):
        original = text[ent.start : ent.end]

        if method == "mask":
            replacement = f"[{ent.label}]"
        elif method == "hash":
            replacement = _hash_token(original, ent.label, key)
        elif method == "replace":
            replacement = _fake_value(ent.label, original, faker, seed=f"{seed}:{original}")
        else:  # shift_dates
            shifted = (
                _shift_date_string(original, date_shift_days)
                if ent.label in _DATE_LABELS and date_shift_days
                else None
            )
            # A date we can't parse or shift must still not leak, so mask it.
            replacement = shifted if shifted is not None else f"[{ent.label}]"

        out = out[: ent.start] + replacement + out[ent.end :]

    return out


class BatchProcessor:
    """Run a PII operation over many documents.

    Port of OpenMed's ``BatchProcessor``. ``model_name`` is accepted for API
    compatibility but unused (detection is delegated to Presidio).

    Parameters
    ----------
    operation:
        ``"extract_pii"`` (default) or ``"deidentify"``.
    method:
        De-identification strategy used when ``operation == "deidentify"``.
    batch_size:
        Documents pulled from the input per chunk. Use :meth:`iter_texts` to
        stream results; :meth:`process_texts` collects them all into a list.
    lang:
        Language code forwarded to the underlying calls.
    """

    def __init__(
        self,
        *,
        operation: str = "extract_pii",
        method: str = "mask",
        model_name: str | None = None,
        batch_size: int = 16,
        lang: str = "en",
        **deidentify_kwargs,
    ) -> None:
        if operation not in {"extract_pii", "deidentify", "analyze"}:
            raise ValueError(f"Unsupported operation {operation!r}")
        self.operation = "extract_pii" if operation == "analyze" else operation
        self.method = method
        self.model_name = model_name
        self.batch_size = max(1, int(batch_size))
        self.lang = lang
        self.deidentify_kwargs = deidentify_kwargs

    def _process_one(self, text: str):
        if self.operation == "deidentify":
            return deidentify(text, method=self.method, lang=self.lang, **self.deidentify_kwargs)
        return extract_pii(text, lang=self.lang)

    def iter_texts(self, texts: Iterable[str]) -> Iterator:
        """Yield per-document results in input order as they are produced.

        Input is pulled lazily in ``batch_size`` chunks and nothing is retained
        after it is yielded, so memory stays bounded for any corpus size.
        """
        iterator = iter(texts)
        while chunk := list(islice(iterator, self.batch_size)):
            for text in chunk:
                yield self._process_one(text)

    def process_texts(self, texts: Iterable[str]) -> list:
        """Process ``texts`` and return all per-document results as a list."""
        return list(self.iter_texts(texts))
