"""gluck-forms — a generic forms service.

One Flask process, one DuckDB, two Caddy sites, routed by Host header. Each
site reaches the process through its own unix socket, handed over by systemd
and reachable only by Caddy, so the Host it sees is the one that chose the
site:

- ``forms.<base>``  — admin API + response reading. Gated by Authelia
  forward-auth or ``Authorization: Bearer <jwt>`` (validated against
  Authelia's JWKS). Requires the ``forms-admin`` group.
- ``f.<base>``      — public form-filler. No auth. The token in the URL
  (``f.<base>/<token>``) is the capability; we compare
  ``sha256(token) == form_token.token_hash`` in constant time.

Blobs are content-addressed under ``/var/lib/gluck-forms/blobs/<sha[:2]>/<sha>``.
Answers are stored as a single JSON column per response; for file and
signature fields the JSON holds ``{blob_id, filename, mime, size}`` and the
bytes live on disk.

IDs use ``SELECT COALESCE(MAX(id),0)+1`` — DuckDB sequences bit us in
gluck-calendar and we don't repeat mistakes. Writes are serialized by a
threading.Lock; DuckDB is single-writer anyway.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

import duckdb
import jwt
import markdown as md
import requests
from flask import (
    Flask,
    Response,
    jsonify,
    render_template,
    request,
    send_file,
)
from jwt import PyJWKClient

# ── Config ────────────────────────────────────────────────────────────────
DB_PATH = os.environ.get("GLUCK_FORMS_DB", "/var/lib/gluck-forms/forms.duckdb")
# Two blob roots — content-addressed materials (admin uploads, dedup'd)
# and per-response directories (one dir per submission, no dedup).
MATERIALS_DIR = Path(
    os.environ.get(
        "GLUCK_FORMS_MATERIALS_DIR", "/var/lib/gluck-forms-blobs/materials"
    )
)
RESPONSES_DIR = Path(
    os.environ.get(
        "GLUCK_FORMS_RESPONSES_DIR", "/var/lib/gluck-forms-blobs/responses"
    )
)
MAX_MATERIAL_MB = int(os.environ.get("GLUCK_FORMS_MAX_MATERIAL_MB", "25"))
PORT = int(os.environ.get("PORT", "9095"))

OIDC_ISSUER = os.environ.get("GLUCK_FORMS_OIDC_ISSUER", "https://auth.kelliher.info")
OIDC_JWKS_URL = os.environ.get(
    "GLUCK_FORMS_OIDC_JWKS_URL", "http://127.0.0.1:9091/jwks.json"
)
OIDC_CLIENT_ID = os.environ.get("GLUCK_FORMS_OIDC_CLIENT_ID", "gforms-cli")
OIDC_USERINFO_URL = os.environ.get(
    "GLUCK_FORMS_OIDC_USERINFO_URL", "http://127.0.0.1:9091/api/oidc/userinfo"
)

ADMIN_GROUP = "forms-admin"
ADMIN_HOST = os.environ.get("GLUCK_FORMS_ADMIN_HOST", "forms.kelliher.info")
PUBLIC_HOST = os.environ.get("GLUCK_FORMS_PUBLIC_HOST", "f.kelliher.info")

MAX_UPLOAD_MB_DEFAULT = 25
FIELD_KINDS = {
    "short_text",
    "long_text",
    "radio",
    "checkbox",
    "multiselect",
    "signature",
    "date",
    "email",
    "phone",
    "file",
    "markdown",
}
ANSWERABLE_KINDS = FIELD_KINDS - {"markdown"}
BLOB_KINDS = {"file", "signature"}

# ── App / DB ──────────────────────────────────────────────────────────────
app = Flask(__name__, template_folder="templates")
app.config["MAX_CONTENT_LENGTH"] = 128 * 1024 * 1024  # 128 MiB hard cap
MATERIALS_DIR.mkdir(parents=True, exist_ok=True)
RESPONSES_DIR.mkdir(parents=True, exist_ok=True)


def human_size(n) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


app.jinja_env.globals["human_size"] = human_size

db_lock = threading.Lock()
db = duckdb.connect(DB_PATH)

_userinfo_cache: dict = {}
_userinfo_cache_lock = threading.Lock()
USERINFO_TTL = 60

_jwks_client = None
_jwks_lock = threading.Lock()


def jwks_client() -> PyJWKClient:
    global _jwks_client
    with _jwks_lock:
        if _jwks_client is None:
            _jwks_client = PyJWKClient(OIDC_JWKS_URL, cache_keys=True, lifespan=3600)
        return _jwks_client


def _decode_jwt_payload(compact: str) -> dict:
    import base64

    parts = compact.split(".")
    if len(parts) < 2:
        return {}
    pad = "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(parts[1] + pad))


def fetch_userinfo(access_token: str, sub: str) -> dict:
    now = time.time()
    with _userinfo_cache_lock:
        hit = _userinfo_cache.get(sub)
        if hit and hit[0] > now:
            return hit[1]
    r = requests.get(
        OIDC_USERINFO_URL,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=5,
    )
    if r.status_code != 200:
        raise RuntimeError(f"userinfo {r.status_code}: {r.text}")
    data = (
        r.json()
        if r.headers.get("content-type", "").startswith("application/json")
        else _decode_jwt_payload(r.text)
    )
    with _userinfo_cache_lock:
        _userinfo_cache[sub] = (now + USERINFO_TTL, data)
    return data


# ── Bearer bypass — copied verbatim from gluck-calendar ───────────────────
@app.before_request
def bearer_to_remote_headers():
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    token = auth.split(None, 1)[1].strip()
    try:
        signing_key = jwks_client().get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            issuer=OIDC_ISSUER,
            options={
                "require": ["exp", "iat", "iss", "sub", "client_id"],
                "verify_aud": False,
            },
        )
    except Exception as e:  # noqa: BLE001
        return jsonify(error=f"invalid bearer token: {e}"), 401

    if claims.get("client_id") != OIDC_CLIENT_ID:
        return jsonify(error="token not issued for this client"), 401

    userinfo = fetch_userinfo(token, claims["sub"])
    username = (
        userinfo.get("preferred_username")
        or userinfo.get("sub")
        or claims.get("sub")
        or ""
    )
    groups = userinfo.get("groups") or []
    if isinstance(groups, str):
        groups = [g.strip() for g in groups.split(",") if g.strip()]

    request.environ["HTTP_REMOTE_USER"] = username
    request.environ["HTTP_REMOTE_GROUPS"] = ",".join(groups)
    return None


SCHEMES = {"light", "dark"}


@app.context_processor
def reader_scheme():
    scheme = request.cookies.get("zanni-scheme")
    return {"scheme": scheme if scheme in SCHEMES else None}


# ── Security headers ──────────────────────────────────────────────────────
@app.after_request
def security_headers(resp: Response) -> Response:
    if resp.mimetype == "text/html":
        resp.vary.add("Cookie")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
        "frame-ancestors 'none'",
    )
    # Never cache anything on the public host — form contents shouldn't
    # linger in intermediary caches, and receipts are per-response.
    if _request_host() == PUBLIC_HOST:
        resp.headers["Cache-Control"] = "no-store"
    return resp


# ── Schema ────────────────────────────────────────────────────────────────
db.execute(
    """CREATE TABLE IF NOT EXISTS form (
        id BIGINT PRIMARY KEY,
        slug TEXT NOT NULL UNIQUE,
        title TEXT NOT NULL,
        description TEXT,
        version INT NOT NULL DEFAULT 1,
        frozen BOOLEAN NOT NULL DEFAULT FALSE,
        created_by TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )"""
)
db.execute(
    """CREATE TABLE IF NOT EXISTS form_field (
        id BIGINT PRIMARY KEY,
        form_id BIGINT NOT NULL,
        name TEXT NOT NULL,
        label TEXT NOT NULL,
        description TEXT,
        kind TEXT NOT NULL,
        required BOOLEAN NOT NULL DEFAULT TRUE,
        ord INT NOT NULL,
        config JSON,
        UNIQUE (form_id, name),
        UNIQUE (form_id, ord)
    )"""
)
db.execute(
    """CREATE TABLE IF NOT EXISTS form_token (
        id BIGINT PRIMARY KEY,
        form_id BIGINT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        hint TEXT,
        form_version_at_mint INT NOT NULL,
        max_uses INT,
        uses INT NOT NULL DEFAULT 0,
        created_by TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        expires_at TIMESTAMPTZ NOT NULL,
        revoked_at TIMESTAMPTZ
    )"""
)
db.execute(
    """CREATE TABLE IF NOT EXISTS form_response (
        id BIGINT PRIMARY KEY,
        form_id BIGINT NOT NULL,
        form_version INT NOT NULL,
        token_id BIGINT,
        answers JSON NOT NULL,
        submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        client_ip TEXT,
        user_agent TEXT
    )"""
)
db.execute(
    """CREATE TABLE IF NOT EXISTS form_blob (
        id BIGINT PRIMARY KEY,
        response_id BIGINT NOT NULL,
        field_name TEXT NOT NULL,
        filename TEXT,
        mime TEXT NOT NULL,
        size BIGINT NOT NULL,
        sha256 TEXT NOT NULL,
        -- Per-response path: <RESPONSES_DIR>/<response_id>/<field-name>.<ext>.
        -- sha256 is kept for integrity but no longer drives layout.
        storage_path TEXT NOT NULL
    )"""
)
db.execute(
    """CREATE TABLE IF NOT EXISTS form_material (
        id BIGINT PRIMARY KEY,
        form_id BIGINT NOT NULL,
        filename TEXT NOT NULL,
        label TEXT,
        mime TEXT NOT NULL,
        size BIGINT NOT NULL,
        sha256 TEXT NOT NULL,
        -- Content-addressed path: <MATERIALS_DIR>/<sha[:2]>/<sha>
        storage_path TEXT NOT NULL,
        ord INT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (form_id, sha256)
    )"""
)
db.execute(
    "CREATE INDEX IF NOT EXISTS form_material_sha_idx ON form_material (sha256)"
)
db.execute(
    "CREATE INDEX IF NOT EXISTS form_material_form_idx ON form_material (form_id, ord)"
)


# ── Small helpers ─────────────────────────────────────────────────────────
def _request_host() -> str:
    # Caddy passes the original Host via the Host header. Strip port.
    return (request.host or "").split(":", 1)[0].lower()


def caller() -> str:
    return request.headers.get("Remote-User", "").strip()


def caller_groups() -> list[str]:
    raw = request.headers.get("Remote-Groups", "")
    return [g.strip() for g in raw.split(",") if g.strip()]


def next_id(table: str) -> int:
    return db.execute(f"SELECT COALESCE(MAX(id), 0) + 1 FROM {table}").fetchone()[0]


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def form_by_slug(slug: str):
    return db.execute(
        """SELECT id, slug, title, description, version, frozen,
                  created_by, created_at, updated_at
           FROM form WHERE slug = ?""",
        [slug],
    ).fetchone()


def fields_for(form_id: int, ordered: bool = True):
    order = "ORDER BY ord" if ordered else ""
    rows = db.execute(
        f"""SELECT id, form_id, name, label, description, kind, required, ord, config
            FROM form_field WHERE form_id = ? {order}""",
        [form_id],
    ).fetchall()
    return [_field_dict(r) for r in rows]


def _field_dict(row) -> dict:
    cfg = row[8]
    if isinstance(cfg, str):
        try:
            cfg = json.loads(cfg)
        except Exception:  # noqa: BLE001
            cfg = None
    return {
        "id": row[0],
        "form_id": row[1],
        "name": row[2],
        "label": row[3],
        "description": row[4],
        "kind": row[5],
        "required": row[6],
        "ord": row[7],
        "config": cfg or {},
    }


def _form_dict(row, include_fields: bool = True) -> dict:
    out = {
        "id": row[0],
        "slug": row[1],
        "title": row[2],
        "description": row[3],
        "version": row[4],
        "frozen": row[5],
        "created_by": row[6],
        "created_at": row[7].isoformat() if row[7] else None,
        "updated_at": row[8].isoformat() if row[8] else None,
    }
    if include_fields:
        out["fields"] = fields_for(row[0])
    return out


# ── Field validation ──────────────────────────────────────────────────────
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^[+0-9()\-.\s]{5,32}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
FIELD_NAME_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


def _mime_matches(mime: str, patterns: list[str]) -> bool:
    for p in patterns:
        p = p.strip().lower()
        if not p:
            continue
        if p.endswith("/*") and mime.lower().startswith(p[:-1]):
            return True
        if p == mime.lower():
            return True
    return False


def validate_field(field: dict, raw_value):
    """Return (ok_value, error_msg). ok_value may be None for skipped fields."""
    kind = field["kind"]
    required = field["required"]
    cfg = field.get("config") or {}

    if kind == "markdown":
        return (None, None)  # display-only

    # Blob-typed fields are handled out-of-band by the submission handler;
    # here `raw_value` is the already-persisted blob dict, or None.
    if kind in BLOB_KINDS:
        if raw_value is None:
            if required:
                return (None, "required")
            return (None, None)
        return (raw_value, None)

    # Everything else is a plain string / list / bool from the form.
    if raw_value is None or (isinstance(raw_value, str) and raw_value.strip() == ""):
        if required:
            return (None, "required")
        return (None, None)

    if kind in ("short_text", "long_text"):
        s = str(raw_value)
        mn, mx = cfg.get("min_length"), cfg.get("max_length")
        if mn is not None and len(s) < int(mn):
            return (None, f"min length {mn}")
        if mx is not None and len(s) > int(mx):
            return (None, f"max length {mx}")
        pat = cfg.get("pattern")
        if pat:
            try:
                if not re.search(pat, s):
                    return (None, "does not match pattern")
            except re.error:
                return (None, "invalid pattern in field config")
        return (s, None)

    if kind == "email":
        s = str(raw_value).strip()
        if len(s) > int(cfg.get("max_length", 200)):
            return (None, "max length 200")
        if not EMAIL_RE.match(s):
            return (None, "invalid email")
        return (s, None)

    if kind == "phone":
        s = str(raw_value).strip()
        if not PHONE_RE.match(s):
            return (None, "invalid phone")
        return (s, None)

    if kind == "date":
        s = str(raw_value).strip()
        if not DATE_RE.match(s):
            return (None, "invalid date (YYYY-MM-DD)")
        try:
            d = datetime.strptime(s, "%Y-%m-%d").date()
        except ValueError:
            return (None, "invalid date")
        if cfg.get("min") and s < str(cfg["min"]):
            return (None, f"must be on or after {cfg['min']}")
        if cfg.get("max") and s > str(cfg["max"]):
            return (None, f"must be on or before {cfg['max']}")
        return (d.isoformat(), None)

    if kind == "radio":
        opts = [o.get("value") for o in cfg.get("options", [])]
        s = str(raw_value)
        if s not in opts:
            return (None, "not a valid option")
        return (s, None)

    if kind == "multiselect":
        opts = {o.get("value") for o in cfg.get("options", [])}
        if isinstance(raw_value, str):
            values = [v for v in raw_value.split(",") if v]
        elif isinstance(raw_value, list):
            values = [str(v) for v in raw_value]
        else:
            return (None, "expected list")
        bad = [v for v in values if v not in opts]
        if bad:
            return (None, f"invalid option(s): {', '.join(bad)}")
        return (values, None)

    if kind == "checkbox":
        if isinstance(raw_value, bool):
            v = raw_value
        else:
            v = str(raw_value).lower() in ("1", "true", "on", "yes")
        if cfg.get("must_check") and required and not v:
            return (None, "must be checked")
        return (v, None)

    return (None, f"unknown kind: {kind}")


def validate_field_spec(spec: dict, ord_seen: set, name_seen: set, default_ord: int):
    name = spec.get("name") or ""
    if not FIELD_NAME_RE.match(name):
        return f"field name '{name}': must be [a-z_][a-z0-9_]*"
    if name in name_seen:
        return f"duplicate field name: {name}"
    name_seen.add(name)
    kind = spec.get("kind")
    if kind not in FIELD_KINDS:
        return f"field '{name}': kind must be one of {sorted(FIELD_KINDS)}"
    # ord is optional — defaults to the field's position in the input
    # array. Explicit values still get their duplicate-check.
    if "ord" not in spec or spec.get("ord") is None:
        spec["ord"] = default_ord
    ord_ = spec["ord"]
    if not isinstance(ord_, int) or ord_ < 0:
        return f"field '{name}': ord must be a non-negative int"
    if ord_ in ord_seen:
        return f"duplicate ord {ord_}"
    ord_seen.add(ord_)
    if not spec.get("label"):
        return f"field '{name}': label required"
    cfg = spec.get("config") or {}
    if kind in ("radio", "multiselect"):
        opts = cfg.get("options")
        if not isinstance(opts, list) or not opts:
            return f"field '{name}': config.options required"
        for o in opts:
            if "value" not in o or "label" not in o:
                return f"field '{name}': each option needs value + label"
    if kind == "signature":
        mode = cfg.get("mode", "drawn")
        if mode not in ("drawn", "typed", "both"):
            return f"field '{name}': signature mode must be drawn|typed|both"
    if kind == "file":
        if "max_size_mb" not in cfg:
            cfg["max_size_mb"] = MAX_UPLOAD_MB_DEFAULT
    spec["config"] = cfg
    return None


# ── Blob storage ──────────────────────────────────────────────────────────
# MIME → extension for per-response filenames.
_MIME_EXT = {
    "application/pdf": "pdf",
    "image/svg+xml": "svg",
    "image/jpeg": "jpg",
    "image/jpg": "jpg",
    "image/png": "png",
    "image/gif": "gif",
    "image/webp": "webp",
    "application/json": "json",
    "text/plain": "txt",
    "text/markdown": "md",
    "text/csv": "csv",
    "text/html": "html",
    "application/zip": "zip",
}


def _ext_for_mime(mime: str) -> str:
    return _MIME_EXT.get((mime or "").lower(), "bin")


def _sanitize_field_name(name: str) -> str:
    # field names are already validated by FIELD_NAME_RE, but be defensive.
    return re.sub(r"[^a-zA-Z0-9_-]", "_", name)[:64] or "blob"


def store_material_bytes(data: bytes) -> tuple[str, str]:
    """Content-address ``data`` under MATERIALS_DIR. Returns (sha256, path)."""
    sha = hashlib.sha256(data).hexdigest()
    dest = MATERIALS_DIR / sha[:2] / sha
    if not dest.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(".tmp")
        tmp.write_bytes(data)
        tmp.rename(dest)
    return sha, str(dest)


def _response_dir(response_id: int) -> Path:
    d = RESPONSES_DIR / str(response_id)
    if not d.exists():
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
    return d


def store_response_bytes(
    response_id: int, field_name: str, mime: str, data: bytes
) -> tuple[str, str]:
    """Write ``data`` under ``responses/<response_id>/<field>.<ext>``. If
    that filename already exists (multi-file field), append ``-N``.
    Returns (sha256, absolute path)."""
    sha = hashlib.sha256(data).hexdigest()
    d = _response_dir(response_id)
    base = _sanitize_field_name(field_name)
    ext = _ext_for_mime(mime)
    candidate = d / f"{base}.{ext}"
    if candidate.exists():
        n = 1
        while True:
            candidate = d / f"{base}-{n}.{ext}"
            if not candidate.exists():
                break
            n += 1
    tmp = candidate.with_suffix(candidate.suffix + ".tmp")
    tmp.write_bytes(data)
    tmp.rename(candidate)
    return sha, str(candidate)


def record_blob(response_id: int, field_name: str, filename, mime: str, data: bytes):
    sha, path = store_response_bytes(response_id, field_name, mime, data)
    blob_id = next_id("form_blob")
    db.execute(
        """INSERT INTO form_blob (id, response_id, field_name, filename, mime,
                                   size, sha256, storage_path)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        [blob_id, response_id, field_name, filename, mime, len(data), sha, path],
    )
    return {
        "blob_id": blob_id,
        "filename": filename,
        "mime": mime,
        "size": len(data),
    }


# ── Host / auth guards ────────────────────────────────────────────────────
def require_admin():
    """403/401 if the current request isn't an authenticated admin.

    Also rejects requests reaching admin endpoints on the public host, so
    a badly-configured Caddy doesn't accidentally expose admin routes
    without auth.
    """
    if _request_host() == PUBLIC_HOST:
        return jsonify(error="admin API not served on this host"), 404
    user = caller()
    if not user:
        return jsonify(error="unauthenticated"), 401
    if ADMIN_GROUP not in caller_groups():
        return jsonify(error=f"requires group {ADMIN_GROUP}"), 403
    return None


# ── Rate limiting (public submissions) ────────────────────────────────────
_rate_lock = threading.Lock()
_rate_buckets: dict[str, deque] = defaultdict(deque)
RATE_LIMIT = 20  # attempts
RATE_WINDOW = 3600  # seconds


def rate_limited(ip: str) -> bool:
    now = time.time()
    cutoff = now - RATE_WINDOW
    with _rate_lock:
        dq = _rate_buckets[ip]
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= RATE_LIMIT:
            return True
        dq.append(now)
        return False


def client_ip() -> str:
    # Trust X-Forwarded-For only on the public host (upstream is
    # cloudflared → Caddy). Take the first hop.
    if _request_host() == PUBLIC_HOST:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",", 1)[0].strip()
    return request.remote_addr or ""


# ═════════════════════════════════════════════════════════════════════════
#  Admin API  (Host: forms.kelliher.info)
# ═════════════════════════════════════════════════════════════════════════
@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/whoami")
def whoami():
    if _request_host() == PUBLIC_HOST:
        return jsonify(error="not served on this host"), 404
    return jsonify(user=caller(), groups=caller_groups(), host=_request_host())


@app.post("/forms")
def create_form():
    denied = require_admin()
    if denied:
        return denied
    body = request.get_json(silent=True) or {}
    slug = str(body.get("slug", "")).strip().lower()
    if not SLUG_RE.match(slug):
        return jsonify(error="slug must match [a-z0-9][a-z0-9-]*"), 400
    title = str(body.get("title", "")).strip()
    if not title:
        return jsonify(error="title required"), 400
    fields = body.get("fields") or []
    if not isinstance(fields, list) or not fields:
        return jsonify(error="fields must be a non-empty list"), 400

    ord_seen: set = set()
    name_seen: set = set()
    for idx, f in enumerate(fields):
        err = validate_field_spec(f, ord_seen, name_seen, idx)
        if err:
            return jsonify(error=err), 400

    with db_lock:
        if form_by_slug(slug):
            return jsonify(error="slug already exists"), 409
        form_id = next_id("form")
        db.execute(
            """INSERT INTO form (id, slug, title, description, created_by)
               VALUES (?, ?, ?, ?, ?)""",
            [form_id, slug, title, body.get("description") or None, caller() or "?"],
        )
        for spec in fields:
            field_id = next_id("form_field")
            db.execute(
                """INSERT INTO form_field
                   (id, form_id, name, label, description, kind, required, ord, config)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    field_id,
                    form_id,
                    spec["name"],
                    spec["label"],
                    spec.get("description"),
                    spec["kind"],
                    bool(spec.get("required", True)),
                    int(spec["ord"]),
                    json.dumps(spec.get("config") or {}),
                ],
            )
        return jsonify(_form_dict(form_by_slug(slug))), 201


@app.get("/forms")
def list_forms():
    denied = require_admin()
    if denied:
        return denied
    with db_lock:
        rows = db.execute(
            """SELECT id, slug, title, description, version, frozen,
                      created_by, created_at, updated_at
               FROM form ORDER BY created_at DESC"""
        ).fetchall()
    return jsonify([_form_dict(r, include_fields=False) for r in rows])


@app.get("/forms/<slug>")
def get_form(slug):
    denied = require_admin()
    if denied:
        return denied
    with db_lock:
        row = form_by_slug(slug)
    if not row:
        return jsonify(error="not found"), 404
    return jsonify(_form_dict(row))


@app.put("/forms/<slug>")
def update_form(slug):
    denied = require_admin()
    if denied:
        return denied
    body = request.get_json(silent=True) or {}
    with db_lock:
        row = form_by_slug(slug)
        if not row:
            return jsonify(error="not found"), 404
        if row[5]:
            return jsonify(error="form is frozen; unfreeze not supported"), 409

        title = body.get("title", row[2])
        description = body.get("description", row[3])
        fields = body.get("fields")

        if fields is not None:
            if not isinstance(fields, list) or not fields:
                return jsonify(error="fields must be a non-empty list"), 400
            ord_seen: set = set()
            name_seen: set = set()
            for idx, f in enumerate(fields):
                err = validate_field_spec(f, ord_seen, name_seen, idx)
                if err:
                    return jsonify(error=err), 400
            db.execute("DELETE FROM form_field WHERE form_id = ?", [row[0]])
            for spec in fields:
                field_id = next_id("form_field")
                db.execute(
                    """INSERT INTO form_field
                       (id, form_id, name, label, description, kind, required, ord, config)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    [
                        field_id,
                        row[0],
                        spec["name"],
                        spec["label"],
                        spec.get("description"),
                        spec["kind"],
                        bool(spec.get("required", True)),
                        int(spec["ord"]),
                        json.dumps(spec.get("config") or {}),
                    ],
                )

        db.execute(
            """UPDATE form SET title = ?, description = ?, version = version + 1,
                                updated_at = now()
               WHERE id = ?""",
            [title, description, row[0]],
        )
        return jsonify(_form_dict(form_by_slug(slug)))


@app.post("/forms/<slug>/freeze")
def freeze_form(slug):
    denied = require_admin()
    if denied:
        return denied
    with db_lock:
        row = form_by_slug(slug)
        if not row:
            return jsonify(error="not found"), 404
        db.execute(
            "UPDATE form SET frozen = TRUE, updated_at = now() WHERE id = ?", [row[0]]
        )
        return jsonify(_form_dict(form_by_slug(slug)))


@app.post("/forms/<slug>/tokens")
def mint_token(slug):
    denied = require_admin()
    if denied:
        return denied
    body = request.get_json(silent=True) or {}
    try:
        days = int(body.get("expires_in_days", 30))
    except (TypeError, ValueError):
        return jsonify(error="expires_in_days must be int"), 400
    if days <= 0 or days > 365 * 5:
        return jsonify(error="expires_in_days out of range"), 400
    max_uses = body.get("max_uses")
    if max_uses is not None:
        try:
            max_uses = int(max_uses)
            if max_uses <= 0:
                raise ValueError
        except (TypeError, ValueError):
            return jsonify(error="max_uses must be a positive int or null"), 400

    with db_lock:
        row = form_by_slug(slug)
        if not row:
            return jsonify(error="not found"), 404

        raw = secrets.token_urlsafe(24)
        token_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        tid = next_id("form_token")
        expires = now_utc() + timedelta(days=days)
        db.execute(
            """INSERT INTO form_token
               (id, form_id, token_hash, hint, form_version_at_mint, max_uses,
                created_by, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                tid,
                row[0],
                token_hash,
                body.get("hint"),
                row[4],
                max_uses,
                caller() or "?",
                expires,
            ],
        )
        return (
            jsonify(
                id=tid,
                token=raw,  # returned exactly once
                hint=body.get("hint"),
                form_version_at_mint=row[4],
                max_uses=max_uses,
                expires_at=expires.isoformat(),
                url=f"https://{PUBLIC_HOST}/{raw}",
            ),
            201,
        )


@app.get("/forms/<slug>/tokens")
def list_tokens(slug):
    denied = require_admin()
    if denied:
        return denied
    with db_lock:
        row = form_by_slug(slug)
        if not row:
            return jsonify(error="not found"), 404
        toks = db.execute(
            """SELECT id, hint, form_version_at_mint, max_uses, uses,
                      created_by, created_at, expires_at, revoked_at
               FROM form_token WHERE form_id = ? ORDER BY created_at DESC""",
            [row[0]],
        ).fetchall()
    return jsonify(
        [
            {
                "id": t[0],
                "hint": t[1],
                "form_version_at_mint": t[2],
                "max_uses": t[3],
                "uses": t[4],
                "created_by": t[5],
                "created_at": t[6].isoformat() if t[6] else None,
                "expires_at": t[7].isoformat() if t[7] else None,
                "revoked_at": t[8].isoformat() if t[8] else None,
            }
            for t in toks
        ]
    )


@app.post("/tokens/<int:tid>/revoke")
def revoke_token(tid):
    denied = require_admin()
    if denied:
        return denied
    with db_lock:
        row = db.execute("SELECT id FROM form_token WHERE id = ?", [tid]).fetchone()
        if not row:
            return jsonify(error="not found"), 404
        db.execute(
            "UPDATE form_token SET revoked_at = now() WHERE id = ? AND revoked_at IS NULL",
            [tid],
        )
        return jsonify(id=tid, revoked=True)


@app.get("/forms/<slug>/responses")
def list_responses(slug):
    denied = require_admin()
    if denied:
        return denied
    with db_lock:
        row = form_by_slug(slug)
        if not row:
            return jsonify(error="not found"), 404
        rs = db.execute(
            """SELECT id, form_version, token_id, answers, submitted_at,
                      client_ip, user_agent
               FROM form_response WHERE form_id = ? ORDER BY submitted_at DESC""",
            [row[0]],
        ).fetchall()
    return jsonify(
        [
            {
                "id": r[0],
                "form_version": r[1],
                "token_id": r[2],
                "answers": json.loads(r[3]) if isinstance(r[3], str) else r[3],
                "submitted_at": r[4].isoformat() if r[4] else None,
                "client_ip": r[5],
                "user_agent": r[6],
            }
            for r in rs
        ]
    )


@app.get("/responses/<int:rid>")
def get_response(rid):
    denied = require_admin()
    if denied:
        return denied
    with db_lock:
        r = db.execute(
            """SELECT id, form_id, form_version, token_id, answers,
                      submitted_at, client_ip, user_agent
               FROM form_response WHERE id = ?""",
            [rid],
        ).fetchone()
    if not r:
        return jsonify(error="not found"), 404
    return jsonify(
        {
            "id": r[0],
            "form_id": r[1],
            "form_version": r[2],
            "token_id": r[3],
            "answers": json.loads(r[4]) if isinstance(r[4], str) else r[4],
            "submitted_at": r[5].isoformat() if r[5] else None,
            "client_ip": r[6],
            "user_agent": r[7],
        }
    )


def _blob_row(bid: int):
    return db.execute(
        """SELECT id, response_id, field_name, filename, mime, size, sha256, storage_path
           FROM form_blob WHERE id = ?""",
        [bid],
    ).fetchone()


def _serve_blob(bid: int, disposition: str):
    denied = require_admin()
    if denied:
        return denied
    with db_lock:
        row = _blob_row(bid)
    if not row:
        return jsonify(error="not found"), 404
    path = Path(row[7])
    if not path.exists():
        return jsonify(error="blob missing on disk"), 410
    resp = send_file(
        path,
        mimetype=row[4],
        as_attachment=(disposition == "attachment"),
        download_name=row[3] or f"blob-{bid}",
    )
    return resp


@app.get("/blobs/<int:bid>")
def blob_download(bid):
    return _serve_blob(bid, "attachment")


@app.get("/blobs/<int:bid>/preview")
def blob_preview(bid):
    return _serve_blob(bid, "inline")


# ── Materials (admin) ─────────────────────────────────────────────────────
def _material_row(mid: int):
    return db.execute(
        """SELECT id, form_id, filename, label, mime, size, sha256,
                  storage_path, ord, created_at
           FROM form_material WHERE id = ?""",
        [mid],
    ).fetchone()


def _material_dict(row, include_path: bool = False) -> dict:
    out = {
        "id": row[0],
        "form_id": row[1],
        "filename": row[2],
        "label": row[3] or row[2],
        "mime": row[4],
        "size": row[5],
        "sha256": row[6],
        "ord": row[8],
        "created_at": row[9].isoformat() if row[9] else None,
    }
    if include_path:
        out["storage_path"] = row[7]
    return out


def _sniff_mime(data: bytes, fallback: str) -> str:
    try:
        import magic  # python-magic

        sniffed = magic.from_buffer(data, mime=True)
        if sniffed:
            return sniffed
    except Exception:  # noqa: BLE001
        pass
    return fallback or "application/octet-stream"


@app.post("/forms/<slug>/materials")
def upload_material(slug):
    denied = require_admin()
    if denied:
        return denied
    fs = request.files.get("file")
    if not fs or not fs.filename:
        return jsonify(error="file required (multipart field 'file')"), 400
    data = fs.read()
    if len(data) > MAX_MATERIAL_MB * 1024 * 1024:
        return jsonify(error=f"exceeds max size {MAX_MATERIAL_MB} MiB"), 413
    filename = (fs.filename or "upload")[:200]
    label = (request.form.get("label") or "").strip() or None
    upload_mime = fs.mimetype or "application/octet-stream"
    mime = _sniff_mime(data, upload_mime)

    with db_lock:
        row = form_by_slug(slug)
        if not row:
            return jsonify(error="not found"), 404
        form_id = row[0]

        sha, path = store_material_bytes(data)

        # Dedup: same form + same sha → return existing row (200).
        existing = db.execute(
            """SELECT id, form_id, filename, label, mime, size, sha256,
                      storage_path, ord, created_at
               FROM form_material WHERE form_id = ? AND sha256 = ?""",
            [form_id, sha],
        ).fetchone()
        if existing:
            return jsonify(_material_dict(existing)), 200

        mid = next_id("form_material")
        next_ord = db.execute(
            "SELECT COALESCE(MAX(ord), -1) + 1 FROM form_material WHERE form_id = ?",
            [form_id],
        ).fetchone()[0]
        db.execute(
            """INSERT INTO form_material
               (id, form_id, filename, label, mime, size, sha256, storage_path, ord)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [mid, form_id, filename, label, mime, len(data), sha, path, int(next_ord)],
        )
        return jsonify(_material_dict(_material_row(mid))), 201


@app.get("/forms/<slug>/materials")
def list_materials(slug):
    denied = require_admin()
    if denied:
        return denied
    with db_lock:
        row = form_by_slug(slug)
        if not row:
            return jsonify(error="not found"), 404
        rows = db.execute(
            """SELECT id, form_id, filename, label, mime, size, sha256,
                      storage_path, ord, created_at
               FROM form_material WHERE form_id = ? ORDER BY ord""",
            [row[0]],
        ).fetchall()
    return jsonify([_material_dict(r) for r in rows])


@app.delete("/forms/<slug>/materials/<int:mid>")
def delete_material(slug, mid):
    denied = require_admin()
    if denied:
        return denied
    with db_lock:
        form = form_by_slug(slug)
        if not form:
            return jsonify(error="not found"), 404
        row = db.execute(
            "SELECT id, form_id FROM form_material WHERE id = ?", [mid]
        ).fetchone()
        if not row or row[1] != form[0]:
            return jsonify(error="not found"), 404
        db.execute("DELETE FROM form_material WHERE id = ?", [mid])
        # Note: we don't unlink the on-disk blob — it's content-addressed
        # and may be referenced by future re-uploads. Sweep offline if needed.
        return ("", 204)


def _serve_material(mid: int, disposition: str):
    with db_lock:
        row = _material_row(mid)
    if not row:
        return jsonify(error="not found"), 404
    path = Path(row[7])
    if not path.exists():
        return jsonify(error="material missing on disk"), 410
    return send_file(
        path,
        mimetype=row[4],
        as_attachment=(disposition == "attachment"),
        download_name=row[2] or f"material-{mid}",
    )


@app.get("/materials/<int:mid>")
def material_download(mid):
    denied = require_admin()
    if denied:
        return denied
    return _serve_material(mid, "attachment")


@app.get("/materials/<int:mid>/inline")
def material_inline(mid):
    denied = require_admin()
    if denied:
        return denied
    return _serve_material(mid, "inline")


# ═════════════════════════════════════════════════════════════════════════
#  Admin dashboard  (Host: forms.kelliher.info) — HTML pages
# ═════════════════════════════════════════════════════════════════════════
def _fmt_ts(ts) -> str | None:
    """Format a datetime for display in the admin UI (UTC, minute precision)."""
    if ts is None:
        return None
    if isinstance(ts, str):
        return ts
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


app.jinja_env.globals["fmt_ts"] = _fmt_ts


@app.get("/admin")
def admin_index():
    denied = require_admin()
    if denied:
        return denied
    with db_lock:
        rows = db.execute(
            """SELECT id, slug, title, description, version, frozen,
                      created_by, created_at, updated_at
               FROM form ORDER BY updated_at DESC"""
        ).fetchall()
        counts = dict(
            db.execute(
                "SELECT form_id, COUNT(*) FROM form_response GROUP BY form_id"
            ).fetchall()
        )
    forms = []
    for r in rows:
        d = _form_dict(r, include_fields=False)
        d["response_count"] = int(counts.get(r[0], 0))
        d["updated_at_display"] = _fmt_ts(r[8])
        forms.append(d)
    return render_template(
        "admin_index.html", forms=forms, caller_user=caller()
    )


def _token_status(row) -> str:
    # row: (id, hint, form_version_at_mint, max_uses, uses, created_by,
    #       created_at, expires_at, revoked_at)
    if row[8] is not None:
        return "revoked"
    exp = row[7]
    if exp is not None:
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp < now_utc():
            return "expired"
    if row[3] is not None and row[4] >= row[3]:
        return "used_up"
    return "active"


@app.get("/admin/<slug>")
def admin_form_page(slug):
    denied = require_admin()
    if denied:
        return denied
    with db_lock:
        row = form_by_slug(slug)
        if not row:
            return _public_error("Form not found.", 404)
        form_dict = _form_dict(row, include_fields=False)
        form_dict["updated_at_display"] = _fmt_ts(row[8])

        tok_rows = db.execute(
            """SELECT id, hint, form_version_at_mint, max_uses, uses,
                      created_by, created_at, expires_at, revoked_at
               FROM form_token WHERE form_id = ? ORDER BY created_at DESC""",
            [row[0]],
        ).fetchall()
        resp_rows = db.execute(
            """SELECT id, form_version, token_id, answers, submitted_at
               FROM form_response WHERE form_id = ?
               ORDER BY submitted_at DESC""",
            [row[0]],
        ).fetchall()
        materials = _materials_for(row[0])

    tokens = []
    any_active = False
    for t in tok_rows:
        status = _token_status(t)
        if status == "active":
            any_active = True
        tokens.append(
            {
                "id": t[0],
                "hint": t[1],
                "form_version_at_mint": t[2],
                "max_uses": t[3],
                "uses": t[4],
                "created_by": t[5],
                "created_at_display": _fmt_ts(t[6]),
                "expires_at_display": _fmt_ts(t[7]),
                "status": status,
            }
        )

    responses = []
    for r in resp_rows:
        answers = json.loads(r[3]) if isinstance(r[3], str) else (r[3] or {})
        blob_count = sum(
            1
            for v in answers.values()
            if isinstance(v, dict) and "blob_id" in v
        )
        field_count = len(answers) - blob_count
        name = (
            answers.get("legal_name")
            or answers.get("name")
            or answers.get("full_name")
            or "—"
        )
        if isinstance(name, dict):
            name = "—"
        email = answers.get("email") or "—"
        if isinstance(email, dict):
            email = "—"
        responses.append(
            {
                "id": r[0],
                "submitted_at_display": _fmt_ts(r[4]),
                "display_name": str(name),
                "display_email": str(email),
                "field_count": field_count,
                "blob_count": blob_count,
            }
        )

    # Public URL is only useful if there's a live token; we can't
    # reconstruct the raw token, so link to the public host root only when
    # at least one token is active so the operator knows a live link exists.
    public_url = None
    if any_active:
        # No specific URL — raw tokens aren't retrievable. Leave a link to
        # the public host as an affordance for testing.
        public_url = f"https://{PUBLIC_HOST}/"

    return render_template(
        "admin_form.html",
        form=form_dict,
        tokens=tokens,
        materials=materials,
        responses=responses,
        response_count=len(responses),
        public_url=public_url,
    )


@app.get("/admin/<slug>/responses/<int:rid>")
def admin_response_page(slug, rid):
    denied = require_admin()
    if denied:
        return denied
    with db_lock:
        form_row = form_by_slug(slug)
        if not form_row:
            return _public_error("Form not found.", 404)
        r = db.execute(
            """SELECT id, form_id, form_version, token_id, answers,
                      submitted_at, client_ip, user_agent
               FROM form_response WHERE id = ? AND form_id = ?""",
            [rid, form_row[0]],
        ).fetchone()
        if not r:
            return _public_error("Response not found.", 404)
        fields = fields_for(form_row[0])

    answers = json.loads(r[4]) if isinstance(r[4], str) else (r[4] or {})

    # Typed-mode signatures store a JSON blob on disk; we don't want to
    # ship a per-request disk read for each one in the template. Pre-load
    # the "typed" strings here so the template just displays them.
    typed_sig_texts: dict[str, str] = {}
    for f in fields:
        if f["kind"] != "signature":
            continue
        ans = answers.get(f["name"])
        if (
            isinstance(ans, dict)
            and ans.get("mime") == "application/json"
            and ans.get("blob_id")
        ):
            with db_lock:
                brow = _blob_row(int(ans["blob_id"]))
            if brow:
                try:
                    payload = json.loads(Path(brow[7]).read_bytes())
                    typed_sig_texts[f["name"]] = payload.get("typed", "")
                except Exception:  # noqa: BLE001
                    pass

    # Signer display name — same heuristic as the dashboard list.
    signer_name = (
        answers.get("legal_name")
        or answers.get("name")
        or answers.get("full_name")
    )
    if isinstance(signer_name, dict) or not signer_name:
        signer_name = "anonymous"

    form_dict = _form_dict(form_row, include_fields=False)
    response_dict = {
        "id": r[0],
        "form_id": r[1],
        "form_version": r[2],
        "token_id": r[3],
        "submitted_at_display": _fmt_ts(r[5]),
        "client_ip": r[6],
        "user_agent": r[7],
    }

    return render_template(
        "admin_response.html",
        form=form_dict,
        response=response_dict,
        fields=fields,
        answers=answers,
        signer_name=str(signer_name),
        typed_sig_texts=typed_sig_texts,
        md_render=lambda s: md.markdown(s or ""),
    )


# ═════════════════════════════════════════════════════════════════════════
#  Public form filler  (Host: f.kelliher.info)
# ═════════════════════════════════════════════════════════════════════════
def _load_by_token(raw_token: str):
    """Resolve a raw token → (token_row, form_row). Returns (None, None) if
    invalid/expired/revoked/used-up."""
    if not raw_token or len(raw_token) < 8 or len(raw_token) > 200:
        return None, None
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    # Constant-time comparison happens at the SQL layer via exact match on
    # a fixed-length hash; the pre-image can't be enumerated from the DB.
    row = db.execute(
        """SELECT id, form_id, token_hash, hint, form_version_at_mint,
                  max_uses, uses, created_by, created_at, expires_at, revoked_at
           FROM form_token WHERE token_hash = ?""",
        [token_hash],
    ).fetchone()
    if not row:
        return None, None
    # Belt-and-braces: verify with hmac.compare_digest against the DB hash.
    if not hmac.compare_digest(row[2], token_hash):
        return None, None
    if row[10] is not None:
        return None, None
    exp = row[9]
    if exp and exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if exp and exp < now_utc():
        return None, None
    if row[5] is not None and row[6] >= row[5]:
        return None, None
    form = db.execute(
        """SELECT id, slug, title, description, version, frozen,
                  created_by, created_at, updated_at
           FROM form WHERE id = ?""",
        [row[1]],
    ).fetchone()
    if not form:
        return None, None
    return row, form


def _materials_for(form_id: int) -> list[dict]:
    rows = db.execute(
        """SELECT id, form_id, filename, label, mime, size, sha256,
                  storage_path, ord, created_at
           FROM form_material WHERE form_id = ? ORDER BY ord""",
        [form_id],
    ).fetchall()
    return [_material_dict(r) for r in rows]


def _render_form_page(raw_token, form_row, token_row, errors=None, values=None):
    fields = fields_for(form_row[0])
    materials = _materials_for(form_row[0])
    return render_template(
        "form.html",
        token=raw_token,
        form_title=form_row[2],
        form_description_html=(md.markdown(form_row[3]) if form_row[3] else ""),
        fields=fields,
        materials=materials,
        errors=errors or {},
        values=values or {},
        kinds=FIELD_KINDS,
    )


@app.route("/<token>", methods=["GET", "POST"])
def public_form(token):
    if _request_host() != PUBLIC_HOST:
        # Don't leak that the endpoint exists on the admin host.
        return jsonify(error="not found"), 404

    with db_lock:
        token_row, form_row = _load_by_token(token)
    if not token_row:
        return _public_error("This form link is invalid, expired, or used up.", 404)

    if request.method == "GET":
        return _render_form_page(token, form_row, token_row)

    # ── POST: rate limit + validate + persist ─────────────────────────────
    ip = client_ip()
    if rate_limited(ip):
        return _public_error("Too many attempts from your address. Try again later.", 429)

    fields = fields_for(form_row[0])
    values = _collect_values(fields)
    errors: dict[str, str] = {}

    # First pass: validate non-blob fields; also stash the raw uploads
    # so we can persist them only when the whole submission is clean.
    pending_blobs: dict[str, dict] = {}
    parsed: dict[str, object] = {}

    for f in fields:
        if f["kind"] == "markdown":
            continue

        if f["kind"] in BLOB_KINDS:
            up = _prepare_blob(f, errors)
            if up is not None:
                pending_blobs[f["name"]] = up
            continue

        raw = values.get(f["name"])
        ok, err = validate_field(f, raw)
        if err:
            errors[f["name"]] = err
        else:
            parsed[f["name"]] = ok

    for f in fields:
        if f["kind"] in BLOB_KINDS and f["required"] and f["name"] not in pending_blobs and f["name"] not in errors:
            errors[f["name"]] = "required"

    if errors:
        return _render_form_page(token, form_row, token_row, errors=errors, values=values), 400

    # ── persist ───────────────────────────────────────────────────────────
    with db_lock:
        # Re-check the token under the lock — someone may have exhausted it.
        token_row, form_row = _load_by_token(token)
        if not token_row:
            return _public_error("This form link is invalid, expired, or used up.", 404)

        response_id = next_id("form_response")
        answers: dict[str, object] = dict(parsed)

        for name, up in pending_blobs.items():
            answers[name] = record_blob(
                response_id, name, up["filename"], up["mime"], up["data"]
            )

        db.execute(
            """INSERT INTO form_response
               (id, form_id, form_version, token_id, answers, client_ip, user_agent)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [
                response_id,
                form_row[0],
                form_row[4],
                token_row[0],
                json.dumps(answers, default=str),
                ip or None,
                (request.headers.get("User-Agent") or "")[:400] or None,
            ],
        )
        db.execute(
            "UPDATE form_token SET uses = uses + 1 WHERE id = ?", [token_row[0]]
        )

    return render_template(
        "receipt.html",
        form_title=form_row[2],
        response_id=response_id,
        token=token,
    )


@app.get("/<token>/receipt")
def public_receipt(token):
    if _request_host() != PUBLIC_HOST:
        return jsonify(error="not found"), 404
    with db_lock:
        token_row, form_row = _load_by_token(token)
    # We deliberately don't reveal past responses to the token holder —
    # tokens are single-purpose capabilities for submission, not read-back.
    if not token_row:
        return _public_error("This form link is invalid, expired, or used up.", 404)
    return render_template(
        "receipt.html", form_title=form_row[2], response_id=None, token=token
    )


# ── Public materials (token-gated) ─────────────────────────────────────────
class _PublicGateFail(Exception):
    def __init__(self, response):
        self.response = response


def _public_gate(token: str):
    """Host + token + rate-limit gate. Raises :class:`_PublicGateFail` with
    the ready-to-return response on rejection; otherwise returns
    ``form_row``."""
    if _request_host() != PUBLIC_HOST:
        raise _PublicGateFail((jsonify(error="not found"), 404))
    if rate_limited(client_ip()):
        raise _PublicGateFail(
            _public_error("Too many attempts from your address. Try again later.", 429)
        )
    with db_lock:
        token_row, form_row = _load_by_token(token)
    if not token_row:
        raise _PublicGateFail(
            _public_error("This form link is invalid, expired, or used up.", 404)
        )
    return form_row


@app.get("/<token>/materials")
def public_list_materials(token):
    try:
        form_row = _public_gate(token)
    except _PublicGateFail as f:
        return f.response
    with db_lock:
        rows = db.execute(
            """SELECT id, filename, label, mime, size
               FROM form_material WHERE form_id = ? ORDER BY ord""",
            [form_row[0]],
        ).fetchall()
    return jsonify(
        [
            {
                "id": r[0],
                "filename": r[1],
                "label": r[2] or r[1],
                "mime": r[3],
                "size": r[4],
            }
            for r in rows
        ]
    )


def _serve_public_material(token: str, mid: int, disposition: str):
    try:
        form_row = _public_gate(token)
    except _PublicGateFail as f:
        return f.response
    with db_lock:
        row = _material_row(mid)
    if not row or row[1] != form_row[0]:
        return _public_error("Not found.", 404)
    path = Path(row[7])
    if not path.exists():
        return _public_error("Not found.", 410)
    return send_file(
        path,
        mimetype=row[4],
        as_attachment=(disposition == "attachment"),
        download_name=row[2] or f"material-{mid}",
    )


@app.get("/<token>/materials/<int:mid>")
def public_material_download(token, mid):
    return _serve_public_material(token, mid, "attachment")


@app.get("/<token>/materials/<int:mid>/inline")
def public_material_inline(token, mid):
    return _serve_public_material(token, mid, "inline")


def _public_error(msg: str, status: int):
    return (
        render_template("error.html", message=msg),
        status,
        {"Content-Type": "text/html; charset=utf-8"},
    )


def _collect_values(fields):
    """Pull posted values off request.form / request.files into a dict
    shaped for the validator + re-render on error."""
    out: dict[str, object] = {}
    for f in fields:
        if f["kind"] == "markdown":
            continue
        name = f["name"]
        if f["kind"] == "multiselect":
            out[name] = request.form.getlist(name) or []
        elif f["kind"] == "checkbox":
            out[name] = request.form.get(name) is not None
        elif f["kind"] == "signature":
            out[name] = {
                "typed": (request.form.get(f"{name}__typed") or "").strip(),
                # svg comes from a hidden input serialized by JS
                "svg": (request.form.get(f"{name}__svg") or "").strip(),
            }
        elif f["kind"] == "file":
            out[name] = "(file)"  # placeholder for re-render
        else:
            out[name] = request.form.get(name, "")
    return out


def _prepare_blob(field, errors):
    """Turn an uploaded file or signature payload into a
    ``{filename, mime, data}`` dict ready for :func:`record_blob`. Records
    validation errors into ``errors`` and returns ``None`` if the field
    was empty. Does not touch the DB or filesystem."""
    name = field["name"]
    cfg = field.get("config") or {}

    if field["kind"] == "file":
        fs = request.files.get(name)
        if not fs or not fs.filename:
            return None
        data = fs.read()
        max_mb = int(cfg.get("max_size_mb", MAX_UPLOAD_MB_DEFAULT))
        if len(data) > max_mb * 1024 * 1024:
            errors[name] = f"exceeds max size {max_mb} MiB"
            return None
        mime = fs.mimetype or "application/octet-stream"
        accept = cfg.get("accept") or []
        if accept and not _mime_matches(mime, accept):
            errors[name] = f"file type not accepted: {mime}"
            return None
        return {"filename": fs.filename[:200], "mime": mime, "data": data}

    if field["kind"] == "signature":
        mode = cfg.get("mode", "drawn")
        svg = (request.form.get(f"{name}__svg") or "").strip()
        typed = (request.form.get(f"{name}__typed") or "").strip()

        if mode == "drawn":
            if not svg:
                if field["required"]:
                    errors[name] = "please sign"
                return None
            return {
                "filename": f"{name}.svg",
                "mime": "image/svg+xml",
                "data": svg.encode("utf-8"),
            }

        if mode == "typed":
            if not typed:
                if field["required"]:
                    errors[name] = "please type your name"
                return None
            payload = json.dumps({"typed": typed}).encode("utf-8")
            return {
                "filename": f"{name}.json",
                "mime": "application/json",
                "data": payload,
            }

        # both — accept whichever is present
        if svg:
            return {
                "filename": f"{name}.svg",
                "mime": "image/svg+xml",
                "data": svg.encode("utf-8"),
            }
        if typed:
            payload = json.dumps({"typed": typed}).encode("utf-8")
            return {
                "filename": f"{name}.json",
                "mime": "application/json",
                "data": payload,
            }
        if field["required"]:
            errors[name] = "please sign or type your name"
        return None

    return None


# ── Error pages ───────────────────────────────────────────────────────────
@app.errorhandler(413)
def too_large(_):
    return _public_error("Upload too large.", 413)


@app.errorhandler(404)
def not_found(_):
    if _request_host() == PUBLIC_HOST:
        return _public_error("This form link is invalid, expired, or used up.", 404)
    return jsonify(error="not found"), 404


def inherited_sockets():
    if os.environ.get("LISTEN_PID") != str(os.getpid()):
        return []
    return [socket.socket(fileno=3 + i) for i in range(int(os.environ.get("LISTEN_FDS", "0")))]


if __name__ == "__main__":
    from waitress import serve

    sockets = inherited_sockets()
    if sockets:
        serve(app, sockets=sockets, threads=6)
    elif os.environ.get("KWEB_LISTEN") == "socket":
        sys.exit("no listening socket from systemd; refusing to fall back to TCP")
    else:
        serve(app, host="127.0.0.1", port=PORT, threads=6)
