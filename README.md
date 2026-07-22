# gluck-forms

A tiny, self-hosted forms service. Design forms with an admin API, hand
out capability-URL tokens, collect responses (including signatures and
file uploads) in a DuckDB. One Flask process, two Caddy sites.

## Trust model

There are two hosts, both proxied to the same backend port (default
**9095**). The app routes by `Host` header.

| Host | Auth | What lives here |
| --- | --- | --- |
| `forms.<base>` | Authelia 2FA (forward-auth) **or** `Authorization: Bearer <jwt>` validated against Authelia's JWKS. Requires the `forms-admin` group. | Admin API — create forms, mint tokens, read responses, download blobs. |
| `f.<base>` | **None**. The URL token is the capability. `sha256(token) == form_token.token_hash` is checked in constant time. | Public form filler — `f.<base>/<token>` renders the form; `POST` submits it. |

Trust boundaries:

- The service binds to loopback. Caddy strips client-supplied `Remote-*`
  headers before forwarding.
- Admin endpoints refuse (`404`) when reached on the public host, so a
  Caddy misconfiguration can't silently expose them.
- `X-Forwarded-For` is only honored on the public host (upstream is
  cloudflared → Caddy) and only the first hop is used.
- Tokens are `secrets.token_urlsafe(24)`; only the sha256 hex is ever
  stored. Raw tokens are returned exactly once, at mint time.
- Comparison uses `hmac.compare_digest` after hashing.
- Public form submissions are rate-limited in-app: **20 attempts / IP /
  hour** (per-process in-memory bucket).
- Every response carries `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, and a strict
  CSP (`default-src 'self'` etc). Public host responses also get
  `Cache-Control: no-store`.

## Data model (DuckDB)

- **form** — `slug`, `title`, `description`, `version`, `frozen`.
- **form_field** — `form_id`, `name` (machine key), `label`, `kind`,
  `required`, `ord`, `config` (JSON, kind-specific).
- **form_token** — `form_id`, `token_hash` (sha256 hex),
  `form_version_at_mint`, `max_uses`, `uses`, `expires_at`, `revoked_at`.
- **form_response** — `form_id`, `form_version`, `token_id`, `answers`
  (JSON keyed by field name), `submitted_at`, `client_ip`, `user_agent`.
- **form_blob** — one row per file/signature written by a response.
  Content-addressed under `/var/lib/gluck-forms/blobs/<sha[:2]>/<sha>` —
  identical uploads dedup to one file on disk with multiple `form_blob`
  rows pointing at it.

IDs are `SELECT COALESCE(MAX(id),0) + 1 FROM <table>` under a
threading.Lock — DuckDB sequences bit us in gluck-calendar.

## Field kinds

`short_text | long_text | radio | checkbox | multiselect | signature | date | email | phone | file | markdown`

`markdown` is display-only (its `label`/`description` is rendered as
markdown, no answer is collected). Everything else produces an entry in
`response.answers[field_name]`.

Per-kind `config` (JSON on `form_field`):

| Kind | Config keys |
| --- | --- |
| `short_text`, `long_text` | `min_length`, `max_length`, `pattern` (regex) |
| `email` | `max_length` (default 200) |
| `date` | `min` (`YYYY-MM-DD`), `max` |
| `radio` | `options: [{value, label}]` (required) |
| `multiselect` | `options: [{value, label}]` (required) |
| `checkbox` | `check_label`, `must_check` (bool) |
| `file` | `accept: ["image/*", "application/pdf", ...]`, `max_size_mb` (default 25) |
| `signature` | `mode: "drawn" \| "typed" \| "both"` |

**Blob-typed** answers (`file`, `signature`) are stored as
`{"blob_id": <int>, "filename": ..., "mime": ..., "size": ...}` in the
answers JSON; the bytes live on disk. Drawn signatures are captured as
SVG in the browser and posted as `<field>__svg`; typed signatures as
`<field>__typed`.

## HTTP endpoints

### Admin — Host `forms.<base>`

```
POST   /forms                             {slug, title, description?, fields: [...]}
GET    /forms
GET    /forms/<slug>
PUT    /forms/<slug>                      allowed only when frozen=false; bumps version
POST   /forms/<slug>/freeze
POST   /forms/<slug>/tokens               {hint?, expires_in_days, max_uses?}
                                          returns {token, url, ...} ONCE
GET    /forms/<slug>/tokens
POST   /tokens/<id>/revoke
GET    /forms/<slug>/responses
GET    /responses/<id>
GET    /blobs/<id>                        Content-Disposition: attachment
GET    /blobs/<id>/preview                Content-Disposition: inline
GET    /health
GET    /whoami
```

### Public — Host `f.<base>`

```
GET    /<token>              render form
POST   /<token>              submit; multipart/form-data
GET    /<token>/receipt      "thanks" page (does not read past submissions)
```

## Example — minting a form + a token

```bash
BASE=https://forms.kelliher.info
BEARER=... # from Authelia's OIDC CLI flow (client_id=gforms-cli)

curl -sf -H "Authorization: Bearer $BEARER" -H 'Content-Type: application/json' \
  "$BASE/forms" --data '{
    "slug": "tos-2026",
    "title": "Terms of Service 2026",
    "description": "Please review and sign.\n\nThis is **binding**.",
    "fields": [
      {"name": "notice", "kind": "markdown", "label": "Notice",
       "description": "By signing below you agree to the ToS.", "required": false, "ord": 0},
      {"name": "name",  "kind": "short_text", "label": "Full name",  "required": true, "ord": 1},
      {"name": "email", "kind": "email",      "label": "Email",      "required": true, "ord": 2},
      {"name": "sig",   "kind": "signature",  "label": "Signature",  "required": true, "ord": 3,
       "config": {"mode": "both"}}
    ]
  }'

curl -sf -H "Authorization: Bearer $BEARER" -H 'Content-Type: application/json' \
  "$BASE/forms/tos-2026/tokens" --data '{
    "hint": "acme corp batch #1", "expires_in_days": 30, "max_uses": 10
  }'
# → {"id": 1, "token": "...", "url": "https://f.kelliher.info/<token>", ...}
```

Hand the `url` to the signer. They open it, fill it, submit. You read
responses with:

```bash
curl -sf -H "Authorization: Bearer $BEARER" "$BASE/forms/tos-2026/responses"
```

## Adding a new field kind

Two touch points:

1. **Backend** — `forms/gluck_forms.py`
   - Add the name to `FIELD_KINDS` (and to `BLOB_KINDS` if it stores bytes).
   - Extend `validate_field_spec` with any admin-time checks on the
     field's `config` (shape of options, required sub-keys, etc.).
   - Extend `validate_field` with the response-time validator. It
     returns `(ok_value, error_message)`; the error is shown inline in
     the re-rendered form.
   - If it's blob-typed, extend `_prepare_blob` (parses the request,
     returns `{filename, mime, data}` or an error) and — if the client
     doesn't post a normal `<input type=file>` — extend `_collect_values`
     so error re-renders preserve what the user typed.

2. **Template** — `forms/templates/form.html`
   - Add a `{% elif f.kind == '<new_kind>' %}` branch inside the field
     loop. Keep the styling in the existing `--fg`/`--muted`/`--accent`
     palette. If it needs client JS, add it to the `<script>` block at
     the bottom scoped by a `data-kind` selector.

That's it — the JSON `config` is opaque to the storage layer, and the
answers JSON is untyped, so no schema migration is needed.

## Deployment

This flake exposes `nixosModules.default`. In your host flake:

```nix
inputs.gluck-forms.url = "github:jack-work/gluck-forms";

imports = [ inputs.gluck-forms.nixosModules.default ];
services.gluck-forms.enable = true;
# services.gluck-forms.port = 9095;  # default
```

That registers **two** sites into `services.kelliher-web.sites`:

- `forms-admin` → `forms.<baseDomain>`, `requireAuth = true`
- `gluck-forms-public` → `f.<baseDomain>`, `requireAuth = false`

Both proxy to the same loopback port. The service runs as a
`DynamicUser` with `StateDirectory = gluck-forms`, so state lives in
`/var/lib/gluck-forms/` (DuckDB + `blobs/`).

You'll also want (outside this repo):

- Authelia OIDC client `gforms-cli` for CLI/agent access.
- Authelia access-control rule requiring 2FA on `forms.<baseDomain>`
  (2FA is *not* set on `f.<baseDomain>` — that's the whole point).
- lldap group `forms-admin` with your admin users in it.

## Local dev

```
nix develop
python forms/gluck_forms.py
# → binds 127.0.0.1:9095 with GLUCK_FORMS_DB=./.local.duckdb
```

The service treats `Host: localhost` as neither admin nor public, so use
`curl --resolve` or `-H "Host: forms.kelliher.info"` to exercise
routing. In tests, injecting `Remote-User` / `Remote-Groups` headers
bypasses the bearer flow.
