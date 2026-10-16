"""Every page renders the reader's light/dark choice from the zanni-scheme
cookie that settings.kelliher.info sets, and nothing for any other value, so
a forged cookie cannot reach the markup. The zanni faces and stylesheets are
served from this origin, which the page's CSP (default-src 'self') allows.

Run: GLUCK_FORMS_SRC=<formsSrc> python tests/test_scheme.py
"""

import os
import sys
import tempfile

tmp = tempfile.mkdtemp()
os.environ.update(
    GLUCK_FORMS_DB=f"{tmp}/forms.duckdb",
    GLUCK_FORMS_MATERIALS_DIR=f"{tmp}/materials",
    GLUCK_FORMS_RESPONSES_DIR=f"{tmp}/responses",
)
sys.path.insert(0, os.environ["GLUCK_FORMS_SRC"])

import gluck_forms as gf  # noqa: E402

c = gf.app.test_client()
PUBLIC = "http://f.kelliher.info"
failed = 0


def check(name, ok, detail=""):
    global failed
    print(("  ok   " if ok else "  FAIL ") + name + ("" if ok else f"\n       {detail}"))
    failed += 0 if ok else 1


def page(cookie):
    if cookie is None:
        c.delete_cookie("zanni-scheme", domain="f.kelliher.info")
    else:
        c.set_cookie("zanni-scheme", cookie, domain="f.kelliher.info")
    r = c.get("/no-such-token", base_url=PUBLIC)
    body = r.get_data(as_text=True)
    return r, body, body.split("<head>", 1)[0]


r, body, top = page(None)
check("the error page renders", r.status_code == 404 and "<html" in body, body[:120])
check("no cookie: it follows the OS", "data-scheme" not in top and "color-scheme: light dark" in body, top)
check("the page varies by cookie", "Cookie" in r.headers.get("Vary", ""), r.headers.get("Vary"))
for s in ("light", "dark"):
    r, body, top = page(s)
    check(f"{s}: pinned on <html>", f'<html lang="en" data-scheme="{s}">' in top, top)
for bad in ("system", "", '"><script>x</script>', "Dark"):
    r, body, top = page(bad)
    check(f"{bad!r}: ignored", "data-scheme=" not in top and "<script>x" not in body, top)

for path, mime in [("/static/zanni/fonts.css", "text/css"), ("/static/zanni/gesso.css", "text/css"),
                   ("/static/zanni/fontpack.css", "text/css"), ("/static/zanni/fonts/vt323.woff2", "font/woff2")]:
    r = c.get(path, base_url=PUBLIC)
    check(f"{path} is served", r.status_code == 200 and r.mimetype == mime, (r.status_code, r.mimetype))
r = c.get("/no-such-token", base_url=PUBLIC)
check("the CSP lets the page load them", "default-src 'self'" in r.headers.get("Content-Security-Policy", ""))
check("no page names a font CDN", all("googleapis" not in open(os.path.join(os.environ["GLUCK_FORMS_SRC"], "templates", f)).read()
                                      for f in os.listdir(os.path.join(os.environ["GLUCK_FORMS_SRC"], "templates"))))
print(f"[scheme] {'all passed' if not failed else f'{failed} failed'}")
sys.exit(1 if failed else 0)
