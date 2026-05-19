# Repository Audit: finance-tracker

## Executive Summary

`finance-tracker` is a small FastAPI + HTMX personal expense tracker backed by Supabase. The code is readable, modular, and the CSV parser is impressively defensive. However, several **security and reliability issues are blocking-grade for a multi-user, internet-exposed deployment**, most notably the use of the Supabase **service-role key for all data operations while RLS is disabled in application logic**, an **insecure default session secret**, missing CSRF protection on state-changing endpoints, and an XSS sink in the category update handler. Reliability gaps include no upload size limit, unbounded synchronous duplicate-check loops, and an HTML-via-`script` injection used to refresh the UI after upload.

The app is described as "single-user" in `README.md` but ships a `/signup` route — this inconsistency drives most of the security risk and should be resolved explicitly.

---

## Findings (ordered by severity)

### 1. 🔴 Critical — Service-role key used for all data ops, RLS unenforced at app layer
`app/database.py` returns a Supabase client built with `SUPABASE_SECRET_KEY` (service role) for *every* query. This key **bypasses Row-Level Security**. The only thing preventing user A from reading user B's expenses is the manual `.eq("user_id", user_id)` filter sprinkled through `app/dashboard.py` and `app/expenses.py`.

- Any future endpoint that forgets `.eq("user_id", ...)` silently leaks/mutates other users' data.
- `migrations/007_enable_rls.sql` enables RLS but adds **no policies**, so the anon key is locked out but the service key still bypasses everything — RLS provides zero defense in depth here.
- If `SUPABASE_SECRET_KEY` ever leaks (logs, error pages, a future debug route), the entire database is compromised.

**Recommendation:** Use the anon key plus an authenticated Supabase session per request, and add RLS policies (`user_id = auth.uid()`) on `expenses`. Keep service-role usage to background/admin tasks only.

---

### 2. 🔴 Critical — Insecure default `SESSION_SECRET`
`main.py`:
```python
SECRET_KEY = os.environ.get("SESSION_SECRET", "change-this-before-deploying")
```
If `SESSION_SECRET` is unset in any environment, sessions are signed with a publicly known string, allowing trivial session forgery and account takeover.

**Recommendation:** Fail fast on startup if `SESSION_SECRET` is missing:
```python
SECRET_KEY = os.environ["SESSION_SECRET"]
```
Also configure `SessionMiddleware(..., https_only=True, same_site="lax", max_age=...)`.

---

### 3. 🔴 High — XSS in category update response
`app/expenses.py::update_category`:
```python
tag_content = category_name if category_name else ""
return HTMLResponse(
    f'<span ... >{tag_content}</span>'
)
```
`category_name` comes straight from form data and is interpolated unescaped into an HTML response that HTMX swaps into the DOM. Although the legitimate UI only sends known category names, the endpoint accepts arbitrary form values — a logged-in user (or CSRF — see #5) can persist/render `<img src=x onerror=...>` into the page.

**Recommendation:** Validate `category_name` against the DB-stored category list before responding, and/or use `html.escape()` / Jinja autoescape for the fragment.

---

### 4. 🔴 High — Logout is a GET request
`app/auth.py`:
```python
@router.get("/logout")
def logout(...): ...
```
Any `<img src="/logout">` on a malicious page logs users out (CSRF). Combined with predictable login flows, this also enables login-fixation-style nuisance.

**Recommendation:** Change to `POST /logout` invoked via an HTMX/form button.

---

### 5. 🟠 High — No CSRF protection on state-changing endpoints
`SessionMiddleware` cookies default to `SameSite=Lax`, which protects most cross-origin POSTs but **not** top-level form submissions and depends on browser version. There is no CSRF token on:
- `POST /login`, `POST /signup`
- `POST /upload/statement`
- `PUT /expense/{id}/category`
- `DELETE /expense/{id}`

**Recommendation:** Add CSRF tokens (e.g. `starlette-csrf` or `fastapi-csrf-protect`) and enforce `SameSite=Strict` plus `Secure` cookies in production.

---

### 6. 🟠 High — Signup is unrestricted; single-user claim is false
README says "Single-user login," but `app/auth.py` exposes public `/signup`. Anyone on the internet can create an account on the deployed Render instance. Because of finding #1, every signup gets a working tenant inside the same DB — fine if intended, but the README's framing suggests it is not.

**Recommendation:** Either (a) gate `/signup` behind an invite code / env-controlled allowlist, or (b) update docs and harden multi-tenancy (#1).

---

### 7. 🟠 High — No upload size / row limits; DoS via large CSV
`app/expenses.py::upload_statement`:
```python
contents = await file.read()        # entire file into memory
transactions = parse_csv_statement(contents)
for txn in transactions:
    existing = (db.table("expenses").select("id")
                  .eq(...).eq(...).eq(...).execute())   # N round-trips
    ...
    db.table("expenses").insert({...}).execute()        # +1 round-trip
```
- No `Content-Length` check — a 1 GB CSV is happily buffered in memory.
- Per-row dedupe does **2 round-trips per transaction**, blocking the event loop on synchronous Supabase calls. A 5k-row statement = 10k blocking HTTP calls.

**Recommendation:**
- Reject uploads above e.g. 5 MB (check `request.headers["content-length"]` and stream).
- Batch dedupe: fetch existing `(name, amount, date)` triples once, dedupe in memory, then `insert([...])` in bulk.
- Run blocking Supabase calls via `run_in_threadpool` or use the async Supabase client.

---

### 8. 🟠 Medium — Injected `<script>` in HTMX response is an anti-pattern and breaks under CSP
`upload_statement` returns:
```python
return HTMLResponse(f"""... <script>setTimeout(...) </script>""")
```
- A future Content-Security-Policy will block this.
- It couples server response to a specific DOM structure (`#modal-overlay`) and bypasses HTMX's normal triggers.

**Recommendation:** Use HTMX response headers: `HX-Trigger: refreshExpenses` + `HX-Reswap: ...`, and listen for that event client-side. Or set `hx-on::after-request` on the form.

---

### 9. 🟠 Medium — Missing security headers and HTTPS hardening
No `SecureHeaders`, no HSTS, no CSP, no `X-Content-Type-Options`, no `Referrer-Policy`. Login form is served without explicit `Cache-Control: no-store`.

**Recommendation:** Add a middleware (e.g. `secure` library) and a strict CSP. Set `https_only=True` on session middleware in production.

---

### 10. 🟡 Medium — `categories.name` collisions across tenants
`update_category` looks up category by name only:
```python
cat_result = db.table("categories").select("id").eq("name", category_name).execute()
```
Because categories have `UNIQUE(name)` and are shared (per CLAUDE.md), this works today — but the income/expense `type` column means two semantically different "Investment" categories existed (fixed by migration 004 renaming). If categories ever become per-user, this lookup silently mis-maps.

**Recommendation:** Resolve by `(name, type)` (sign of `amount`), and assert exactly one row returned.

---

### 11. 🟡 Medium — `date` stored as `TEXT`
`migrations/001_initial_schema.sql`: `date TEXT NOT NULL`. The app already had to defensively filter malformed dates in the JS chart code (`templates/dashboard.html`):
```js
.filter(e => /^\d{4}-\d{2}-\d{2}$/.test(e.date));
```
That guard hides a real data-integrity problem.

**Recommendation:** Migrate to `DATE`; reject parsed transactions whose `_parse_date` fails (already done) and let the DB enforce the type.

---

### 12. 🟡 Medium — `amount` as `DOUBLE PRECISION`
Floating-point for money invites rounding drift, especially across import → display → re-import dedupe (`.eq("amount", txn["amount"])` in `upload_statement`). A reimport of the same row with a different parser path can fail dedup due to FP round-trip.

**Recommendation:** Migrate to `NUMERIC(14,2)`. In Python, parse with `Decimal`.

---

### 13. 🟡 Low — File-type check is by extension only
`upload_statement`:
```python
if filename.lower().endswith(".csv"):
```
A user can upload arbitrary content named `.csv`. Combined with #7 (no size limit), this is a soft DoS / parser-fuzz vector.

**Recommendation:** Check `Content-Type` and run the parser inside a size-bounded reader.

---

### 14. 🟡 Low — Reliance on `localStorage` for "excluded from chart"
`templates/dashboard.html` stores excluded IDs in `localStorage`. State is per-browser, not per-user, and IDs collide across accounts logged in on the same browser.

**Recommendation:** Persist `excluded` as a column on `expenses` (or a side table).

---

### 15. 🟡 Low — `print`/error visibility, no structured logging, no Sentry
Failures in Supabase calls surface as unhandled 500s with full tracebacks (FastAPI default) — risk of leaking schema details in prod if `DEBUG`-ish responses are ever enabled.

**Recommendation:** Add a global exception handler returning generic 500s, plus structured logging.

---

### 16. 🟢 Info — Tests, CI, dependency pinning
No `tests/`, no CI workflow, and the parser in `app/expenses.py` (the most fragile code) has zero automated coverage despite being well-documented. `pyproject.toml`/`uv.lock` not shown but Render uses `--frozen`, which is good — keep it that way and add Dependabot/Renovate.

---

## Concrete Recommendations Summary

| Area | File | Change |
|---|---|---|
| Auth | `main.py` | Require `SESSION_SECRET`; enable `https_only`, `same_site`. |
| Auth | `app/auth.py` | Make `/logout` POST-only; consider invite-gated signup. |
| DB | `app/database.py` | Stop using service key for per-request data; use anon + user JWT. |
| DB | `migrations/008_rls_policies.sql` (new) | Add policies: `user_id = auth.uid()` on `expenses`. |
| Schema | `migrations/001_initial_schema.sql` | `date DATE`, `amount NUMERIC(14,2)`. |
| XSS | `app/expenses.py::update_category` | Validate category against DB, escape output. |
| CSRF | All POST/PUT/DELETE routes | Add CSRF middleware/token. |
| DoS | `app/expenses.py::upload_statement` | Cap upload size, batch dedupe, bulk insert, offload to threadpool. |
| HTMX | `app/expenses.py::upload_statement` | Use `HX-Trigger` instead of inline `<script>`. |
| Headers | `main.py` | Add security-headers middleware + CSP. |
| Parser | `app/expenses.py::parse_csv_statement` | Add unit tests for each bank's sample CSV. |
| Tests/CI | repo root | Add `pytest`, GitHub Actions, dependency scanning. |

---

## Next Steps Checklist

- [ ] Require `SESSION_SECRET` at boot; rotate any value used so far.
- [ ] Convert `/logout` to POST; add CSRF tokens to all state-changing routes.
- [ ] Decide explicitly: single-user (remove `/signup`) or multi-tenant (do the next item).
- [ ] Add RLS policies on `expenses` and switch data ops to the user-scoped Supabase session.
- [ ] Escape/validate `category_name` in `update_category` response.
- [ ] Add `MAX_UPLOAD_BYTES` guard and bulk-insert path in `upload_statement`.
- [ ] Replace inline `<script>` in upload response with `HX-Trigger` header.
- [ ] Migrate `expenses.date` to `DATE` and `expenses.amount` to `NUMERIC(14,2)`.
- [ ] Add security headers middleware + CSP; set `Secure`, `SameSite=Strict` cookies in prod.
- [ ] Add `pytest` suite, especially fixtures of real bank CSVs for `parse_csv_statement`.
- [ ] Wire a GitHub Actions CI (lint, type-check, tests) and enable Dependabot.
- [ ] Persist chart-exclusions and any other UI state server-side, keyed by `user_id`.