# Repository Audit: finance-tracker

## Executive Summary

`finance-tracker` is a small, well-organized FastAPI + HTMX personal finance app backed by Supabase. The code is readable, well-commented, and the CSV statement parser shows commendable defensive engineering. However, the security posture has several significant gaps: the app uses the Supabase **service-role key for all data operations**, bypassing RLS entirely and shifting the entire authorization burden onto application code. There is also no CSRF protection, no upload size limits, an insecure default session secret, missing template autoescape verification on user input, and minor correctness/performance issues (e.g., N+1 inserts on statement import, server-side filtering bypassed for category joins). No tests, no CI, no dependency pinning checks.

Overall: a solid hobby project, but several items should be addressed before this is used with real financial data or exposed publicly.

---

## Findings (by severity)

### 🔴 High

#### 1. Service-role key used for all data ops; RLS not actually enforced
`app/database.py` instantiates the data client with `SUPABASE_SECRET_KEY` (service-role), which **bypasses RLS**. `migrations/007_enable_rls.sql` enables RLS but adds **no policies**. The only thing protecting user data from cross-tenant access is the `eq("user_id", user_id)` filter scattered across handlers. A single forgotten filter (e.g., in a future endpoint) silently leaks all users' data.

- The category filter query in `app/dashboard.py::expense_list_partial` constructs `.eq("categories.name", category)` — a join filter, **not a row filter** — and then post-filters in Python. The unfiltered query still pulls *all* of that user's rows from the DB.
- `update_category` in `app/expenses.py` looks up category by name **without** any user/tenant scoping (categories are shared — fine — but worth a comment).

**Recommendation:**
- Switch the data client to the **anon key** and add a proper RLS policy: `USING (user_id = auth.uid())` on `expenses`. Pass the user's JWT via `postgrest.auth(jwt)` per request.
- If you keep the service-role pattern, add a thin wrapper that **requires** `user_id` on every query and rejects ones that omit it.

#### 2. Insecure default session secret
`main.py`:
```python
SECRET_KEY = os.environ.get("SESSION_SECRET", "change-this-before-deploying")
```
If `SESSION_SECRET` is unset the app silently starts with a public, well-known key — anyone can forge session cookies. This is a latent foot-gun for local dev that escapes to prod.

**Recommendation:** Fail fast:
```python
SECRET_KEY = os.environ["SESSION_SECRET"]
```
(Match the strictness used for `SUPABASE_*` in `app/database.py`.) Also set `https_only=True`, `same_site="lax"`, and a sensible `max_age` on `SessionMiddleware`.

#### 3. No CSRF protection on state-changing endpoints
`POST /upload/statement`, `PUT /expense/{id}/category`, `DELETE /expense/{id}`, `POST /login`, `POST /signup` all rely solely on a session cookie. An attacker site can submit forms / HTMX requests cross-origin (HTMX uses standard form encoding and same-site cookies are not enforced by default).

**Recommendation:** Add CSRF tokens (e.g., `starlette-csrf` or a manual double-submit token rendered into templates and validated in a dependency). At minimum, set `SameSite=Strict` on the session cookie and verify `Origin`/`Referer` on mutating routes.

#### 4. Unbounded file upload
`upload_statement` reads the entire upload via `await file.read()` with no size cap. A malicious or accidental large upload exhausts memory.

**Recommendation:**
- Stream/read with a size guard (reject > e.g. 2 MB).
- Validate content-type, not just filename extension.
- Consider running the parser inside `asyncio.to_thread` — `parse_csv_statement` is CPU-bound and currently blocks the event loop.

---

### 🟠 Medium

#### 5. N+1 inserts on statement import
`app/expenses.py::upload_statement` issues **two queries per row** (`select existing`, `select prior_cats`, `insert`). A 500-row statement = ~1500 round-trips.

**Recommendation:**
- Pull existing rows for this user once (filter in Python) or use a single upsert with a `UNIQUE (user_id, name, amount, date)` constraint and `ON CONFLICT DO NOTHING`.
- Bulk-insert deduped rows in one call: `db.table("expenses").insert([...]).execute()`.

#### 6. Float for money
`expenses.amount` is `DOUBLE PRECISION` (`migrations/001_initial_schema.sql`) and `_parse_amount` returns `float`. Rounding artifacts will appear in totals — and worse, in the dedup check `eq("amount", txn["amount"])`, where a re-imported statement with a tiny float difference will silently double-import.

**Recommendation:** Use `NUMERIC(12,2)` in Postgres and `decimal.Decimal` (or integer minor units) in Python.

#### 7. Date stored as TEXT
`expenses.date TEXT` (`migrations/001_initial_schema.sql`) — Supabase string comparison works because the format is ISO-8601, but indexing, range queries, and constraints would all benefit from `DATE`.

**Recommendation:** `ALTER COLUMN date TYPE DATE USING date::date;`

#### 8. Missing dedup uniqueness constraint
Dedup is purely application-side. A race between two concurrent uploads, or any future direct DB insert, can create duplicates.

**Recommendation:** `UNIQUE (user_id, name, amount, date)` (paired with finding #5's upsert pattern).

#### 9. Template autoescape — sanity check raw user input
Jinja2 templates from `Jinja2Templates(directory="templates")` autoescape `.html` by default, which is correct. But:
- `app/expenses.py::update_category` returns `HTMLResponse(f'... {category_name} ...')` with a value that came **directly from form data**. This is reflected XSS:
  ```python
  return HTMLResponse(f'<span class="expense-category-tag" id="category-tag-{expense_id}">{tag_content}</span>')
  ```
  A user can POST `category="<script>...</script>"`. Even though the dropdown values are controlled, the endpoint does not validate against the categories table.
- Similarly `_row_name` values flow from CSV into the DB and onto the page; autoescape handles the page side, but consider rejecting control chars / length-limiting names (e.g., 200 chars).

**Recommendation:** Validate `category_name` is in the known categories before echoing it. Or render via a template fragment, not f-string.

#### 10. Auth flow brittleness
- `app/auth.py::login` stores `user_id` and `user.email` in the session, but **does not** retain the Supabase JWT — so the data client cannot operate as the user. This entrenches finding #1.
- No password complexity, no rate limiting on `/login` or `/signup`. A single-user app is one mis-toggle away from being multi-user; both endpoints are public.

**Recommendation:** Persist `access_token`/`refresh_token` in session (signed cookie is fine for low-volume), refresh on expiry, and pass JWT to the data client. Add basic IP-based rate limiting (e.g., `slowapi`).

#### 11. `_require_auth` returns inconsistent types
`app/dashboard.py::_require_auth` returns `RedirectResponse`, while `app/expenses.py::_require_auth` returns `HTMLResponse("Unauthorized", 401)`. Callers do `if redirect: return redirect`, which works, but the pattern is easy to misuse (forgetting the check still type-checks). Convert to a FastAPI **dependency** that raises `HTTPException` or returns the user id.

```python
def current_user(request: Request) -> str:
    uid = request.session.get("user_id")
    if not uid: raise HTTPException(303, headers={"Location": "/login"})
    return uid
```

---

### 🟡 Low

#### 12. Hard-coded Render-only static asset
`templates/dashboard.html` loads HTMX and Chart.js from CDN with no SRI/integrity hash and no fallback. Add `integrity=` attributes or self-host.

#### 13. Inline `<script>` blocks
Large blocks of JS in `templates/dashboard.html` and the modal partial inhibit a useful CSP. Move to `static/dashboard.js` and add a `Content-Security-Policy` header (script-src 'self' plus CDN hashes).

#### 14. No tests, no CI
There are no unit tests for `parse_csv_statement` — the most logic-heavy module, and the one most likely to silently break on a new bank format. A handful of fixture-based tests would be high-value.

**Recommendation:** Add `tests/` with `pytest`, fixtures of CSVs from each bank you support, and a GitHub Action running `uv sync && uv run pytest`.

#### 15. Migrations are manual and not idempotent
`migrations/001_initial_schema.sql` will fail on a re-run (no `IF NOT EXISTS`). Migration 006 has a hand-edited `<YOUR_USER_UUID>` placeholder that will throw if forgotten. Consider `supabase-cli` migrations or a `psql` runner script.

#### 16. `_require_auth` returns a `RedirectResponse` for HTMX partials
`/partials/expense-list` redirects to `/login` on expiry. HTMX will swap the **login page HTML** into the expense list. Return `HX-Redirect: /login` header instead:
```python
return Response(status_code=401, headers={"HX-Redirect": "/login"})
```

#### 17. `category_id` lookup ignores type
In `update_category`, you look up category by `name` without filtering by `type`. After migration 004 renamed the income "Investment" to "Investment Returns", names are unique — fine for now — but consider adding `(name, type)` uniqueness or always passing the id from the frontend.

#### 18. Singleton clients are not async-safe initialization
`get_client` uses a module-global with no lock. Under concurrent first requests, you may instantiate two clients — harmless here but worth a `functools.lru_cache` for clarity.

#### 19. `--reload` in production entrypoint
`main.py` runs `uvicorn.run(..., reload=True)` when invoked directly. Render uses `uvicorn` directly so this is dormant, but it's a footgun — gate behind `if os.getenv("ENV") == "dev"`.

---

## Next Steps Checklist

**Security (do first):**
- [ ] Require `SESSION_SECRET` — remove the fallback (`main.py`)
- [ ] Add RLS policies on `expenses` and switch data client to anon-key + per-request JWT (`app/database.py`, new migration)
- [ ] Validate `category` input against the categories table in `update_category` (`app/expenses.py`)
- [ ] Add CSRF tokens to all POST/PUT/DELETE; set `same_site="strict"` / `https_only=True` on the session cookie
- [ ] Cap upload size and validate content type in `upload_statement`
- [ ] Add rate limiting on `/login`, `/signup`, and `/upload/statement`

**Correctness / Data integrity:**
- [ ] Migrate `expenses.amount` to `NUMERIC(12,2)`, `expenses.date` to `DATE`
- [ ] Add `UNIQUE (user_id, name, amount, date)` and switch to upsert
- [ ] Bulk-insert statement transactions and pre-fetch existing rows once (`app/expenses.py`)
- [ ] Return `HX-Redirect` on auth failure for HTMX endpoints

**Quality:**
- [ ] Add pytest + fixture CSVs for `parse_csv_statement`; wire up GitHub Actions
- [ ] Replace `_require_auth` with a FastAPI dependency
- [ ] Extract inline JS from `dashboard.html` into `static/`, add CSP and SRI
- [ ] Make migrations idempotent (`CREATE TABLE IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`)
- [ ] Gate `reload=True` behind an env flag

**Nice-to-have:**
- [ ] Use `lru_cache` on Supabase client factories
- [ ] Add structured logging and a request-id middleware
- [ ] Document the bank-format support matrix and add a sample CSV per supported bank under `tests/fixtures/`