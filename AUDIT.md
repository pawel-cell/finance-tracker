# Repository Audit: finance-tracker

## Executive Summary

`finance-tracker` is a small, well-organized FastAPI + HTMX personal finance app backed by Supabase. The code is readable, comments are unusually thoughtful (CSV parsing, date heuristics), and module boundaries are clean. However, the app has several **security and correctness issues that should block production use**: it bypasses Row-Level Security via the service-role key on every request, lacks CSRF protection on state-changing endpoints, has unbounded file upload handling, and ships with an insecure default session secret. There is also no automated test suite and no CI.

Overall the project is in good shape for a hobby app, but needs a focused security/hardening pass before it can be considered production-ready, even for single-user deployment.

---

## Findings (by severity)

### 🔴 Critical

#### 1. Service-role key used for all data operations — RLS is effectively disabled
`app/database.py` returns a client built with `SUPABASE_SECRET_KEY` (service role) for all CRUD. Migration `007_enable_rls.sql` enables RLS but defines **no policies**, and the app intentionally bypasses RLS. This means:
- A bug in `WHERE user_id = …` enforcement (e.g. a missing `.eq("user_id", …)`) immediately becomes a cross-tenant data leak.
- The service-role key is loaded into the web process, expanding blast radius if the app is ever compromised (SSRF, RCE, log leak).

The app already has the user's JWT after `sign_in_with_password`; it should be used to make per-user authenticated requests against PostgREST with proper RLS policies.

**Recommendation:** Store the access/refresh tokens in the session, build per-request Supabase clients with `postgrest.auth(jwt)`, and write RLS policies like `user_id = auth.uid()` on `expenses`. Keep the service-role client only for genuine admin operations.

#### 2. Default `SESSION_SECRET` is a hardcoded placeholder
`main.py`:
```python
SECRET_KEY = os.environ.get("SESSION_SECRET", "change-this-before-deploying")
```
If the env var is ever missing in production, sessions are trivially forgeable. There is no startup validation.

**Recommendation:** Fail fast: `SECRET_KEY = os.environ["SESSION_SECRET"]`. Also set `https_only=True`, `same_site="lax"`, and an explicit `max_age` on `SessionMiddleware`.

#### 3. No CSRF protection on state-changing endpoints
Session auth via cookies + no CSRF token means any logged-in user visiting a malicious site can be forced to upload statements, delete expenses, change categories, or call `/logout`. The `DELETE`/`PUT` endpoints provide partial protection (preflight) but `POST /upload/statement` and form-based `POST /login`/`/signup` are exposed.

**Recommendation:** Add a CSRF middleware (e.g. `starlette-csrf` or `fastapi-csrf-protect`), set `SameSite=Strict` (or at minimum `Lax`) on the session cookie, and consider verifying `Origin`/`Referer` for HTMX requests.

---

### 🟠 High

#### 4. Unbounded file upload and in-memory parsing
`app/expenses.py::upload_statement` does `contents = await file.read()` with no size limit and no content-type validation beyond a filename suffix. A multi-GB upload can OOM the dyno; a malicious `.csv` could be arbitrarily large.

**Recommendation:**
- Enforce a max body size (e.g. via reverse proxy or `request.headers["content-length"]` check, then `await file.read(MAX_BYTES + 1)`).
- Validate MIME type, not just extension.
- Stream-parse instead of fully buffering.

#### 5. N+1 inserts + N+1 dedup queries on import
For every transaction the importer does two round-trips (`select` for dedup, `select` for prior category) and one `insert`. A 500-row statement = ~1500 DB calls. Slow and bills against Supabase quotas.

`app/expenses.py::upload_statement`

**Recommendation:** Batch-fetch existing `(name, amount, date)` tuples for the user once, do dedup in Python, then do a single `insert([...])` for the new rows. Similarly batch the prior-category lookup.

#### 6. Categories table is global, not per-user
`expenses` has `user_id` but `categories` does not. Every user sees and selects from the same shared category list, and `update_category` selects a category by name with no user scoping. This is technically working but conceptually broken for a multi-user app and prevents customization.

**Recommendation:** Add `user_id` (nullable for system defaults) and scope queries accordingly.

#### 7. `update_category` returns un-escaped category name as HTML
```python
return HTMLResponse(f'<span class="…">{tag_content}</span>')
```
`tag_content` comes from a form field. Since categories are currently chosen from a dropdown matched to DB rows you'd have to inject a category named `<script>…</script>` to exploit, but as written nothing prevents that, and `parse_csv_statement` writes user-controlled `name` directly into the DB and then back into templates.

**Recommendation:** Use `templates.TemplateResponse(...)` (Jinja autoescapes) or call `html.escape()` before interpolating. Apply the same audit to inline `f"…"` HTML returns.

---

### 🟡 Medium

#### 8. `expenses.date` is `TEXT`, not `DATE`
`migrations/001_initial_schema.sql` stores dates as `TEXT`. All sorting, filtering, and chart bucketing relies on `YYYY-MM-DD` lexicographic order. One off-format insert (e.g. a future import that produces `15/03/2026`) silently corrupts ordering and breaks `fillGaps()` in the dashboard.

**Recommendation:** Migrate to `DATE` type. Adds type-safety and indexable range queries.

#### 9. Missing indexes
- `expenses(date)` (used in every dashboard `ORDER BY date DESC`)
- `expenses(user_id, name, amount, date)` (dedup query in import)
- `expenses(user_id, category_id)` for filtered queries

Only `expenses_user_id_idx` exists (migration 006).

#### 10. Auth check inconsistency
- `dashboard._require_auth` returns a redirect.
- `expenses._require_auth` returns a 401.

Both are open-coded in each module. Easy to forget on a new route, and the duplication invites drift.

**Recommendation:** Replace with a single FastAPI dependency, e.g.:
```python
def current_user(request: Request) -> str:
    uid = request.session.get("user_id")
    if not uid: raise HTTPException(401)
    return uid
```

#### 11. Logout doesn't invalidate Supabase session
`auth.py::logout` only clears the session cookie. The Supabase access token (if it were tracked) remains valid for its TTL. Not exploitable today because the token isn't used, but if finding #1 is fixed this becomes important.

#### 12. CDN scripts loaded without SRI
`templates/dashboard.html` loads HTMX and Chart.js from unpkg/jsdelivr without `integrity=` or `crossorigin=`. A compromised CDN can ship arbitrary JS into a session-authenticated page.

**Recommendation:** Add SRI hashes, pin major+minor+patch, or self-host.

---

### 🟢 Low / Code Quality

#### 13. No tests, no CI
There is no `tests/` directory, no GitHub Actions workflow. `parse_csv_statement` in particular has rich heuristics and zero coverage — it would benefit hugely from a table-driven test suite with sample bank exports.

#### 14. Migrations are manual and not idempotent
Migrations 003–006 mutate existing data in non-reversible ways (e.g. 004 renames "Investment" → "Investment Returns"), with no down-migration and no migration tooling (Alembic/sqitch). `migrations/006_expenses_user_id.sql` requires hand-editing a UUID before running.

#### 15. Frontend logic lives in a 300-line `<script>` block in `dashboard.html`
- `excludedIds` lives in `localStorage` instead of the DB, so "excluded from chart" doesn't sync across devices.
- DOM mutation, chart state, and HTMX event listeners are interleaved.
- `MutationObserver` re-running `checkDropdownOverflow` per class change is noisy.

**Recommendation:** Extract to `static/dashboard.js`. Consider persisting `excluded` to the DB as a column on `expenses`.

#### 16. Receipt feature is half-built
`expenses.receipt_path` exists in migration 001 but no upload route, storage integration, or UI uses it. Either remove or ticket.

#### 17. `category` form value is unvalidated
`update_category` accepts any string as the category name; if it doesn't match a DB row, `category_id` silently becomes `None`. Should 400 instead.

#### 18. Race condition in CSV dedup
Two concurrent uploads of the same file can both pass the "does this row exist?" check and insert duplicates. Low impact for a single-user app, but worth a unique constraint: `UNIQUE(user_id, name, amount, date)`.

---

## Recommendations Summary

| # | File | Change |
|---|------|--------|
| 1 | `app/database.py`, new migration | Stop using service-role for user data; add RLS policies; thread JWT through |
| 2 | `main.py` | Require `SESSION_SECRET`; set `https_only`, `same_site` |
| 3 | `main.py`, new middleware | Add CSRF protection |
| 4 | `app/expenses.py` | Cap upload size; validate MIME |
| 5 | `app/expenses.py` | Batch dedup + insert |
| 6 | migrations | Add `user_id` to `categories` |
| 7 | `app/expenses.py` | Escape HTML in `update_category` response |
| 8 | new migration | `expenses.date` → `DATE` |
| 9 | new migration | Add composite indexes |
| 10 | `app/auth_deps.py` (new) | Consolidate auth into a dependency |
| 12 | `templates/dashboard.html` | Pin + SRI on CDN scripts |
| 13 | `tests/` | Add pytest suite, especially for `parse_csv_statement` |
| 14 | tooling | Introduce Alembic or supabase migrations CLI |

---

## Next-Steps Checklist

**Before merging this PR (or a follow-up security PR):**
- [ ] Fail-fast on missing `SESSION_SECRET`; set cookie flags
- [ ] Add CSRF protection middleware
- [ ] Cap statement upload size (e.g. 5 MB)
- [ ] HTML-escape the `update_category` response
- [ ] Add SRI to CDN `<script>` tags

**Short-term (next iteration):**
- [ ] Write pytest cases for `parse_csv_statement` (per-bank fixtures)
- [ ] Set up GitHub Actions: lint (ruff), type-check (mypy), test
- [ ] Batch the import loop into 1 select + 1 insert
- [ ] Migrate `expenses.date` to `DATE` and add indexes
- [ ] Centralize `_require_auth` as a FastAPI dependency

**Medium-term (architecture):**
- [ ] Replace service-role data access with JWT-scoped clients + RLS policies
- [ ] Per-user categories
- [ ] Adopt a migration tool (Alembic / supabase CLI) with reversible migrations
- [ ] Move dashboard JS out of the template; persist "exclude from chart" server-side
- [ ] Remove or implement the dormant `receipt_path` feature