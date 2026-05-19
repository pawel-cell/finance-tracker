# Repository Audit: finance-tracker

## Executive Summary

`finance-tracker` is a small, well-organized FastAPI + HTMX personal expense tracker backed by Supabase. The code is readable, the CSV parser is thoughtfully robust to Czech bank quirks, and route modules are cleanly separated. However, the app has **several serious security issues** that should be addressed before any multi-user or production use: the service-role key is used for *all* database operations (bypassing RLS), session cookies lack hardening flags, there is no CSRF protection on state-changing endpoints, and a deploy-time default `SESSION_SECRET` of `"change-this-before-deploying"` is silently accepted. There are also some correctness risks (N+1 inserts in the importer, an XSS vector in `update_category`, race-prone dedup logic) and minor architectural smells worth cleaning up.

---

## Findings (by severity)

### 🔴 Critical

#### 1. Service-role key used for all data operations bypasses RLS
**File:** `app/database.py`, `app/expenses.py`, `app/dashboard.py`

`get_client()` returns a client built with `SUPABASE_SECRET_KEY` (service role), and the codebase relies solely on `.eq("user_id", user_id)` filters in application code to enforce tenant isolation. Migration `007_enable_rls.sql` even acknowledges this and *enables RLS without policies* — meaning RLS provides zero defense in depth. Any bug that forgets the `.eq("user_id", ...)` filter (e.g., an admin endpoint added later, or a typo) silently exposes/mutates every user's data.

**Recommendation:**
- Add proper RLS policies on `expenses` (e.g., `auth.uid() = user_id` for SELECT/INSERT/UPDATE/DELETE).
- Use a per-request **user-scoped** client — sign in via Supabase Auth, store the JWT in the session, and use it to authenticate Supabase calls so RLS is enforced. The service-role key should never reach the request path.

#### 2. `SESSION_SECRET` silently defaults to a public literal
**File:** `main.py:23`

```python
SECRET_KEY = os.environ.get("SESSION_SECRET", "change-this-before-deploying")
```

In any environment where `SESSION_SECRET` is unset (forgotten on Render, local with leaked secrets, etc.), session cookies are signed with a publicly known value, allowing trivial session forgery and impersonation of any user.

**Recommendation:** Fail fast — `SECRET_KEY = os.environ["SESSION_SECRET"]` and let the app refuse to start without it. The same pattern is already used in `database.py`.

#### 3. XSS via unescaped category name in `update_category`
**File:** `app/expenses.py` (`update_category`)

```python
return HTMLResponse(
    f'<span class="expense-category-tag" id="category-tag-{expense_id}">{tag_content}</span>'
)
```

`tag_content = category_name` comes directly from the form. While the dropdown only sends names that match seeded values, nothing on the server side validates this — a crafted HTMX request can submit arbitrary HTML that will be swapped into the DOM. (The dedicated `update_category` endpoint also doesn't verify that `category_name` is a valid category before echoing it back.)

**Recommendation:**
- Verify `category_name` exists in `categories` *before* updating, and return a 400 otherwise.
- Render via a Jinja partial or `html.escape(category_name)` rather than f-string interpolation.

### 🟠 High

#### 4. No CSRF protection on state-changing endpoints
**Files:** `app/expenses.py`, `app/auth.py`

The app uses cookie-based sessions but has no CSRF tokens on POST `/login`, POST `/upload/statement`, PUT `/expense/{id}/category`, or DELETE `/expense/{id}`. An attacker can host a page that triggers a cross-site request with the victim's cookie attached. HTMX PUT/DELETE requests with form bodies are reachable from a cross-site form.

**Recommendation:**
- Add CSRF tokens (e.g., `starlette-csrf` or `fastapi-csrf-protect`), or
- Set the session cookie to `SameSite=Strict` (see #5) and additionally validate the `Origin`/`Referer` header on state-changing routes.

#### 5. Session cookie missing hardening flags
**File:** `main.py`

`SessionMiddleware` is added without `https_only=True`, `same_site="strict"`, or `max_age`. The defaults (`same_site="lax"`, `https_only=False`) are too permissive for a production app.

**Recommendation:**
```python
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    https_only=True,
    same_site="strict",
    max_age=14 * 24 * 3600,
)
```

#### 6. N+1 queries + race condition in statement importer
**File:** `app/expenses.py` (`upload_statement`)

For each row, the importer issues:
1. A `SELECT` to check for duplicates,
2. A `SELECT` for prior-category lookup,
3. An `INSERT`.

A 500-row statement issues ~1,500 sequential round-trips to Supabase. It is both slow (likely seconds per upload) and subject to a TOCTOU race between the duplicate check and insert if a user uploads twice concurrently.

**Recommendation:**
- Add a unique constraint `(user_id, name, amount, date)` on `expenses` and use `INSERT ... ON CONFLICT DO NOTHING` (Supabase: `.upsert(..., on_conflict=...)` or a single SQL `INSERT ... SELECT`).
- Batch the prior-category lookup with a single `IN (...)` query keyed by transaction names.
- Wrap the import in a single statement, ideally a Postgres function called via RPC.

#### 7. No file size limit on statement upload
**File:** `app/expenses.py` (`upload_statement`)

`await file.read()` loads the entire upload into memory with no bounds check. A user (or attacker, given #4) can upload a multi-GB file and OOM the worker.

**Recommendation:** Cap content length explicitly (e.g., reject if `request.headers["content-length"]` > 5 MB) and/or stream-parse the CSV via `file.file` chunked reads.

### 🟡 Medium

#### 8. `categories` table is global rather than per-user
**Files:** `migrations/001`, `app/dashboard.py`

All users share one `categories` table. A second user cannot rename, hide, or add their own categories. The category dropdown is also fetched twice on each dashboard render (`dashboard.py` queries it in `_get_expenses_and_categories` and again in `expense_list_partial`).

**Recommendation:** Either scope categories per-user (add `user_id` with default seeds) or document that categories are intentionally global. Cache the category list in memory or use a Supabase view.

#### 9. `expenses.date` stored as `TEXT`, not `DATE`
**File:** `migrations/001_initial_schema.sql`

Storing ISO date strings as TEXT works because the format is sortable, but it forfeits date validation, fast range queries, and indexing semantics, and silently accepts garbage values. The dashboard JS already had to add a defensive regex filter (`/^\d{4}-\d{2}-\d{2}$/`) because of this.

**Recommendation:** Migrate to `DATE` and add an index on `(user_id, date DESC)` for the dashboard ordering.

#### 10. JSON serialization of expenses inlines all rows into HTML
**File:** `templates/dashboard.html`

`{{ expenses | tojson }}` embeds every expense in the initial HTML and feeds it into Chart.js. For users with thousands of transactions this bloats the page and prevents pagination. There's also a duplicated data path (server-rendered list + JSON dump for charts) — adding/deleting/editing requires updating both `allExpenses` (JS) and the DOM.

**Recommendation:** Add a JSON endpoint for chart data, paginate the expense list, and let the chart fetch its own data on filter changes.

#### 11. Filter category lookup is brittle
**File:** `app/dashboard.py` (`expense_list_partial`)

```python
query = query.eq("categories.name", category)
...
if category:
    expenses = [e for e in expenses if e.get("categories")]
```

Filtering on a joined relationship in PostgREST returns *all* parent rows with `categories=null` for non-matches. The code corrects for this in Python, but this is fragile and means filtering doesn't actually push down to the DB.

**Recommendation:** Look up `category_id` first and filter `.eq("category_id", id)` directly.

#### 12. No tests, no linter, no type-checker configured
There are no `tests/`, no CI workflow, no `ruff`/`mypy` config visible. The CSV parser in particular has many edge-cases (encodings, delimiters, decimal separators, split debit/credit) that absolutely warrant unit tests.

**Recommendation:** Add `pytest` tests for `parse_csv_statement` with fixtures for each Czech bank format; add `ruff` and `mypy --strict` to a GitHub Actions workflow.

### 🟢 Low / Nits

- **`app/auth.py`:** Login error is generic but returns 401 with a full HTML page — fine for browsers, but inconsistent with HTMX partial-error patterns elsewhere. Consider rate-limiting login attempts.
- **`app/dashboard.py`:** `RedirectResponse` returned from `_require_auth` for an HTMX partial route results in a 303 that HTMX likely won't follow correctly. Return `HX-Redirect` header instead for HTMX requests.
- **`migrations/006_expenses_user_id.sql`** contains a literal `<YOUR_USER_UUID>` placeholder — fine as a one-off, but document this clearly or remove the migration from version control.
- **`main.py`:** `if __name__ == "__main__":` uses `reload=True` and binds `0.0.0.0` — exposes the dev server on LAN. Use `127.0.0.1` by default.
- **CDN dependencies:** `htmx.org@2.0.4` and `chart.js@4` are loaded from unpkg/jsdelivr without SRI hashes. Add `integrity="sha384-..."` or self-host.
- **`expenses.py`:** `_parse_amount` mutates `cleaned` but doesn't normalize Unicode minus (`−`, `‐`) which some banks use.
- **`templates/partials/expense_list.html`:** `{{ expense.date[8:10] }}/{{ expense.date[5:7] }}/...` relies on a specific string format — fragile if migrated to DATE (see #9).
- **CSS:** `static/dashboard.css` has duplicated `max-height: 260px; overflow-y: auto;` in `.filter-dropdown`.

---

## Next Steps Checklist

**Before any multi-user use:**
- [ ] Replace `SESSION_SECRET` default with a hard env-var requirement (`main.py`).
- [ ] Add RLS policies on `expenses` and switch data-path to user-scoped Supabase JWT client.
- [ ] Escape/validate `category_name` in `update_category` (`app/expenses.py`).
- [ ] Add CSRF protection or strict-SameSite + Origin check.
- [ ] Configure session cookie: `https_only`, `same_site="strict"`, `max_age`.
- [ ] Cap statement upload size (≤ 5 MB) and stream-parse if larger.

**Quality & correctness:**
- [ ] Add `(user_id, name, amount, date)` uniqueness and refactor importer to batch insert.
- [ ] Add `pytest` suite for `parse_csv_statement` covering each Czech bank format.
- [ ] Migrate `expenses.date` to `DATE`; add `(user_id, date DESC)` index.
- [ ] Add `ruff` + `mypy` + GitHub Actions CI.

**Architecture & polish:**
- [ ] Decide on per-user vs global categories; eliminate redundant lookups in dashboard routes.
- [ ] Replace `expenses | tojson` dump with a paginated JSON endpoint for charts.
- [ ] Filter expense list by `category_id` rather than via PostgREST join (`app/dashboard.py`).
- [ ] Self-host or SRI-pin HTMX and Chart.js.
- [ ] Bind dev server to `127.0.0.1` by default; document `0.0.0.0` opt-in.
- [ ] Clean up duplicated CSS rules in `static/dashboard.css`.