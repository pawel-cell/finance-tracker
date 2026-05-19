# Repository Audit: finance-tracker

## Executive Summary

`finance-tracker` is a small FastAPI + Supabase personal expense tracker with reasonable structure and clear code. However, several security and reliability issues should be addressed before this is used beyond a single-developer context. The most pressing concerns are (1) a weak default session secret that allows session forgery if not overridden, (2) **open user signup combined with shared category data and service-role DB access**, (3) missing CSRF protection on state-changing endpoints, and (4) unbounded file uploads with no size or row limits. RLS is enabled in the DB but bypassed everywhere by use of the service-role key, so all isolation depends on app-level `user_id` checks — which are mostly correct but inconsistently applied.

---

## Findings (Highest Impact First)

### 1. 🔴 Critical — Insecure default `SESSION_SECRET` allows session forgery
`main.py` falls back to a hardcoded literal if `SESSION_SECRET` is unset:

```python
SECRET_KEY = os.environ.get("SESSION_SECRET", "change-this-before-deploying")
```

If the env var is ever missing in production (typo, misconfig, local `.env` shipped accidentally), attackers can mint valid session cookies for any `user_id`/email and impersonate users. Starlette `SessionMiddleware` uses itsdangerous, which is signing-only (not encrypted); the cookie contents are also readable client-side.

**Fix:**
- Fail hard at startup if `SESSION_SECRET` is missing or short: `raise RuntimeError(...)`.
- Set `https_only=True`, `same_site="lax"`, and a sensible `max_age` on `SessionMiddleware`.
- Rotate the production secret now (current value may have been deployed accidentally).

---

### 2. 🔴 Critical — Open signup + shared global tables + service-role key
`app/auth.py` exposes a public `/signup` endpoint that creates Supabase Auth users. Combined with:

- `get_client()` using `SUPABASE_SECRET_KEY` (service-role, bypasses RLS) for **all** data ops (`app/database.py`),
- the `categories` table being **global / shared across all users** (migration 003, no `user_id`),

…any signed-up user can:
- Read all categories (fine).
- Indirectly affect other users if any future code mutates categories using user input.
- Brute-force or enumerate accounts (Supabase Auth largely mitigates this, but signup should be gated for a "single-user app").

The README and `CLAUDE.md` describe this as a "single-user app," but the code allows arbitrary registration.

**Fix:**
- Either disable `/signup` entirely (remove route, use Supabase dashboard to create the user) or gate it behind an `ALLOW_SIGNUP=true` env flag or invite token.
- Document explicitly that the service-role key must never be exposed and that RLS protection is *not* in effect at the app layer.

---

### 3. 🟠 High — No CSRF protection on state-changing endpoints
The app uses cookie-based sessions and accepts `POST`/`PUT`/`DELETE` without any CSRF token:

- `POST /login`, `POST /signup`, `POST /upload/statement`
- `PUT /expense/{id}/category`, `DELETE /expense/{id}`

Any other site the user visits while logged in can trigger expense deletion, category changes, or statement uploads via simple form posts / `fetch` (HTMX requests are not magically protected).

**Fix:**
- Add a CSRF middleware (e.g., `starlette-csrf`, or implement a double-submit token rendered into templates and validated on unsafe verbs).
- Set the session cookie `SameSite=Lax` (mitigates most but not all cases) and consider `SameSite=Strict` where workflow allows.

---

### 4. 🟠 High — Unbounded file upload (DoS / memory exhaustion)
`app/expenses.py::upload_statement` reads the entire upload into memory and then iterates row-by-row, issuing **two DB calls per row** with no cap:

```python
contents = await file.read()      # no size limit
...
for txn in transactions:           # no row cap
    existing = db.table(...).select(...)...execute()   # 1 query per row
    prior_q  = db.table(...)...execute()                # 2nd query per row
    db.table("expenses").insert({...}).execute()        # 3rd query per row
```

A 100 MB CSV (or a deeply pathological one) will OOM the worker, and even a 10k-row statement could take minutes and exhaust Supabase connection quota.

**Fix:**
- Enforce a max upload size (e.g., 5 MB) by checking `file.size` or streaming with a counter; reject early.
- Cap parsed transactions (e.g., 5000).
- Replace the per-row dedup loop with a single batched query: fetch existing `(name, amount, date)` tuples for the user once into a `set`, then do **one** bulk `insert` call.
- Add an overall timeout.

---

### 5. 🟠 High — `category_id` not constrained to current user / global table abuse
`PUT /expense/{id}/category` (`app/expenses.py`) looks up category by **name only**:

```python
cat_result = db.table("categories").select("id").eq("name", category_name).execute()
```

Since the form value is user-controlled (HTMX `select`), and categories are global, this is acceptable today — but it relies on uniqueness of `name` and trusts arbitrary client input. If categories ever become per-user, this query is wrong. Also, no validation that `category_name` is one of the known categories — an attacker could pass any string; if it doesn't match, `category_id` becomes `None`, which is benign but silent.

**Fix:**
- Validate `category_name` against an allowlist server-side; return 400 on unknown values.
- Ensure `expenses.id` is verified to belong to the current user **before** the update (the current `eq("user_id", user_id)` clause does this — good — but a follow-up `select` to confirm a row was actually updated and return 404 otherwise would be more robust).

---

### 6. 🟡 Medium — Date stored as `TEXT` instead of `DATE`
`migrations/001_initial_schema.sql`:

```sql
date TEXT NOT NULL,   -- stored as YYYY-MM-DD string
```

This works because the parser normalizes to ISO format, but:
- No DB-level validation; a single malformed insert poisons sorting and the dashboard JS (the template even adds a regex guard for this on the client).
- Sorts lexicographically, which only works for ISO strings — accidental future formats break ordering.

**Fix:** Migrate to `DATE`. Also consider `NUMERIC(12,2)` instead of `DOUBLE PRECISION` for `amount` to avoid floating-point rounding (e.g., `0.1 + 0.2`).

---

### 7. 🟡 Medium — Missing error handling around DB calls
Throughout `app/expenses.py` and `app/dashboard.py`, `.execute()` results are dereferenced (`.data[0]["id"]`) without checking for empty results or transport errors. A transient Supabase outage will produce a 500 with raw traceback; an unexpectedly empty result will raise `IndexError`.

**Fix:**
- Wrap DB calls in helpers that translate errors to friendly responses.
- Add a global exception handler in `main.py` that returns a clean error page/HTMX fragment without leaking stack traces.

---

### 8. 🟡 Medium — `request.session["user"]` and `user_id` not re-validated
The session cookie's `user_id` is trusted indefinitely. Once issued, there's no check that the user still exists in `auth.users` or hasn't been disabled. Combined with the weak default secret (#1), this expands the impact of any cookie compromise.

**Fix:**
- Store a short-lived session, refresh on activity, and optionally re-verify the user against Supabase periodically.
- Implement a logout-all / session invalidation mechanism (e.g., a `session_id` claim checked against a server-side store on sensitive operations).

---

### 9. 🟡 Medium — CDN scripts loaded without SRI
`templates/dashboard.html`:

```html
<script src="https://unpkg.com/htmx.org@2.0.4"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
```

These are loaded over HTTPS, but with no `integrity=` (SRI) attribute. A CDN compromise or version-pin slip would execute arbitrary JS in an authenticated session.

**Fix:**
- Pin exact versions and add `integrity` + `crossorigin="anonymous"`.
- Better: vendor the scripts under `static/` and remove the external dependency.

---

### 10. 🟢 Low — Information leakage in flash/error messages
`app/auth.py` surfaces Supabase's raw `e.message` in the signup error path. Most Supabase Auth errors are safe to show, but this leaks internal phrasing and could in future leak rate-limit/internal state.

**Fix:** Map known error types to user-facing strings; log the raw message server-side.

---

### 11. 🟢 Low — `expense_list_partial` filtering is inefficient and brittle
```python
expenses = query.execute().data
if category:
    expenses = [e for e in expenses if e.get("categories")]
```

The Supabase join returns *all* rows with `categories: null` for the non-matching ones, which is filtered client-side. For users with many expenses, this is wasteful and surprising.

**Fix:** Switch to filtering at the DB by `category_id` (do one lookup of category id by name, then `.eq("category_id", id)`), or use `categories!inner(name)` to perform an inner join.

---

### 12. 🟢 Low — Hardcoded reload/dev defaults in `main.py`
```python
uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
```

Binds to all interfaces with `reload=True` even in `python main.py`. The Render deploy uses a separate command, so this is dev-only — but consider gating on `if os.getenv("ENV") == "dev"`.

---

## Pragmatic Next-Steps Checklist

- [ ] **Fail-fast on `SESSION_SECRET`**: raise at startup if unset or `<32` chars. Rotate prod secret. Configure `SessionMiddleware(https_only=True, same_site="lax", max_age=...)`. *(main.py)*
- [ ] **Gate `/signup`** behind env flag or invite token; remove if single-user only. *(app/auth.py)*
- [ ] **Add CSRF protection** to all `POST/PUT/DELETE` endpoints; render token into templates. *(main.py, templates/*)*
- [ ] **Enforce upload limits**: max body size (~5 MB) and max parsed rows (~5k); reject early with a clean error. *(app/expenses.py)*
- [ ] **Bulk-dedupe and bulk-insert** statement rows in 1–2 queries instead of 3 per row. *(app/expenses.py)*
- [ ] **Validate `category_name`** against an allowlist on `PUT /expense/{id}/category`. *(app/expenses.py)*
- [ ] **Migrate `expenses.date` to `DATE`** and `amount` to `NUMERIC(12,2)`; add a new `migrations/008_*.sql`. *(migrations/)*
- [ ] **Pin + SRI-hash** htmx and Chart.js, or vendor them under `static/`. *(templates/dashboard.html)*
- [ ] **Add a global exception handler** + structured logging so DB/Supabase errors don't leak tracebacks. *(main.py)*
- [ ] **Refactor `expense_list_partial`** to filter at the DB by `category_id`. *(app/dashboard.py)*
- [ ] **Add tests**: at minimum, parser tests for `parse_csv_statement` with each bank format, plus auth/authorization tests confirming user A cannot read/modify user B's expenses by ID.
- [ ] **Add basic rate limiting** on `/login`, `/signup`, `/upload/statement` (e.g., `slowapi`).
- [ ] **Document the threat model** in `CLAUDE.md`: service-role key is used; RLS is enabled but not relied on; isolation = app-level `user_id` filters.