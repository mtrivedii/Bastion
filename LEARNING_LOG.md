# Learning Log

This file exists so the plain-English explanations behind each step of this
project don't just live in a chat and disappear. Every time a step gets
explained, it gets written down here — what we did, why, and what it
actually proved. Two purposes: a way to look back and remember what I
already learned instead of re-deriving it, and a real artifact for
interviews ("I documented my own learning as I built this").

Entries are in the order they happened, grouped by phase.

---

## Phase 1: Secure Delivery Pipeline

### Step 1 — Building the app core

**The problem being solved:** software projects depend on a lot of open
source packages, and some of those packages have known security holes.
The app's job is: given a list of packages a project uses, say which ones
have known problems.

**What an SBOM is:** SBOM = "software bill of materials." Literally a
list of every package (name, version, source) that makes up a piece of
software, written as a JSON file. This project accepts the CycloneDX
format specifically, because that's what Syft (the tool generating SBOMs
in the CI pipeline) produces by default — the app and the pipeline speak
the same format with no conversion step needed.

**What happens step by step:**

1. **Upload.** The app reads the SBOM JSON, pulls out every package's
   name, version, and ecosystem (ecosystem = which language/package
   manager it's from — the same package name can exist in Python, Node,
   Java, etc., so this matters). Saves it to the database, hands back an
   ID.
2. **Scan.** The app takes every package from that submission and asks
   OSV.dev, a free public vulnerability database, whether any of them
   have known problems.
3. **Report.** The app returns which packages have issues, how severe,
   and a summary.

**Why the database has four tables:**

- `sbom_submissions` — records that an SBOM was uploaded, when, and the
  current scan status.
- `packages` — every individual package from that SBOM.
- `vulnerabilities` — a local cache of vulnerability details already
  fetched from OSV.dev, so repeat scans don't re-fetch the same thing.
- `findings` — links a package to a vulnerability, records when it was
  found, and — this is the important one — when it stopped showing up in
  a later scan (`resolved_at`). That field is what gives the Phase 5
  report a real "time to remediate" number, which only works if it's
  being recorded from Phase 1 onward, not backfilled in December.

**The OSV.dev integration, the part with actual design decisions:**

Querying OSV.dev one package at a time would mean one network call per
package — slow, and rude to a free public service. Instead:

- `POST /v1/querybatch` checks up to 1000 packages in a single request.
  But it only returns bare vulnerability IDs (like `GHSA-xxxx`), not full
  details.
- For any ID not seen before, `GET /v1/vulns/{id}` is called to
  "hydrate" it — get the actual summary and severity.
- Once an ID is hydrated, it's cached in the `vulnerabilities` table
  permanently. Future scans (from any submission) reuse the cache instead
  of asking OSV.dev again. Over time, most lookups get answered locally.
- Every call is wrapped in retry + exponential backoff for timeouts and
  5xx errors — but NOT for 4xx errors, since retrying a bad request just
  gets the same bad result again. This matters for a real-world reason:
  OSV.dev is a free service and can be briefly slow or flaky, and the app
  needs to handle that without falling over.

**The endpoints:** upload, trigger scan (runs in the background so the
caller doesn't wait), get findings, and a health check (built now even
though it's not used yet, because Kubernetes will need it in Phase 2).

---

### Step 2 — The 18-test suite, explained

Three layers of the app get tested separately, so a failure points
directly at what broke instead of requiring a guess across the whole
system.

**Shared setup (`conftest.py`):** every test gets a fresh, empty,
in-memory database, thrown away afterward. Nothing leaks between tests.

**Group 1 — `test_sbom_parsing.py` (does the app read the file
correctly?)** Pure input-in, output-out logic, no database or network.
Covers: a known ecosystem parses correctly, an unknown purl type doesn't
crash (just stores `ecosystem: None`), a component missing a version gets
silently skipped rather than blocking the whole upload, a component
missing a purl entirely still works, invalid JSON raises a clear error,
and valid JSON that isn't actually a CycloneDX file raises a clear error.
Theme: bad input fails predictably, not randomly.

**Group 2 — `test_osv_client.py` (does the OSV.dev integration behave,
including when things go wrong?)** Uses `respx` to fake HTTP responses
instead of hitting the real internet — fast, and lets failure scenarios
get tested on purpose. Covers: a batch query correctly matches results
back to the right package, hydration returns the full record, a call
that fails once with a 500 then succeeds on retry actually gets retried
(proving the retry logic really works, not just that it's written),
a call that fails repeatedly eventually gives up after 3 tries instead of
retrying forever, and a 400 (bad request, our fault) is NOT retried —
only counted once.

**Group 3 — `test_endpoints.py` (does the whole API work end to end?)**
Sends real requests into the app in-process. Covers: uploading a valid
SBOM returns 201 with the right data, uploading garbage returns 400,
asking about a submission that doesn't exist returns 404 (both for
findings and for triggering a scan), triggering a scan returns 202
immediately without waiting (proving the background-task pattern works —
this test also fakes the OSV.dev response, since triggering a scan kicks
off a real network call otherwise), findings are correctly empty before
any scan runs, and the health check responds.

---

### Step 3 — Verifying against real Postgres

**Why this mattered:** every test up to this point ran against SQLite —
fast for automated tests, but not what the app actually runs on in
Kubernetes, where it talks to Postgres. Different database engines don't
behave identically (timestamps, connection handling, type strictness),
so "all tests pass" wasn't proof the app works in its real target
environment.

**What was done:** installed a real Postgres 16 server, pointed the app
at it using the same `DATABASE_URL` environment variable the app already
reads (nothing new had to be built for this), ran the app's real startup
logic to create the tables, called the actual API endpoints, and then —
the important part — went behind the app's back and queried Postgres
directly with `psql` to confirm the raw tables and rows actually looked
right, rather than just trusting the API's response codes.

**What it proved:** the data model and upload logic hold up against the
real database engine, including the async Postgres driver (`asyncpg`)
and timestamp defaults.

**What it didn't prove:** the scan step against real Postgres — that
still needs real internet access to OSV.dev, which this working
environment can't reach. Worth confirming once, somewhere with normal
internet access, rather than assuming it'll just work.

---

---

### Step 4 — Fixing a real design gap before seeding a vulnerability

**What I was about to do:** add a genuinely vulnerable package to a demo
SBOM, scan it, fix it, rescan, and confirm the finding shows as resolved
— proving the "caught and fixed" story for the Phase 5 report.

**What stopped that plan:** the `resolved_at` logic only compared
findings *within the same submission*. But the real pipeline uploads a
brand-new SBOM on every CI run — a new submission, with entirely new
`Package` rows, every time. Nothing ever looked at a previous
submission's findings when scanning a new one. So the actual flow this
project depends on (commit with a vulnerability → fix committed → next
CI run's scan shows it resolved) would never have worked. It would have
looked fine in a single-submission demo and then silently failed the
moment real CI ran twice.

**The fix:** findings are now matched by the package's **name and
ecosystem**, not by the database row ID. A database row ID is only ever
valid for one submission; the name and ecosystem (e.g. "pyyaml" +
"PyPI") are what actually identify the same real-world dependency across
two different scans taken on two different days. When a later scan of
the same dependency no longer reports a vulnerability that was
previously open, that finding now gets marked resolved — even though the
two scans never shared a database row.

**One thing this doesn't yet handle, on purpose:** if a vulnerable
dependency is removed from the project entirely (rather than upgraded),
its finding stays open forever, because nothing re-checks a dependency
that's no longer in the SBOM at all. Not fixed yet — it's a real gap,
written down here rather than pretended away, and worth revisiting
before the Phase 5 metrics are treated as fully trustworthy.

**Proof the fix is real, not just claimed:** before committing to it, I
reverted the change and reran the new test against the old code —
confirmed it actually fails (`resolved_at` stays `None`) on the old
logic, and passes on the new logic. A test that can't fail isn't proving
anything.

**The actual seed:** `PyYAML` version 5.3, which has a real, public,
well-documented vulnerability — `CVE-2020-14343` / `GHSA-8q59-q68h-6hv4`,
arbitrary code execution via `full_load()`, fixed in version 5.4. Two
demo SBOM files now exist in `demo/`: `seed_vulnerable_sbom.json`
(pyyaml 5.3) and `seed_fixed_sbom.json` (pyyaml 6.0, patched).

**To run the real end-to-end proof** (needs actual internet access to
OSV.dev, which this working environment doesn't have):

```bash
uvicorn app.main:app --reload &

# Upload the vulnerable version, note the returned "id"
curl -X POST http://localhost:8000/sboms \
  -F "file=@demo/seed_vulnerable_sbom.json;type=application/json"

curl -X POST http://localhost:8000/sboms/<id>/scan
sleep 3
curl http://localhost:8000/sboms/<id>/findings | python3 -m json.tool
# expect: GHSA-8q59-q68h-6hv4, resolved_at: null

# Upload the fixed version as a new submission, note its new "id"
curl -X POST http://localhost:8000/sboms \
  -F "file=@demo/seed_fixed_sbom.json;type=application/json"

curl -X POST http://localhost:8000/sboms/<new_id>/scan
sleep 3
curl http://localhost:8000/sboms/<id>/findings | python3 -m json.tool
# expect: same finding, resolved_at now has a real timestamp
```

This is also your first real discovered_at/resolved_at data point for
the Phase 5 report.

---

---

### Step 5 — Building and smoke-testing the Docker image

**What was verified:** the multi-stage Dockerfile actually builds into a
runnable image, the app starts correctly inside it, and the core API
endpoints work against a containerized process.

**The multi-stage build, and why it matters:**

The Dockerfile has two stages. The builder stage installs all Python
packages into an isolated virtualenv at `/venv`. The final stage starts
from the same base image but copies only `/venv` -- no pip, no build
tools, no compiler. This keeps the shipped image as small as possible
(322 MB in this case) and removes tooling that an attacker could use if
they found a path into the container. The build took about 30 seconds
on first run; subsequent builds that only change app code are much
faster because Docker caches the dependency layer and only re-runs the
layers that changed.

**The bug that was found, and what it taught:**

The first run failed at startup with `sqlite3.OperationalError: unable
to open database file`. The root cause: `WORKDIR /app` in the
Dockerfile creates the directory as the current build user, which is
root. The app runs as `appuser` (UID 1000) and the SQLite fallback
tries to write `drydock.db` into `/app/`. Root owns that directory;
appuser can't write there.

The fix is one line before the `USER` switch:
```
RUN chown -R appuser:appuser /app
```
This transfers ownership so the non-root process can write to its own
working directory. It's a classic Docker pitfall: switching to a
non-root user doesn't automatically give that user write access to
directories the build created as root. You have to transfer ownership
explicitly.

Note that in Kubernetes (Phase 2 onward), `DATABASE_URL` will always
be set to a Postgres connection string via a Secret, so the SQLite
fallback never runs there. But the `chown` is still correct because
any process should own its workdir, and it makes local dev and the
smoke test work without needing an external database.

**What the smoke test covered:**

1. `docker build` completes cleanly (exit 0, 322 MB final image).
2. `docker run` starts the process as UID 1000 (`appuser`), not root.
3. `GET /health` returns `{"status": "ok"}` -- confirms the server is
   listening and the lifespan startup hook (which creates the database
   tables) succeeded.
4. `POST /sboms` with the seed SBOM file returns HTTP 201 with
   `package_count: 1` and `scan_status: pending` -- confirms
   multipart file upload parsing, SBOM parsing, and the database write
   all work inside the container.
5. `GET /sboms/1/findings` returns empty findings and
   `last_scanned_at: null` -- correct pre-scan state.

The scan step (`POST /sboms/1/scan`) was not tested in the container
because it needs real internet access to OSV.dev. That was already
documented as a known gap in Step 3. The smoke test confirms everything
except the external network call.

**Base image vulnerabilities:**

The IDE's Docker linter flagged `python:3.12-slim` as containing 1
critical and 2 high CVEs in the base image layers. This is expected
and deliberately left for the pipeline to handle: Trivy is the planned
tool for this in Phase 1's GitHub Actions workflow. Seeing it flagged
early confirms Trivy will have real findings to report, which is the
point of including it. The fix when the pipeline is built will be to
scan the image in CI and either pin to a patched digest or accept
known base-image findings with a documented exception.

---

## Phase 1 — Still to do

- [x] Fix finding-resolution to track dependencies across submissions
- [x] Confirm the Docker image actually builds locally (done, one bug fixed)
- [ ] Run the seed-and-fix demo against real OSV.dev (commands in Step 4)
- [ ] Build the GitHub Actions pipeline (lint, pytest, Bandit, pip-audit,
      Trivy, Syft SBOM, Cosign signing, push to GHCR)
- [ ] Write the STRIDE threat model, scoped to what exists right now
      (app + pipeline only -- not the AWS pieces, which don't exist yet)
- [ ] Known gap, not urgent: a removed (not upgraded) vulnerable
      dependency never auto-resolves
