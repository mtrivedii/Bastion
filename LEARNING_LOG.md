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

## Phase 1 — Still to do

- [ ] Seed a real vulnerable dependency on purpose, let the pipeline
      catch it, fix it, and record discover/resolve timestamps
- [ ] Build the GitHub Actions pipeline (lint, pytest, Bandit, pip-audit,
      Trivy, Syft SBOM, Cosign signing, push to GHCR)
- [ ] Write the STRIDE threat model, scoped to what exists right now
      (app + pipeline only — not the AWS pieces, which don't exist yet)
- [ ] Confirm the Docker image actually builds locally
