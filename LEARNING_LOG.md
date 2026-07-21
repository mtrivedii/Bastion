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

---

### Step 6 -- Building the GitHub Actions CI/CD pipeline

**File:** `.github/workflows/ci.yml`

The pipeline runs on every push to `main` and on every pull request
targeting `main`. It's a single job with ten stages in sequence, and
every stage must pass before the next one runs. The push and signing
steps at the end are conditional: they only execute on a push to
`main`, not on pull requests. This means a pull request gets the full
test and security scan, but nothing is published until the code is
actually merged.

---

**Before writing anything: looking up action versions**

Every action used in the pipeline was looked up against the current
GitHub Marketplace releases rather than assumed from memory. These
versions change often and a stale reference is a common way pipelines
silently break or regress. Confirmed versions used:

| Action | Version | Notes |
|--------|---------|-------|
| `actions/checkout` | `@v4` | v7 released July 20, 2026 -- too new |
| `actions/setup-python` | `@v5` | same reasoning |
| `docker/setup-buildx-action` | `@v4` | confirmed in build-push README |
| `docker/build-push-action` | `@v7` | confirmed latest stable |
| `docker/login-action` | `@v4` | confirmed latest stable |
| `aquasecurity/trivy-action` | `@v0.36.0` | pinned, see security note below |
| `anchore/sbom-action` | `@v0.24.0` | confirmed latest |
| `sigstore/cosign-installer` | `@v4.1.2` | confirmed, installs cosign 3.0.6 |

`actions/checkout` and `actions/setup-python` moved to v7 the day
before this pipeline was written (July 20, 2026). v7 uses Node.js 24
as its runtime. v4/v5 use Node.js 20. GitHub has announced Node 20
deprecation but hasn't removed it -- so v4/v5 still work; they may
eventually produce deprecation warnings in the logs, at which point
upgrading to v7 is a one-line change.

`trivy-action` is pinned to a specific version rather than a floating
`@v0` major tag for a specific reason -- see the security note below.

---

**The supply chain attack on trivy-action (March 2026)**

This came up directly in research for this step. In March 2026 a
threat actor used compromised credentials to force-push malicious code
into 76 of 77 version tags in `aquasecurity/trivy-action`. Any
workflow pinned to an old mutable tag (e.g. `0.28.0` without the `v`
prefix) was executing credential-stealing malware before any real scan
ran. The attack harvested SSH keys, cloud credentials, and tokens from
CI environments.

The safe response was two things: Aqua Security migrated to
`v`-prefixed tags (`v0.35.0` instead of `0.35.0`) for all releases
from that point, and they published `v0.35.0` as the first clean
release post-incident. The latest safe version is `v0.36.0`, which is
what this pipeline uses.

The lesson for supply chain security: mutable version tags (including
floating major-version tags like `@v0`) are trust-on-update -- you're
trusting that whoever controls that tag won't change what it points
to. Pinning to a commit SHA is the only way to guarantee the code you
reviewed is the code that runs. For this portfolio pipeline, using the
specific `v0.36.0` tag is reasonable; the highest-paranoia approach
would be `aquasecurity/trivy-action@<sha>`. Worth knowing both exist
and why one is stricter.

---

**Stage 1: checkout and Python setup**

`actions/checkout` fetches the repository code onto the runner.
`actions/setup-python` installs Python 3.12 and sets it as the
active version. The `cache: pip` option caches the pip download cache
between runs, keyed to `requirements.txt`, so the actual package
downloads are skipped on runs where the file hasn't changed.

The application dependencies (`requirements.txt`) and the CI-only
tools (`ruff`, `bandit`, `pip-audit`) are installed in separate steps
so they're easy to tell apart. The CI tools are not included in
`requirements.txt` because they're not needed inside the Docker image
-- only on the runner during testing.

---

**Stage 2: Lint (ruff)**

`ruff check .` runs static analysis across all Python files in the
repo. Ruff's default rule set covers PEP 8 style errors (E rules) and
pyflakes -- unused imports, undefined names, etc. (F rules). It
excludes the `venv/` directory by default, so no configuration file
is needed for this project.

Lint runs before tests because it's faster. If there's a syntax error
or a clearly broken import, you want to know in five seconds, not
after the tests have had time to run.

---

**Stage 3: Tests (pytest)**

`pytest` runs the full test suite. The `pytest.ini` file sets
`asyncio_mode = auto` which is what the async test functions need.
The tests use an in-memory SQLite database (set up in `conftest.py`)
so there's no external service dependency and no test isolation
problems.

Tests run after lint because lint catches things that would also cause
tests to fail, but faster. Both gates need to pass.

---

**Stage 4: Bandit (static security analysis of Python source)**

Bandit reads the `app/` directory and looks for known insecure
patterns in the Python code itself: things like hardcoded passwords,
use of weak crypto, shell injection via `subprocess`, disabling of TLS
verification, and about 40 other categories. It's reading source code,
not running it.

This stage is deliberately placed after tests but before the Docker
build. Tests confirm the code is correct; Bandit confirms it doesn't
have obvious security defects in the source. If Bandit finds
something, fixing it before building the image is cleaner than
building and then having to rebuild.

`bandit -r app/` scans only the application code, not the tests.
Bandit's B101 rule flags `assert` statements (common in tests, risky
in production code), so scanning the test files would produce noise.

---

**Stage 5: pip-audit (dependency CVE scan)**

`pip-audit -r requirements.txt` checks every package listed in
`requirements.txt` against the Python Packaging Advisory Database
(PyPA). It's asking: "do any of the packages this app depends on have
known vulnerabilities right now?"

The `-r requirements.txt` argument scans the declared dependencies,
not the full runner environment (which also includes `ruff`, `bandit`,
`pip-audit` itself, and their transitive deps -- scanning those would
add noise that isn't relevant to what actually ships).

pip-audit complements Trivy (stage 7): pip-audit checks the Python
dependency declarations; Trivy checks the final built image including
OS packages. Between them, they cover both layers of the dependency
tree.

---

**Stage 6: Docker build**

Three things happen here:

1. **Lowercase the image name.** GHCR requires all image names to be
   lowercase. `github.repository` returns the owner/repo name as it
   exists on GitHub, which preserves the repository's actual casing
   (e.g. `mtrivedii/Bastion`). The `tr '[:upper:]' '[:lower:]'`
   command converts it to `mtrivedii/bastion` and writes it to
   `$GITHUB_ENV` so subsequent steps see the corrected value.

2. **Set up Docker Buildx.** Buildx is Docker's extended build
   subsystem (BuildKit). `docker/build-push-action` requires it, and
   `docker/setup-buildx-action` creates and activates a Buildx
   builder. On GitHub's `ubuntu-latest` runners it's already installed
   but not necessarily activated as the default builder.

3. **Build the image.** `docker/build-push-action` with `push: false,
   load: true` builds the image and loads it into the local Docker
   daemon on the runner -- but does not push it to any registry. The
   image is tagged with `ghcr.io/...:<git-sha>`. Using the commit SHA
   as the tag means every image is unambiguously traceable to an exact
   commit. The `cache-from: type=gha` and `cache-to: type=gha,mode=max`
   lines use GitHub Actions' built-in cache to store Docker layer
   cache between runs, which makes repeated builds significantly faster
   when only the app code changes (the heavy dependencies layer is
   already cached).

The image is built at this point but not yet pushed. Stages 7 and 8
scan it while it's still local. This is intentional: scan first, push
only after all gates pass. Nothing reaches the registry until it's
been checked.

---

**Stage 7: Trivy (image vulnerability scan)**

Trivy scans the built image for known CVEs in both OS packages
(Debian packages in the `python:3.12-slim` base) and library packages
(Python packages in the virtualenv). It produces a table of findings
and exits with code 1 if any CRITICAL or HIGH severity issues are
found.

The `ignore-unfixed: true` setting is important. It means Trivy will
only fail the build for vulnerabilities that have a fix available
upstream. A CVE in a Debian package that has been patched in a newer
package version will still fail the build (we could fix it by
rebuilding from a newer base). A CVE where the Debian maintainers
haven't released a fix yet is reported in the output but doesn't block
the pipeline -- there's nothing to do about it.

This gives the pipeline a meaningful gate: it blocks when there's
something we can actually fix (an outdated base image, an outdated
Python dependency), but doesn't stay permanently broken because of
unpatched upstream issues.

The IDE flagged `python:3.12-slim` as having known CVEs when the
Dockerfile was written (Step 5). The first real Trivy run in CI will
show exactly which ones, and whether any have fixes available.

---

**Stage 8: Syft / anchore/sbom-action (SBOM generation)**

The `anchore/sbom-action` runs Syft internally to generate a CycloneDX
JSON SBOM from the just-built image. The format is `cyclonedx-json`,
which is exactly the format this application's own `/sboms` endpoint
accepts. This closes the loop on the project's stated narrative: the
pipeline generates an SBOM that the app it's building can then analyze.

The SBOM is automatically uploaded as a workflow artifact (visible in
the GitHub Actions run UI) under the name `sbom-<sha>.cdx.json`. This
creates a per-build artifact trail: every successfully scanned image
has an SBOM attached to the CI run that produced it.

SBOM generation runs after Trivy because the image needs to be clean
before we invest in documenting it.

---

**Stages 9-10: Login, push, sign (main branch only)**

These three steps all carry `if: github.event_name == 'push' &&
github.ref == 'refs/heads/main'`. On a pull request, or on a push to
any branch other than `main`, they are skipped entirely.

**Login:** `docker/login-action` authenticates to GHCR using
`github.actor` (the username of whoever triggered the workflow) and
`secrets.GITHUB_TOKEN` (a short-lived token GitHub automatically
provides to every workflow run). No stored credentials needed.

**Push:** `docker push` uploads the image that was built and scanned
in earlier steps. The image is already in the local daemon; the push
is a transfer to GHCR. Because all the security gates have already
passed at this point, what gets pushed is the same image that was
scanned.

**Cosign keyless signing:** `sigstore/cosign-installer` downloads the
`cosign` binary (v3.0.6 in this case). Then `cosign sign --yes <image>`
signs the image using GitHub's OIDC token.

How keyless signing works: instead of a private key that has to be
stored somewhere and could be leaked, cosign requests a short-lived
signing certificate from Sigstore's Fulcio certificate authority. The
request includes a GitHub OIDC token that proves "this is a GitHub
Actions run from workflow X at commit Y in repo Z." Fulcio issues a
certificate valid for a few minutes, cosign uses it to sign, and the
signature and certificate go into Sigstore's Rekor public transparency
log. Anyone can later verify the signature by checking Rekor -- no
private key, no secret management, full traceability.

The `id-token: write` permission at the job level is what grants the
workflow access to request that OIDC token. Without it, cosign would
fail with an auth error.

This is directly consistent with the project's principle of no
long-lived credentials (the same principle behind using GitHub OIDC
for AWS access in Phase 2 instead of stored access keys).

---

## Phase 1 — Still to do

---

### Step 7 -- Proving the security gate actually blocks bad builds

**The difference between a gate that runs and a gate that works**

A security scan that exits with code 0 regardless of findings is not
a gate, it's a log message. To establish that the pipeline is a real
gate, you need to see it both pass on clean code and fail on known-bad
code. The first successful CI run proved the pass case. This step
proves the fail case.

**What was done**

A short-lived branch `test/trivy-gate` was created off main.
`pyyaml==5.3` was added to `requirements.txt` -- the same package
used for the app-level seed-and-fix demo in Step 4. CVE-2020-14343 /
GHSA-8q59-q68h-6hv4 affects all PyYAML versions below 5.4 (arbitrary
code execution via `yaml.full_load()`). It is a real, public, fully
documented vulnerability. Adding it deliberately is safe; it only
matters if the code calls `yaml.full_load()` on untrusted input, and
no code in this project does that.

A pull request was opened against main. The PR description explicitly
stated it must not be merged and existed only to trigger CI.

**What the pipeline reported**

The run failed in 33 seconds at stage 5 (pip-audit), with this output:

```
Found 4 known vulnerabilities in 1 package
Name   Version ID             Fix Versions
------ ------- -------------- ------------
pyyaml 5.3     PYSEC-2020-96  5.3.1
pyyaml 5.3     PYSEC-2021-142 5.4
pyyaml 5.3     PYSEC-2021-142 5.4
pyyaml 5.3     PYSEC-2020-96  5.3.1
Process completed with exit code 1.
```

`PYSEC-2020-96` is the PyPA advisory database identifier for
CVE-2020-14343 (the `full_load()` code execution issue, fix: 5.3.1).
`PYSEC-2021-142` is a separate PyYAML vulnerability that wasn't fixed
until 5.4. pip-audit found both.

**Why pip-audit caught it, not Trivy**

pip-audit runs at stage 5. Trivy runs at stage 7. Stage 6 is the
Docker build. Because every stage runs to completion before the next
one starts, and because a failing stage stops the job immediately,
the Docker build never ran. Trivy therefore never ran either -- there
was no image to scan.

This is correct pipeline behavior. pip-audit checks Python package
declarations from `requirements.txt` directly, before building
anything. It's cheaper and faster than building a Docker image and
then scanning it. Catching a bad dependency at stage 5 (in seconds)
instead of stage 7 (after a 90-second Docker build) is the whole
point of having multiple security stages ordered from cheapest to
most expensive.

In practice, pip-audit and Trivy are complementary, not redundant:
- pip-audit checks the Python dependency declarations before anything
  is built.
- Trivy checks the final built artifact -- OS packages from the base
  image, and all Python packages as actually installed. Trivy would
  catch a vulnerability that came in through a transitive dependency
  that isn't listed in `requirements.txt`, or one in the Debian base
  image layers that pip-audit has no visibility into.

A vulnerability in a direct Python dependency (like this test) will
likely be caught by pip-audit first. A vulnerability in a
base-image OS package, or introduced indirectly through the build
process, reaches only Trivy.

**What this established**

Two CI runs, two different outcomes:

| Run | Branch | Code state | Result | Stage that decided it |
|-----|--------|------------|--------|----------------------|
| 1 | main | clean | pass | all stages green |
| 2 | test/trivy-gate | pyyaml==5.3 added | fail | pip-audit, stage 5 |

A gate that only ever passes is useless -- you can't tell if it's
working or just not running. A gate that only ever fails isn't
deployable. Seeing both outcomes from real CI runs on real code is
what establishes the gate works.

The PR was closed without merging. The branch was deleted. `main`
remains clean.

---

### Step 8 -- Writing the STRIDE threat model

**File:** `THREAT_MODEL.md` (repo root)

**What threat modeling is and why it's worth doing now**

A threat model is a structured exercise that asks: what could go wrong,
and what's already in place to prevent it? STRIDE is the most common
framework for this: Spoofing, Tampering, Repudiation, Information
Disclosure, Denial of Service, Elevation of Privilege. You walk through
each category and ask whether the system has a problem there.

The reason to do this at the end of Phase 1 rather than later: the
right time to build a model is when a system is small enough to fully
understand but functional enough that there are real attack surfaces to
model. In Phase 1, the full system is the FastAPI app and the CI/CD
pipeline. After Phase 2 and 3 add Kubernetes, AWS, EKS, Helm, ArgoCD,
and a real load balancer, the system is much more complex. Starting
the threat model now captures a clean baseline.

**What's in scope**

The FastAPI application -- four endpoints, the OSV.dev integration, the
Postgres/SQLite database, the background scan task -- and the GitHub
Actions CI/CD pipeline. The document explicitly does NOT model AWS, EKS,
Kubernetes, or any Phase 2-3 infrastructure that doesn't exist yet.
Modeling infrastructure that hasn't been built would be guessing at
attack surfaces, not observing real ones.

**The 18 threats, and the honest treatment rule**

The threat model catalogs 18 specific findings across all six STRIDE
categories. The rule for writing it: honest treatment of gaps, not
sanitized spin. Two things in particular get full disclosure:

1. **No authentication on any endpoint.** Any client that can reach the
   app can upload SBOMs, trigger scans, and read all findings. There is
   no API key, no OAuth2, no token of any kind. This is documented as an
   accepted gap for a single-user portfolio demo, not silently omitted.
   The document names what the fix would be and says why it's not in
   yet.

2. **No rate limiting on uploads or scan triggers.** This is a
   denial-of-service angle on the app itself, and also against OSV.dev
   as a free public service: enough concurrent scans could make the app
   flood OSV.dev with requests. Also documented as an open gap with the
   specific fix identified (409 Conflict when a scan is already running,
   plus size limits on uploads).

**What the model found is already mitigated**

Six of the 18 findings were already mitigated before the threat model
was written -- these aren't gaps, they're existing controls worth naming:

- **TLS on OSV.dev calls** (S2): `httpx.AsyncClient` verifies
  certificates by default. OSV.dev MITM is blocked.
- **Cosign image signing** (T3): every image pushed to GHCR from the
  main branch is signed with a keyless Sigstore certificate tied to the
  pipeline's OIDC identity. A tampered image in GHCR would fail
  verification.
- **Cosign/Rekor transparency log** (R2): all signed images have an
  immutable, public record in Rekor. You can prove exactly which CI run
  produced any image.
- **Retry/backoff on OSV.dev** (D3): if OSV.dev is briefly unavailable,
  the scan fails gracefully and the app keeps serving other requests.
  It doesn't retry in a tight loop.
- **Non-root container user** (E2): code execution inside the container
  gets UID 1000, not root. Multi-stage build removes pip and build
  tools from the final image, so there's less to work with.
- **Graceful scan failure** (D3 / E2 overlap): any unhandled exception
  in the background scan task sets `scan_status = "failed"` and commits.
  The app doesn't crash or hang.

**The one partially-mitigated finding worth noting**

The CI pipeline's `id-token: write` and `packages: write` permissions
apply to the entire job, including the stages that don't need them.
A compromised third-party action that runs in the build or scan steps
could use those permissions. The correct fix is splitting into two jobs
(test-and-scan with no elevated permissions, then a separate publish
job), but that's a known improvement queued for Phase 2 when a real
deploy step makes the split natural anyway.

**What the model found are open gaps (no mitigation yet)**

Five open gaps identified -- these have documented fix paths, none of
them require architectural changes to address, and none are surprising
for a Phase 1 app:

- No TLS on the app itself (T1, I2) -- expected to be handled at
  Kubernetes ingress in Phase 2.
- No structured audit log on API operations (R1) -- no one is relying
  on audit data right now; worth building when there are real users.
- No rate limiting on uploads (D1) -- simple size check and 429 response
  at the endpoint level; queued for later.
- No rate limiting on scan triggers (D2) -- a single-line 409 check
  (if `scan_status == "scanning"`, reject) would eliminate the main
  risk; queued for later.

**What changes in Phase 3**

The threat model explicitly lists what is out of scope and why: AWS IAM,
EKS API server, Kubernetes network policy, Helm/Kyverno, ArgoCD,
Prometheus/Grafana, ECR, Terraform state. When Phase 3 is complete,
this document should be revisited -- the application-level findings
remain valid, but the runtime and delivery trust model changes
significantly once the app runs in a real AWS cluster.

---

## Phase 1 -- Still to do

- [x] Fix finding-resolution to track dependencies across submissions
- [x] Confirm the Docker image actually builds locally (done, one bug fixed)
- [x] Build the GitHub Actions pipeline (done, .github/workflows/ci.yml)
- [x] Prove the security gate blocks bad builds (done, Step 7)
- [x] Write the STRIDE threat model, scoped to what exists right now
      (done, THREAT_MODEL.md -- 18 findings, app + pipeline only)
- [ ] Run the seed-and-fix demo against real OSV.dev (commands in Step 4)
- [ ] Known gap, not urgent: a removed (not upgraded) vulnerable
      dependency never auto-resolves
