# 🐛 bugbounty  [![ci](https://github.com/Gethubsathvik/Bug_Bounty_Toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/Gethubsathvik/Bug_Bounty_Toolkit/actions/workflows/ci.yml)

[![Go](https://img.shields.io/badge/go-1.26%2B-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev/)
[![CI](https://github.com/bbtoolkit/bugbounty/actions/workflows/ci.yml/badge.svg)](https://github.com/bbtoolkit/bugbounty/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-see%20repo-blue?style=flat-square)](#-scope)
[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.png)](https://console.cloud.google.com/cloudshell/open?git_repo=https://github.com/bbtoolkit/bugbounty)

**[ ☁️ Open in Google Cloud Shell →](https://console.cloud.google.com/cloudshell/open?git_repo=https://github.com/bbtoolkit/bugbounty)**

A recon and assessment toolkit for authorised bug bounty work. It takes a
declaration of what may be tested, checks everything against it before sending a
packet, and turns what it observes into a report a researcher can hand in.

It is a reporting tool, not an exploitation tool. Nothing here attempts to
exploit a vulnerability: every finding is a lead derived from observation, and
anything that would need a human to confirm says so instead of pretending to be
a result.

## 🛡️ What it will not do

These are properties of the code, not aspirations. Each is enforced where the
decision is made, and each has a test that fails if the enforcement is removed.

- **It will not touch a target outside the declared scope.** There is no flag
  that widens scope for a single run. The only scope inputs are the scope file
  and `--exclude`, and `--exclude` can only remove targets, never add them.
- **It will not disable certificate validation from a configuration file.** The
  loader rejects `insecure_skip_verify` in a file. An operator who wants it must
  pass `--insecure` on the command line, where it is visible in the shell
  history and in the run's metadata, and the run is recorded as having run with
  verification off.
- **It will never contact a cloud metadata endpoint.** `169.254.169.254`
  carries instance credentials; reading it is theft on any asset. Setting
  `policy.allow_cloud_metadata` has no effect, and the loader warns that it was
  ignored.
- **It never stores a credential.** Free text that came from a target is
  redacted before it is persisted or rendered. A secret reflected in a response
  body cannot be recovered from the database or the report.
- **It does not report a failed run as a clean one.** A stage that could not
  run, a source that timed out, a request budget that ran out: each becomes a
  warning, and warnings appear in every output format. An empty report means
  "nothing was found", never "nothing was there".

An empty report is not a clean bill of health.

## 📦 Install

Requires **Go 1.26 or later**. Pick the instructions for your platform below —
or skip straight to one of the cloud options: [☁️ Google Cloud Shell](#-run-it-on-google-cloud-shell) and [🧪 Replit](#-run-it-on-replit) both run the full test suite with no local setup.

<details>
<summary><b>🐧 Linux</b></summary>

```bash
# Install into $GOPATH/bin (usually ~/go/bin)
go install github.com/bbtoolkit/bugbounty/cmd/bugbounty@latest
export PATH="$(go env GOPATH)/bin:$PATH"

# Verify
bugbounty version
```
</details>

<details>
<summary><b>🍎 macOS</b></summary>

```bash
# Install into $GOPATH/bin (usually ~/go/bin); works the same under Homebrew's Go
go install github.com/bbtoolkit/bugbounty/cmd/bugbounty@latest
export PATH="$(go env GOPATH)/bin:$PATH"

# Verify
bugbounty version
```
</details>

<details>
<summary><b>🪟 Windows (PowerShell)</b></summary>

```powershell
# Install into %USERPROFILE%\go\bin and put it on PATH for this session
go install github.com/bbtoolkit/bugbounty/cmd/bugbounty@latest
$env:Path += ";$(go env GOPATH)\bin"

# Persist it for future sessions (optional, needs a new shell to take effect)
[Environment]::SetEnvironmentVariable(
  "Path",
  [Environment]::GetEnvironmentVariable("Path", "User") + ";$(go env GOPATH)\bin",
  "User")

# Verify
bugbounty version
```

To build a local binary instead:

```powershell
go build -trimpath -o bugbounty.exe ./cmd/bugbounty
.\bugbounty.exe version
```
</details>

<details>
<summary><b>🤖 Android (Termux)</b></summary>

Cross-compiles cleanly for `android/arm64`; the same `go install` works, and
`$(go env GOPATH)/bin` lands in Termux's home directory.

```bash
pkg install golang
export GOOS=android GOARCH=arm64
go install github.com/bbtoolkit/bugbounty/cmd/bugbounty@latest
unset GOOS GOARCH

~/go/bin/bugbounty version
```

Note that DNS resolution on Termux is the Android resolver's, and the
`dns` stage is the one most affected by that. Everything else is unaffected.
</details>

<details>
<summary><b>🐳 Container (any platform)</b></summary>

Builds and tests in one step and runs as an unprivileged user:

```bash
docker build -t bugbounty .
docker run --rm -v "$PWD/data:/data" bugbounty scan example.com --scope scope.yaml
```
</details>

Or build from a checkout with the Makefile — note that `make` targets use
POSIX shell syntax, so on Windows run them from Git Bash or WSL, not `cmd.exe`:

```
make build          # -> dist/bugbounty
make check          # vet and test; the default target
```

---

## 🧪 Test this project

The suite is hermetic: it binds loopback servers and stands in for DNS, and it
needs no outbound network access and no credentials.

```bash
make check                      # go vet + go test; the default target
```

Or run the commands directly, which is what the Makefile does:

```bash
go vet ./...                    # static checks
go test -count=1 ./...          # full suite, cache-bypassed
go test -cover ./...            # with a coverage summary per package
gofmt -l .                      # lists anything not gofmt-clean; empty is good
```

Target a single package or test:

```bash
go test ./internal/scope/ -v
go test ./internal/pipeline/ -run TestPassiveOnly -v
```

The race detector needs cgo and a C compiler, so it is not available on a
default Windows or macOS toolchain:

```bash
make race                       # refuses to run without gcc and says so
CGO_ENABLED=1 go test -race ./...   # on Linux, macOS with Xcode CLT, or WSL
```

CI runs the suite on Linux, Windows and macOS, and the race detector on Linux
where a C compiler is available.

---

## ☁️ Run it on Google Cloud Shell

No local install, no configuration. Cloud Shell provisions Go for you.

1. Click **[Open in Cloud Shell](https://console.cloud.google.com/cloudshell/open?git_repo=https://github.com/bbtoolkit/bugbounty)** at the top of this file.
2. Run the test suite:

   ```bash
   go version
   go vet ./...
   go test -count=1 ./...
   ```

3. Build and run a dry run, which contacts nothing:

   ```bash
   go build -trimpath -o bugbounty ./cmd/bugbounty
   cp scope.example.yaml scope.yaml
   ./bugbounty scan example.com --scope scope.yaml --dry-run
   ```

> Replace the `git_repo` parameter in the button URL with your own fork URL if
> you have not published this repository under `bbtoolkit/bugbounty`.

---

## 🧪 Run it on Replit

[Replit](https://replit.com) runs the same Go toolchain in the browser, with no
account-local setup beyond the workspace itself.

**From the browser:** import the repository, then use the **Shell** tab and run
the same commands:

```bash
go vet ./... && go test -count=1 ./...
go build -o bugbounty ./cmd/bugbounty
./bugbounty version
```

**Or with a config file** — create `.replit` in the repository root:

```ini
modules = ["go"]

run = "go test -count=1 ./..."

[env]
GO111MODULE = "on"
```

Replit's runner is Linux, so the `make` targets work as written. The race
detector is not available there (no C compiler), so skip `make race`.

> Replit sandboxes outbound network access. The test suite is designed for that
> and will pass; a real `scan` against a live target will not, because the
> sandbox blocks the connection. Use Cloud Shell or a local machine for those.


## 🚀 Use

Every run starts with a scope file. It is the declaration of what may be tested,
and it is mandatory. Start from the annotated example:

```
cp scope.example.yaml scope.yaml   # then edit it
bugbounty scope check scope.yaml
```

`scope check` is the command to run before every engagement. It reports the
policy that will actually apply after the loader has clamped it, lists the
authorised and excluded targets, and prints any warning worth reading. It
contacts nothing.

Then run the assessment:

```
bugbounty scan example.com --scope scope.yaml
```

The target must be covered by the scope file. If it is not, the run stops
before anything is sent.

Useful variations:

```
# Validate everything and exit without scanning.
bugbounty scan example.com --scope scope.yaml --dry-run

# Passive only: no active stage runs and no target is contacted at all.
bugbounty scan example.com --scope scope.yaml --passive-only

# Go slower than the programme requires, which is usually the right default.
bugbounty scan example.com --scope scope.yaml --rate 2 --concurrency 2

# Run part of the pipeline, or a subset of the rules.
bugbounty scan example.com --scope scope.yaml --stage dns,http
bugbounty scan example.com --scope scope.yaml --rule http-missing-hsts

# A self-signed target, deliberately, on the command line.
bugbounty scan staging.example.com --scope scope.yaml --insecure
```

When a target is skipped and you want to know why:

```
bugbounty scope explain www.example.com --scope scope.yaml
```

### 📊 Reports

`scan` writes Markdown and JSON by default. Formats are `csv`, `html`, `json`,
`markdown`, `sarif` and `text`; SARIF imports into most CI dashboards.

```
bugbounty scan example.com --scope scope.yaml --report markdown,html,sarif
bugbounty report --format html --min-severity high
bugbounty report --run "$RUN_ID" --needs-manual
```

`report` reads from the database, so it works on a previous run without
scanning again. `--run` restricts it to one engagement; without it you get every
finding in the database, which is rarely what you want when you have more than
one client.

### 📏 Rules

```
bugbounty rules
```

Lists every finding rule with its severity and whether it needs manual
verification. Findings that need a human are marked as such in every report
format, because a report that presents an unverified lead as a confirmed
vulnerability is worse than no report.

---

## 🎛️ Command Reference (Flags)

### Global Flags (available on every command)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--config` | | string | auto | Path to configuration file; default is `~/.config/bugbounty/config.yaml` (Linux/macOS) or `%AppData%\bugbounty\config.yaml` (Windows) |
| `--profile` | | string | "" | Name of a pipeline profile to apply (profiles are defined in the config file) |
| `--output` | | string | "" | Directory to write output files into |
| `--format` | | string | `json` | Report format for commands that render: `json`, `markdown`, `html`, `sarif`, `csv`, `text` |
| `--quiet`, `-q` | `-q` | bool | `false` | Suppress progress output; errors and warnings still print to stderr |

---

### `bugbounty scan <target>` — Run an assessment

**Required:**
| Flag | Type | Description |
|------|------|-------------|
| `--scope` | string | **Required.** Path to the scope file defining what may be tested. |

**Scope modifiers:**
| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--exclude` | string | `""` | Additional file of rules to exclude; it can only narrow the scope, never widen it. |
| `--passive-only` | bool | `false` | Run no active stage; the tool contacts no target at all. Overrides the scope file's policy. |
| `--insecure` | bool | `false` | Skip TLS certificate verification. **Command line only** — the config loader rejects this setting in a file so it cannot be committed and forgotten. |

**Rate & concurrency (clamped to hard ceilings):**
| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--rate` | float64 | `0` | Requests per second; overrides the configuration. Cannot exceed the scope file's ceiling. |
| `--concurrency` | int | `0` | Maximum concurrent requests; overrides the configuration. Cannot exceed the scope file's ceiling. |
| `--timeout` | duration | `0` | Overall time limit for the run (e.g. `10m`, `1h`). |

**Pipeline control:**
| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--stage` | []string | all | Run only these stages (comma-separated): `passive-recon`, `dns`, `http`, `fingerprint`, `crawl`, `findings`, `report` |
| `--rule` | []string | all | Run only these finding rules (comma-separated). Use `bugbounty rules` to list IDs. |
| `--provider` | []string | `certtransparency` | Passive sources to use. Currently only `certtransparency` is implemented. |
| `--resume` | bool | `false` | Continue the last resumable run for this target, skipping stages it already completed. |
| `--run` | string | `""` | With `--resume`, continue this specific run ID instead of the most recent one. |

**Output:**
| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--report` | []string | `markdown,json` | Report formats to write: `csv`, `html`, `json`, `markdown`, `sarif`, `text`. |
| `--output-file` | string | `""` | Write the first report to this exact path instead of the default name. |
| `--engagement` | string | `""` | Client or programme name recorded in the report metadata. |
| `--no-db` | bool | `false` | Do not open the database; nothing is persisted. Useful for quick one-off runs. |
| `--dry-run` | bool | `false` | Validate the configuration and scope, then exit without scanning. Prints what would happen. |

---

### `bugbounty scope check <scope-file>` — Validate a scope file

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--output`, `-O` | `-O` | string | `""` | Also write the summary to this file (Markdown). |

> Run this **before every engagement**. It parses the file, clamps values to safe ceilings, and prints exactly what the run will authorise — without contacting anything.

---

### `bugbounty scope explain <target> --scope <file>` — Explain a scope decision

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--scope` | string | **required** | Scope file to consult. |

> Explains whether a target would be permitted and which rule decided. Contacts nothing.

---

### `bugbounty report` — Render stored findings

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--format` | string | `markdown` | Report format: `csv`, `html`, `json`, `markdown`, `sarif`, `text`. |
| `--run` | string | `""` | Restrict to findings from this run ID. |
| `--limit` | int | `0` | Maximum findings to include; `0` means all. |
| `--min-severity` | string | `""` | Only include findings at or above this severity (`critical`, `high`, `medium`, `low`, `informational`). |
| `--needs-manual` | bool | `false` | Only include findings that require manual verification. |

> Reads from the database, so it works on a previous run without scanning again.

---

### `bugbounty rules` — List finding rules

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--all` | bool | `false` | Include every rule regardless of severity filter. |

---

### `bugbounty config show` — Print effective configuration

No flags. Prints the resolved configuration (never secrets).

---

### `bugbounty config init [path] --force` — Write a default config file

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--force` | bool | `false` | Overwrite an existing file. |

> The file is created owner-readable only and contains no credentials — only the names of environment variables.

---

## ⚙️ Configuration

Optional, at the user config directory (`~/.config/bugbounty/config.yaml` on
Unix, `%AppData%\bugbounty\config.yaml` on Windows) or wherever `--config` points.
Every default errs towards doing less, so an absent config is safe.

```
bugbounty config init     # write a starter file, owner-readable only
bugbounty config show     # show effective settings, never a credential
```

API keys are never written to a config or scope file. The file names the
environment variable holding the credential and the value is resolved at run
time. `config show` prints the resolved provider and never the secret.

## 🔄 How a run works

Stages, in order. `--stage` runs a subset; each is independently skippable and
a failure in one does not abort the rest.

| Stage | What it does | Contacts targets |
| --- | --- | --- |
| `passive-recon` | Subdomain and certificate sources | No |
| `dns` | Records, TTLs, posture, dangling checks | Resolver only |
| `http` | Probe schemes and ports, collect headers and TLS | Yes |
| `fingerprint` | Match technology signatures | Uses what `http` gathered |
| `crawl` | Bounded crawl within scope, honouring robots | Yes |
| `findings` | Evaluate rules and correlate evidence | No |
| `report` | Render findings in the requested formats | No |

Guards that apply to every stage that touches the network:

- **Scope is checked before the connection, not after.** Redirects are
  re-checked, so a redirect cannot walk the crawl off-scope.
- **DNS answers are pinned.** A name that resolves to a different address
  between the check and the connection is refused, which closes DNS rebinding.
- **Response and header counts are bounded**, so a hostile or merely enormous
  response cannot exhaust memory.
- **Requests are capped per run**, and rate and concurrency are clamped to hard
  ceilings that no scope file can raise.
- **Method and body are controlled.** A read-only assessment does not send
  forms.

---

## 📋 End-to-End Workflow Example

Here is a complete, runnable walkthrough from an empty directory to a finished report.

### 1. Prepare the scope file

```bash
cp scope.example.yaml scope.yaml
# Edit scope.yaml to list your authorised targets.
# Minimum: change `program:` and add your domain under `scope.allowed:`.
```

```yaml
# scope.yaml (trimmed example)
version: 1
metadata:
  program: "Example Corp Bug Bounty"
  reference: "https://example.com/policy"
  operator: "your-handle"
  authorized_until: "2026-12-31"
scope:
  allowed:
    - example.com
    - "*.dev.example.com"
  excluded:
    - staging.example.com
policy:
  passive_only: false
  max_rps: 5
  max_concurrency: 5
  max_requests_per_run: 2000
  respect_robots: true
  allowed_ports: [80, 443]
sources:
  enabled: [certtransparency]
```

### 2. Validate the scope (run this every time)

```bash
bugbounty scope check scope.yaml
```

Output:
```
scope file:      scope.yaml
programme:       Example Corp Bug Bounty
reference:       https://example.com/policy
authorised until: 2026-12-31
passive only:    false
requests/second: 5.0
concurrency:     5
requests per run: 2000
respects robots: true
cloud metadata:  false
allowed:         2
excluded:        1
sources:         certtransparency

Authorised targets:
  *.dev.example.com
  example.com

Excluded:
  staging.example.com
```

If this prints `SECURITY: ... authorises nothing` or a warning you don't understand, fix the file before scanning.

### 3. Dry run (safe preview)

```bash
bugbounty scan example.com --scope scope.yaml --dry-run
```

Output:
```
dry run: the configuration and scope are usable
  target:      example.com
  in scope:    *.dev.example.com, example.com
  excluded:    staging.example.com
  passive:     false
  rate:        5.00 req/s
  concurrency: 5
  reports:     markdown, json

This run would contact the targets above. Nothing was sent.
```

### 4. Run the scan

```bash
bugbounty scan example.com --scope scope.yaml
```

Typical output:
```
wrote report-report-1725123456789012345.md
wrote report-report-1725123456789012345.json
```

The run:
1. **passive-recon** — Queries Certificate Transparency for `example.com` subdomains
2. **dns** — Resolves every discovered name, checks posture (SPF/DMARC, dangling CNAMEs)
3. **http** — Probes HTTP/HTTPS on ports 80/443, collects headers, TLS, titles
4. **fingerprint** — Matches technology signatures (servers, frameworks, CMS)
5. **crawl** — Bounded crawl from `https://example.com/`, honours `robots.txt`
6. **findings** — Evaluates every rule against the collected evidence, correlates, deduplicates
7. **report** — Renders Markdown + JSON (default) to `./report-<runID>.<ext>`

If any stage fails (e.g., a source times out), the run **continues** and the failure becomes a warning in the report. An empty report means "nothing was found," never "nothing was there."

### 5. Inspect the report

```bash
cat report-report-*.md
```

Key sections:
- **Metadata** — programme, run ID, seed, scope, exclusions, policy, timestamps
- **Summary** — counts by severity/status, manual-verification flags
- **Findings** — each with title, severity, confidence, asset, endpoint, description, evidence, remediation, references
- **Manual verification** — findings that need human confirmation are marked `_(needs manual verification)_`

### 6. Re-generate a different format later

```bash
bugbounty report --format sarif --min-severity high --run "$RUN_ID"
```

This reads the stored findings (no re-scan) and writes SARIF for CI import.

---

## 🛠️ Development

```
make check      # go vet + go test
make race       # needs a C compiler; run it in CI or a container
make fmt
```

See [🧪 Test this project](#-test-this-project) for running the suite directly
without `make`, and for the coverage and per-package invocations.

CI runs the suite on Linux, Windows and macOS, and the race detector on Linux
where a C compiler is available. The container build runs vet and the tests
before it produces a binary, so a broken build never ships as an image.

Layout:

```
.
├── cmd/
│   └── bugbounty/            # CLI entry point, command wiring
├── internal/
│   ├── config/               # config loading, secrets (env-var-only), validation
│   ├── crawler/              # bounded, scope-aware crawl (robots.txt, sitemaps)
│   ├── dns/                  # resolver, TTL cache, rebinding defence
│   ├── findings/             # rules engine, correlation, dedup, redaction
│   ├── fingerprint/          # technology signatures (headers, cookies, body)
│   ├── http/                 # HTTP client: pinning, limits, redirect checks
│   ├── logging/              # structured logging
│   ├── pipeline/             # stage orchestration, passive-only guarantees
│   ├── ratelimit/            # token bucket + concurrency semaphore
│   ├── recon/                # passive sources (cert transparency, etc.)
│   ├── redact/               # single central secret redaction
│   ├── report/               # renderers: JSON, Markdown, SARIF, HTML, CSV, Text
│   ├── robots/               # RFC 9309 robots.txt parser
│   ├── scope/                # **the security boundary** — every network op checks here
│   └── storage/              # SQLite persistence (runs, findings, assets)
├── pkg/
│   └── models/               # shared types (Finding, DNSRecord, Graph, etc.)
├── .github/workflows/        # CI: test (linux/windows/macOS), race (linux), gosec
├── Dockerfile                # multi-stage build, runs as non-root
├── Makefile                  # check (default), build, test, race, fmt, lint, tidy
├── go.mod / go.sum
├── scope.example.yaml        # annotated scope file template
└── README.md
```

`internal/scope` is the part to read first. Every other stage consults it, and
its refusal is what keeps a typo in a hostname from becoming authorisation to
test a stranger's domain.

## ⚖️ Scope

Use only against assets you have explicit written authorisation to test. The
tool enforces the scope you declare; it cannot verify that the declaration
itself is genuine. That is your responsibility, and `metadata.reference` in the
scope file exists so a reader can check it.
