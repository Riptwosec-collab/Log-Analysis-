# Log Analysis SOC Dashboard

Production demo: https://log-analysis-virid.vercel.app/

Log Analysis SOC Dashboard is a Next.js + TypeScript dashboard for defensive log review, SOC triage, incident notes, and report export.

## Features

- Paste or upload `.log`, `.txt`, and `.csv` files.
- Analyze common security and operations events from web, Linux, Windows, firewall, cloud, and network logs.
- Show risk score, severity counts, top source IP, timeline, source overview, and correlated findings.
- Filter by severity, keyword, source, user, host, IP, rule, and MITRE tactic.
- Open an incident detail drawer with evidence, raw log line, root cause, impact, and recommended fix.
- Manage custom detection rules, IOC watchlist, webhook settings, and audit notes.
- Export JSON, CSV, text/Markdown-style reports, CEF, LEEF, and PDF.
- Keep browser-local history for recent analysis sessions.
- Support Thai and English analyst summaries.

## Live demo

```text
https://log-analysis-virid.vercel.app/
```

## Tech stack

- Next.js App Router
- React
- TypeScript
- Tailwind CSS
- Browser localStorage
- Vercel deployment
- GitHub Actions build checks

## Run locally

```bash
git clone https://github.com/Riptwosec-collab/Log-Analysis-.git
cd Log-Analysis-
npm install
npm run dev
```

Open:

```text
http://localhost:3000
```

## Build check

```bash
npm run typecheck
npm run build
```

## Deploy

Recommended platform: Vercel

- Install command: `npm install`
- Build command: `npm run build`
- Production branch: `main`
- Production URL: `https://log-analysis-virid.vercel.app/`

## Sample logs

Sample fixtures are available in `samples/`:

- `samples/ssh-auth.log`
- `samples/firewall-events.log`
- `samples/windows-auth.log`
- `samples/network-events.log`
- `samples/cloudtrail-events.jsonl`
- `samples/mixed-soc-demo.log`

## Privacy notice

Logs can include sensitive data such as usernames, internal IPs, hostnames, tokens, cookies, customer identifiers, or private system details. Redact sensitive values before sharing logs publicly. This project is a defensive analysis helper and should be used with normal security review processes.

## Project structure

```text
app/                 Next.js routes and UI
app/components/      Dashboard panels and controls
lib/                 Parser, scoring, and i18n helpers
samples/             Test fixtures
docs/                Roadmap and release notes
.github/workflows/   CI build check
```

## Roadmap and version

- Roadmap: `docs/ROADMAP.md`
- Current version: `v1.0.0`
- Release notes: `CHANGELOG.md`
