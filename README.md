# HeaderGrade

A free, self-hostable security header scanner, inspired by [securityheaders.com](https://securityheaders.com).
Enter any URL and HeaderGrade fetches the page, inspects its HTTP response headers, and returns an instant
**A+ to F** grade — plus a breakdown of what's present, what's missing, and why it matters.

Live: **https://headergrade.cybercrew.co.jp**

## What it checks

The grade is based on the six headers that control most browser-side security:

| Header | Protects against |
| --- | --- |
| `Strict-Transport-Security` | Protocol downgrade, cookie hijacking |
| `Content-Security-Policy` | XSS and injection attacks |
| `X-Frame-Options` | Clickjacking |
| `X-Content-Type-Options` | MIME-type sniffing |
| `Referrer-Policy` | Referrer data leakage |
| `Permissions-Policy` | Unwanted browser feature access |

**Grading:** every missing header drops the grade one step (A → F). All six present earns an **A**;
all six with a `Content-Security-Policy` free of `unsafe-inline`/`unsafe-eval` earns an **A+**.
Sites served over plain HTTP are capped at **D**. Information-leaking headers
(`Server`, `X-Powered-By`, …) are flagged as warnings but don't affect the grade.

## Features

- One-click scan with follow-redirects and hide-from-listings options
- Full raw response header view
- Grand totals, recent scans, hall of fame (A/A+) and hall of shame (F)
- JSON API
- SSRF guard — refuses to scan private and internal addresses
- Zero database — results persist to a simple JSON file

## Quick start

```bash
npm install
npm start
# open http://localhost:3000
```

Requires Node.js 18+ (uses the built-in `fetch`).

## API

```
GET /api/scan?url=example.com&follow=1&hide=0
GET /api/stats
```

`/api/scan` returns the grade, per-header report, notes, warnings, and raw headers as JSON.
`/api/stats` returns grand totals and the recent / fame / shame lists.

## Project layout

```
server.js        Express server, scan + grading logic, JSON persistence
public/          Static frontend (no build step)
data/scans.json  Scan history (created on first scan)
```

## Disclaimer

Grades reflect header presence only. A good grade is a starting point, not a security audit.

## License

MIT
