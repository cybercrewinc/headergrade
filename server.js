const express = require('express');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const { assertPublicHost } = require('./lib/guard');
const { runOsint } = require('./lib/osint');

const app = express();
const PORT = process.env.PORT || 3000;

// Behind DigitalOcean's proxy — trust the first hop so rate limiting keys on
// the real client IP rather than the load balancer.
app.set('trust proxy', 1);

// Site-wide limiter: generous, covers static assets and the stats endpoint.
const siteLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) =>
    res.status(429).json({ error: 'Too many requests.', errorCode: 'rate_limited' }),
});

// Scan/OSINT limiter: these make outbound network calls, so they're tighter.
const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) =>
    res.status(429).json({ error: 'Too many requests.', errorCode: 'rate_limited' }),
});

app.use(siteLimiter);
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'scans.json');

// ---------------------------------------------------------------------------
// Persistence (simple JSON store)
// ---------------------------------------------------------------------------

function loadData() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch {
    return { totals: {}, recent: [], sites: {} };
  }
}

function saveData(data) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

let db = loadData();

// ---------------------------------------------------------------------------
// Grading rules
// ---------------------------------------------------------------------------

const SCORED_HEADERS = [
  {
    name: 'strict-transport-security',
    label: 'Strict-Transport-Security',
    why: 'Forces browsers to only connect over HTTPS, preventing protocol downgrade attacks and cookie hijacking.',
  },
  {
    name: 'content-security-policy',
    label: 'Content-Security-Policy',
    why: 'Controls which resources the browser may load, the strongest defence against XSS and injection attacks.',
  },
  {
    name: 'x-frame-options',
    label: 'X-Frame-Options',
    why: 'Stops the site being embedded in frames on other origins, protecting against clickjacking.',
  },
  {
    name: 'x-content-type-options',
    label: 'X-Content-Type-Options',
    why: 'Prevents MIME-type sniffing, which can turn an innocent upload into executable content.',
  },
  {
    name: 'referrer-policy',
    label: 'Referrer-Policy',
    why: 'Controls how much referrer information leaves your site with outbound requests.',
  },
  {
    name: 'permissions-policy',
    label: 'Permissions-Policy',
    why: 'Declares which browser features (camera, geolocation, etc.) the site and embedded frames may use.',
  },
];

const LEAKY_HEADERS = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'];

const GRADE_BY_MISSING = ['A', 'B', 'C', 'D', 'E', 'F', 'F'];

// Human-readable text lives in the client so it can be shown in either
// language. The API returns stable codes; the frontend dictionary renders them.
function gradeHeaders(headers, finalUrl) {
  const report = SCORED_HEADERS.map((h) => ({
    key: h.name,
    header: h.label,
    present: headers.has(h.name),
    value: headers.get(h.name) || null,
  }));

  const missing = report.filter((r) => !r.present).length;
  let grade = GRADE_BY_MISSING[missing];
  const notes = [];

  const csp = headers.get('content-security-policy') || '';
  const cspWeak = /unsafe-inline|unsafe-eval/.test(csp);

  if (missing === 0 && !cspWeak) {
    grade = 'A+';
  }
  if (csp && cspWeak) {
    notes.push({ code: 'csp_weak' });
  }

  if (finalUrl.startsWith('http:')) {
    notes.push({ code: 'http_scheme' });
    if (grade < 'D') grade = 'D';
  }

  const warnings = LEAKY_HEADERS.filter((h) => headers.has(h)).map((h) => ({
    code: 'leaky_header',
    header: h,
    value: headers.get(h),
  }));

  return { grade, report, notes, warnings };
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

async function scanUrl(rawUrl, followRedirects) {
  let target = rawUrl.trim();
  if (!/^https?:\/\//i.test(target)) target = 'https://' + target;

  const parsed = new URL(target);
  await assertPublicHost(parsed.hostname);

  const res = await fetch(parsed.href, {
    method: 'GET',
    redirect: followRedirects ? 'follow' : 'manual',
    signal: AbortSignal.timeout(15000),
    headers: { 'User-Agent': 'HeaderGrade/1.0 (+security header scanner)' },
  });

  const finalUrl = res.url || parsed.href;
  const { grade, report, notes, warnings } = gradeHeaders(res.headers, finalUrl);

  const raw = {};
  res.headers.forEach((value, key) => {
    raw[key] = value;
  });

  return {
    url: parsed.href,
    finalUrl,
    status: res.status,
    grade,
    report,
    notes,
    warnings,
    rawHeaders: raw,
    scannedAt: new Date().toISOString(),
  };
}

function recordScan(result, hidden) {
  const host = new URL(result.finalUrl).host;
  db.totals[result.grade] = (db.totals[result.grade] || 0) + 1;
  db.sites[host] = { grade: result.grade, scannedAt: result.scannedAt };
  if (!hidden) {
    db.recent.unshift({ host, grade: result.grade, scannedAt: result.scannedAt });
    db.recent = db.recent.slice(0, 50);
  }
  saveData(db);
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

app.use(
  express.static(path.join(__dirname, 'public'), {
    setHeaders: (res, filePath) => {
      // HTML/JS/CSS must revalidate so redeploys reach visitors immediately;
      // images can be cached normally.
      if (/\.(html|js|css)$/.test(filePath)) res.setHeader('Cache-Control', 'no-cache');
    },
  })
);

app.get('/api/scan', scanLimiter, async (req, res) => {
  const { url, follow = '1', hide = '0' } = req.query;
  if (!url) return res.status(400).json({ error: 'Missing url parameter.', errorCode: 'missing_url' });

  try {
    const result = await scanUrl(String(url), follow === '1');
    recordScan(result, hide === '1');
    res.json(result);
  } catch (err) {
    const errorCode = err.name === 'TimeoutError' ? 'timeout' : err.code || 'scan_failed';
    res.status(422).json({ error: err.message || 'Scan failed.', errorCode });
  }
});

app.get('/api/osint', scanLimiter, async (req, res) => {
  const { domain } = req.query;
  if (!domain) return res.status(400).json({ error: 'Missing domain parameter.', errorCode: 'missing_domain' });
  try {
    const result = await runOsint(String(domain));
    res.json(result);
  } catch (err) {
    res.status(422).json({ error: err.message || 'OSINT lookup failed.', errorCode: err.code || 'osint_failed' });
  }
});

app.get('/api/stats', (req, res) => {
  const order = ['A+', 'A', 'B', 'C', 'D', 'E', 'F'];
  const totals = order.map((g) => ({ grade: g, count: db.totals[g] || 0 }));
  const total = totals.reduce((sum, t) => sum + t.count, 0);

  const seen = new Set();
  const uniqueRecent = db.recent.filter((r) => {
    if (seen.has(r.host)) return false;
    seen.add(r.host);
    return true;
  });

  res.json({
    totals,
    total,
    fame: uniqueRecent.filter((r) => r.grade === 'A+' || r.grade === 'A').slice(0, 10),
  });
});

app.listen(PORT, () => {
  console.log(`HeaderGrade running at http://localhost:${PORT}`);
});
