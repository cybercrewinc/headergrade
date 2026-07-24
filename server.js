const express = require('express');
const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const net = require('net');

const app = express();
const PORT = process.env.PORT || 3000;
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

function gradeHeaders(headers, finalUrl) {
  const report = SCORED_HEADERS.map((h) => ({
    header: h.label,
    present: headers.has(h.name),
    value: headers.get(h.name) || null,
    why: h.why,
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
    notes.push('Content-Security-Policy contains unsafe-inline or unsafe-eval, which weakens XSS protection.');
  }

  if (finalUrl.startsWith('http:')) {
    notes.push('The site was served over plain HTTP. Serve it over HTTPS to allow HSTS and secure cookies.');
    if (grade < 'D') grade = 'D';
  }

  const warnings = LEAKY_HEADERS.filter((h) => headers.has(h)).map(
    (h) => `${h} header exposes server software details (${headers.get(h)}). Consider removing it.`
  );

  return { grade, report, notes, warnings };
}

// ---------------------------------------------------------------------------
// SSRF guard — refuse to scan private / internal addresses
// ---------------------------------------------------------------------------

function isPrivateIp(ip) {
  if (net.isIPv6(ip)) {
    const low = ip.toLowerCase();
    return low === '::1' || low.startsWith('fc') || low.startsWith('fd') || low.startsWith('fe80');
  }
  const parts = ip.split('.').map(Number);
  const [a, b] = parts;
  return (
    a === 10 ||
    a === 127 ||
    a === 0 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254)
  );
}

async function assertPublicHost(hostname) {
  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname)) throw new Error('Refusing to scan private or internal addresses.');
    return;
  }
  const results = await dns.lookup(hostname, { all: true });
  for (const r of results) {
    if (isPrivateIp(r.address)) throw new Error('Refusing to scan private or internal addresses.');
  }
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

app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/scan', async (req, res) => {
  const { url, follow = '1', hide = '0' } = req.query;
  if (!url) return res.status(400).json({ error: 'Missing url parameter.' });

  try {
    const result = await scanUrl(String(url), follow === '1');
    recordScan(result, hide === '1');
    res.json(result);
  } catch (err) {
    const message =
      err.name === 'TimeoutError'
        ? 'The site took too long to respond.'
        : err.message || 'Scan failed.';
    res.status(422).json({ error: message });
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
    recent: uniqueRecent.slice(0, 10),
    fame: uniqueRecent.filter((r) => r.grade === 'A+' || r.grade === 'A').slice(0, 10),
    shame: uniqueRecent.filter((r) => r.grade === 'F').slice(0, 10),
  });
});

app.listen(PORT, () => {
  console.log(`HeaderGrade running at http://localhost:${PORT}`);
});
