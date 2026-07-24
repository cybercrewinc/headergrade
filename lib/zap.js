// OWASP ZAP passive baseline scan.
//
// This drives a ZAP daemon's API to spider a target and run ZAP's PASSIVE
// scanner only — it reads and analyses the responses ZAP receives while
// crawling, exactly like the `zap-baseline.py` convenience script. It never
// invokes the active scanner, so no attack payloads (SQLi, XSS, fuzzing) are
// ever sent to the target. Spidering itself is ordinary crawl traffic.
//
// Configured via environment variables so the daemon can live on a separate
// host (e.g. a DigitalOcean droplet):
//   ZAP_API_URL  e.g. http://203.0.113.10:8080
//   ZAP_API_KEY  the daemon's api.key

const ZAP_URL = process.env.ZAP_API_URL || '';
const ZAP_KEY = process.env.ZAP_API_KEY || '';

const SPIDER_MAX_CHILDREN = 10; // keep crawls light
const POLL_MS = 2000;
const SPIDER_TIMEOUT_MS = 70000;
const PSCAN_TIMEOUT_MS = 60000;

function isConfigured() {
  return Boolean(ZAP_URL && ZAP_KEY);
}

async function zapGet(apiPath, params = {}) {
  const url = new URL(apiPath, ZAP_URL);
  url.searchParams.set('apikey', ZAP_KEY);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, String(v));
  const res = await fetch(url, { signal: AbortSignal.timeout(25000) });
  if (!res.ok) throw new Error(`ZAP API ${res.status}`);
  return res.json();
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function pollUntil(check, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await check()) return true;
    await sleep(POLL_MS);
  }
  return false;
}

const RISK_ORDER = { High: 0, Medium: 1, Low: 2, Informational: 3 };

async function baselineScan(target) {
  if (!isConfigured()) {
    throw Object.assign(new Error('ZAP scanner is not configured.'), { code: 'zap_unconfigured' });
  }

  let host = String(target).trim();
  if (!/^https?:\/\//i.test(host)) host = 'https://' + host;
  const url = new URL(host).href;

  // Pull the target into ZAP's site tree.
  await zapGet('/JSON/core/action/accessUrl/', { url, followRedirects: true });

  // Spider (crawl only) — passive scanner runs automatically on each response.
  const spider = await zapGet('/JSON/spider/action/scan/', {
    url,
    maxChildren: SPIDER_MAX_CHILDREN,
    recurse: true,
    subtreeOnly: true,
  });
  const spiderId = spider.scan;

  await pollUntil(async () => {
    const s = await zapGet('/JSON/spider/view/status/', { scanId: spiderId });
    return String(s.status) === '100';
  }, SPIDER_TIMEOUT_MS);

  // Let the passive-scan queue drain.
  await pollUntil(async () => {
    const q = await zapGet('/JSON/pscan/view/recordsToScan/');
    return parseInt(q.recordsToScan, 10) === 0;
  }, PSCAN_TIMEOUT_MS);

  const { alerts = [] } = await zapGet('/JSON/alert/view/alerts/', { baseurl: url, start: 0, count: 500 });

  // Deduplicate by (name, risk); count instances.
  const byKey = new Map();
  for (const a of alerts) {
    const key = `${a.risk}|${a.alert || a.name}`;
    if (byKey.has(key)) {
      byKey.get(key).instances += 1;
    } else {
      byKey.set(key, {
        name: a.alert || a.name,
        risk: a.risk,
        confidence: a.confidence,
        description: (a.description || '').trim(),
        solution: (a.solution || '').trim(),
        reference: (a.reference || '').split('\n')[0] || null,
        cwe: a.cweid && a.cweid !== '-1' ? a.cweid : null,
        instances: 1,
      });
    }
  }

  const summary = [...byKey.values()].sort(
    (x, y) => (RISK_ORDER[x.risk] ?? 4) - (RISK_ORDER[y.risk] ?? 4)
  );
  const counts = { High: 0, Medium: 0, Low: 0, Informational: 0 };
  for (const s of summary) if (counts[s.risk] != null) counts[s.risk] += 1;

  return { target: url, counts, alerts: summary, scannedAt: new Date().toISOString() };
}

module.exports = { baselineScan, isConfigured };
