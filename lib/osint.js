const dns = require('dns').promises;
const tls = require('tls');
const net = require('net');
const { assertPublicHost } = require('./guard');

// Most checks here are passive: they read public DNS, certificate transparency
// logs, RDAP data, GeoIP, and the target's own page/headers. The one active
// check is a light TCP connect probe of common ports (openPorts), guarded to
// public hosts only.

const DNS_TIMEOUT = 6000;

function withTimeout(promise, ms, label) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(`${label} timed out`)), ms)),
  ]);
}

async function tryResolve(fn) {
  try {
    return await withTimeout(fn(), DNS_TIMEOUT, 'DNS');
  } catch {
    return [];
  }
}

// --- DNS records -----------------------------------------------------------

async function dnsRecords(domain) {
  const [a, aaaa, mx, ns, txt, soa, caa] = await Promise.all([
    tryResolve(() => dns.resolve4(domain)),
    tryResolve(() => dns.resolve6(domain)),
    tryResolve(() => dns.resolveMx(domain)),
    tryResolve(() => dns.resolveNs(domain)),
    tryResolve(() => dns.resolveTxt(domain)),
    (async () => {
      try {
        return await withTimeout(dns.resolveSoa(domain), DNS_TIMEOUT, 'SOA');
      } catch {
        return null;
      }
    })(),
    tryResolve(() => dns.resolveCaa(domain)),
  ]);

  return {
    a,
    aaaa,
    mx: mx.map((m) => `${m.exchange} (priority ${m.priority})`),
    ns,
    txt: txt.map((chunks) => chunks.join('')),
    soa: soa ? `${soa.nsname} / ${soa.hostmaster}` : null,
    caa: caa.map((c) => `${c.critical ? '[critical] ' : ''}${c.issue || c.issuewild || JSON.stringify(c)}`),
  };
}

// --- Email authentication --------------------------------------------------

async function emailAuth(domain, txtRecords) {
  const spf = txtRecords.find((t) => /^v=spf1/i.test(t)) || null;

  let dmarc = null;
  try {
    const rows = await withTimeout(dns.resolveTxt(`_dmarc.${domain}`), DNS_TIMEOUT, 'DMARC');
    dmarc = rows.map((c) => c.join('')).find((t) => /^v=DMARC1/i.test(t)) || null;
  } catch {
    /* no DMARC */
  }

  const mxPresent = (await tryResolve(() => dns.resolveMx(domain))).length > 0;

  return [
    spf
      ? { label: 'SPF', ok: true, code: 'spf_ok', record: spf }
      : { label: 'SPF', ok: false, code: 'spf_missing' },
    dmarc
      ? { label: 'DMARC', ok: true, code: 'dmarc_ok', record: dmarc }
      : { label: 'DMARC', ok: false, code: 'dmarc_missing' },
    mxPresent
      ? { label: 'MX', ok: true, code: 'mx_ok' }
      : { label: 'MX', ok: false, code: 'mx_missing' },
  ];
}

// --- TLS certificate -------------------------------------------------------

function tlsCertificate(hostname) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      { host: hostname, port: 443, servername: hostname, rejectUnauthorized: false, timeout: 8000 },
      () => {
        const cert = socket.getPeerCertificate();
        socket.end();
        if (!cert || !cert.valid_to) return resolve(null);
        const to = new Date(cert.valid_to);
        const daysLeft = Math.round((to.getTime() - Date.now()) / 86400000);
        resolve({
          subject: cert.subject && cert.subject.CN ? cert.subject.CN : null,
          issuer: cert.issuer ? cert.issuer.O || cert.issuer.CN || null : null,
          validFrom: cert.valid_from || null,
          validTo: cert.valid_to || null,
          daysLeft,
          altNames: cert.subjectaltname ? cert.subjectaltname.replace(/DNS:/g, '').split(', ') : [],
        });
      }
    );
    socket.on('error', () => resolve(null));
    socket.on('timeout', () => {
      socket.destroy();
      resolve(null);
    });
  });
}

// --- Subdomains via certificate transparency (crt.sh) ----------------------

async function subdomains(domain) {
  try {
    const res = await fetch(`https://crt.sh/?q=${encodeURIComponent('%.' + domain)}&output=json`, {
      signal: AbortSignal.timeout(12000),
      headers: { 'User-Agent': 'HeaderGrade-OSINT/1.0' },
    });
    if (!res.ok) return [];
    const rows = await res.json();
    const set = new Set();
    for (const row of rows) {
      String(row.name_value || '')
        .split('\n')
        .forEach((name) => {
          const n = name.trim().toLowerCase();
          if (n && !n.startsWith('*.') && n.endsWith(domain)) set.add(n);
        });
    }
    return [...set].sort().slice(0, 100);
  } catch {
    return [];
  }
}

// --- Domain registration via RDAP ------------------------------------------

async function registration(domain) {
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      redirect: 'follow',
      signal: AbortSignal.timeout(10000),
      headers: { Accept: 'application/rdap+json', 'User-Agent': 'HeaderGrade-OSINT/1.0' },
    });
    if (!res.ok) return null;
    const data = await res.json();
    const events = {};
    (data.events || []).forEach((e) => {
      events[e.eventAction] = e.eventDate;
    });
    const registrar = (data.entities || []).find((e) => (e.roles || []).includes('registrar'));
    let registrarName = null;
    if (registrar && Array.isArray(registrar.vcardArray)) {
      const fn = registrar.vcardArray[1].find((v) => v[0] === 'fn');
      registrarName = fn ? fn[3] : null;
    }
    return {
      registrar: registrarName,
      created: events.registration || null,
      expires: events.expiration || null,
      updated: events.lastChanged || events['last changed'] || null,
      status: data.status || [],
      nameservers: (data.nameservers || []).map((n) => (n.ldhName || '').toLowerCase()).filter(Boolean),
    };
  } catch {
    return null;
  }
}

// --- Page fetch (shared by firewall / carbon / social) ---------------------

async function fetchPage(host) {
  try {
    const res = await fetch(`https://${host}/`, {
      redirect: 'follow',
      signal: AbortSignal.timeout(12000),
      headers: { 'User-Agent': 'HeaderGrade-OSINT/1.0 (+https://osint.cybercrew.co.jp)' },
    });
    const buf = Buffer.from(await res.arrayBuffer());
    const headers = {};
    res.headers.forEach((v, k) => {
      headers[k.toLowerCase()] = v;
    });
    return { ok: true, status: res.status, finalUrl: res.url, headers, bytes: buf.length, body: buf.toString('utf8', 0, 600000) };
  } catch {
    return { ok: false };
  }
}

// --- Server location (GeoIP) -----------------------------------------------

async function geoLocation(ip) {
  if (!ip) return null;
  try {
    const res = await fetch(
      `http://ip-api.com/json/${ip}?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as`,
      { signal: AbortSignal.timeout(8000) }
    );
    const d = await res.json();
    if (d.status !== 'success') return null;
    return {
      ip,
      city: d.city || null,
      region: d.regionName || null,
      country: d.country || null,
      countryCode: d.countryCode || null,
      zip: d.zip || null,
      timezone: d.timezone || null,
      lat: d.lat,
      lon: d.lon,
      isp: d.isp || null,
      org: d.org || null,
      asn: d.as || null,
    };
  } catch {
    return null;
  }
}

// --- Host names (reverse DNS) ----------------------------------------------

async function hostNames(ips) {
  const out = new Set();
  for (const ip of ips.slice(0, 3)) {
    try {
      const names = await withTimeout(dns.reverse(ip), DNS_TIMEOUT, 'PTR');
      names.forEach((n) => out.add(n.toLowerCase()));
    } catch {
      /* no PTR */
    }
  }
  return [...out];
}

// --- Firewall / WAF detection (header heuristics) --------------------------

function detectFirewall(headers) {
  if (!headers) return { detected: false, name: null };
  const server = (headers['server'] || '').toLowerCase();
  const has = (k) => k in headers;
  const signatures = [
    ['Cloudflare', () => server.includes('cloudflare') || has('cf-ray')],
    ['Sucuri', () => has('x-sucuri-id') || has('x-sucuri-cache')],
    ['Akamai', () => server.includes('akamai') || has('x-akamai-transformed')],
    ['Imperva Incapsula', () => has('x-iinfo') || (headers['x-cdn'] || '').toLowerCase().includes('incapsula')],
    ['AWS CloudFront', () => server.includes('cloudfront') || has('x-amz-cf-id')],
    ['Fastly', () => server.includes('fastly') || has('fastly-debug-digest')],
    ['Vercel', () => server.includes('vercel') || has('x-vercel-id')],
    ['Barracuda', () => has('barra_counter_session')],
    ['F5 BIG-IP', () => has('x-waf-status') || /big-?ip/.test(server)],
  ];
  for (const [name, fn] of signatures) {
    try {
      if (fn()) return { detected: true, name };
    } catch {
      /* skip */
    }
  }
  return { detected: false, name: null };
}

// --- Carbon footprint (Sustainable Web Design model) -----------------------

function carbonFootprint(bytes) {
  if (!bytes) return null;
  const KWH_PER_GB = 0.81; // Sustainable Web Design v3 estimate
  const GRID_INTENSITY = 442; // g CO2 per kWh, global average
  const gb = bytes / 1e9;
  const energyKwh = gb * KWH_PER_GB;
  const co2g = energyKwh * GRID_INTENSITY;
  return {
    sizeKb: +(bytes / 1024).toFixed(2),
    energyMwh: +(energyKwh * 1e6).toFixed(3),
    co2mg: +(co2g * 1000).toFixed(3),
  };
}

// --- Social tags (Open Graph / Twitter / meta) -----------------------------

function socialTags(body) {
  if (!body) return null;
  const metaTags = body.match(/<meta\b[^>]*>/gi) || [];
  const map = {};
  for (const tag of metaTags) {
    const attrs = {};
    const re = /([a-zA-Z:_-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
    let m;
    while ((m = re.exec(tag))) attrs[m[1].toLowerCase()] = m[2] != null ? m[2] : m[3];
    const key = attrs.property || attrs.name;
    if (key && attrs.content != null) map[key.toLowerCase()] = attrs.content;
  }
  const titleTag = (body.match(/<title[^>]*>([^<]*)<\/title>/i) || [])[1];
  const tags = {
    title: map['og:title'] || (titleTag ? titleTag.trim() : null),
    description: map['og:description'] || map.description || null,
    image: map['og:image'] || map['twitter:image'] || null,
    keywords: map.keywords || null,
    twitterCard: map['twitter:card'] || null,
    siteName: map['og:site_name'] || null,
  };
  return Object.values(tags).some(Boolean) ? tags : null;
}

// --- Open ports (light TCP connect probe) ----------------------------------

const COMMON_PORTS = [21, 22, 25, 80, 110, 143, 443, 3306, 3389, 8080, 8443];

function checkPort(host, port) {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port, timeout: 2500 });
    socket.on('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.on('error', () => resolve(false));
    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });
  });
}

async function openPorts(host) {
  const results = await Promise.all(COMMON_PORTS.map(async (p) => ({ port: p, open: await checkPort(host, p) })));
  return { open: results.filter((r) => r.open).map((r) => r.port), checked: COMMON_PORTS };
}

// --- Orchestrator ----------------------------------------------------------

async function runOsint(domain) {
  const host = domain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(host))
    throw Object.assign(new Error('Enter a valid domain name.'), { code: 'invalid_domain' });
  await assertPublicHost(host);

  const records = await dnsRecords(host);
  const primaryIp = records.a[0] || null;

  const [email, cert, subs, reg, page, geo, hosts, ports] = await Promise.all([
    emailAuth(host, records.txt),
    tlsCertificate(host),
    subdomains(host),
    registration(host),
    fetchPage(host),
    geoLocation(primaryIp),
    hostNames(records.a),
    openPorts(host),
  ]);

  return {
    domain: host,
    dns: records,
    email,
    certificate: cert,
    subdomains: subs,
    registration: reg,
    location: geo,
    hostNames: hosts,
    firewall: detectFirewall(page.ok ? page.headers : null),
    carbon: page.ok ? carbonFootprint(page.bytes) : null,
    social: page.ok ? socialTags(page.body) : null,
    ports,
    server: page.ok ? { status: page.status, finalUrl: page.finalUrl, poweredBy: page.headers['server'] || null } : null,
    scannedAt: new Date().toISOString(),
  };
}

module.exports = { runOsint };
