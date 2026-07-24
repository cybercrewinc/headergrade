const dns = require('dns').promises;
const tls = require('tls');
const { assertPublicHost } = require('./guard');

// All checks here are passive: they read public DNS, certificate transparency
// logs, RDAP registration data, and the target's own TLS certificate. Nothing
// probes ports or sends unsolicited application traffic beyond a normal fetch.

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

  const findings = [];
  findings.push(
    spf
      ? { label: 'SPF', ok: true, detail: spf }
      : { label: 'SPF', ok: false, detail: 'No SPF record — the domain can be spoofed in email From headers.' }
  );
  findings.push(
    dmarc
      ? { label: 'DMARC', ok: true, detail: dmarc }
      : { label: 'DMARC', ok: false, detail: 'No DMARC policy — receivers have no instruction for failed SPF/DKIM.' }
  );
  findings.push({
    label: 'MX',
    ok: mxPresent,
    detail: mxPresent ? 'Mail exchangers are configured.' : 'No MX records — the domain does not receive email.',
  });
  return findings;
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

// --- Orchestrator ----------------------------------------------------------

async function runOsint(domain) {
  const host = domain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(host)) throw new Error('Enter a valid domain name.');
  await assertPublicHost(host);

  const records = await dnsRecords(host);
  const [email, cert, subs, reg] = await Promise.all([
    emailAuth(host, records.txt),
    tlsCertificate(host),
    subdomains(host),
    registration(host),
  ]);

  return {
    domain: host,
    dns: records,
    email,
    certificate: cert,
    subdomains: subs,
    registration: reg,
    scannedAt: new Date().toISOString(),
  };
}

module.exports = { runOsint };
