const GRADE_COLORS = {
  'A+': 'var(--g-aplus)',
  A: 'var(--g-a)',
  B: 'var(--g-b)',
  C: 'var(--g-c)',
  D: 'var(--g-d)',
  E: 'var(--g-e)',
  F: 'var(--g-f)',
};

const form = document.getElementById('scan-form');
const input = document.getElementById('url-input');
const btn = document.getElementById('scan-btn');
const resultEl = document.getElementById('result');
const osintEl = document.getElementById('osint');

function esc(s) {
  const d = document.createElement('div');
  d.textContent = String(s);
  return d.innerHTML;
}

function gradeChip(grade) {
  return `<span class="grade-chip" style="color:${GRADE_COLORS[grade] || 'inherit'}">${esc(grade)}</span>`;
}

async function loadStats() {
  const res = await fetch('/api/stats');
  const stats = await res.json();

  document.getElementById('totals-table').innerHTML =
    stats.totals
      .map((t) => `<tr><td>${gradeChip(t.grade)}</td><td class="num">${t.count.toLocaleString()}</td></tr>`)
      .join('') +
    `<tr><td><strong>Total</strong></td><td class="num"><strong>${stats.total.toLocaleString()}</strong></td></tr>`;

  for (const [id, rows] of [
    ['recent-table', stats.recent],
    ['fame-table', stats.fame],
    ['shame-table', stats.shame],
  ]) {
    document.getElementById(id).innerHTML = rows.length
      ? rows
          .map(
            (r) =>
              `<tr><td class="host"><a href="#" data-scan="${esc(r.host)}">${esc(r.host)}</a></td><td class="num">${gradeChip(r.grade)}</td></tr>`
          )
          .join('')
      : '<tr><td class="empty">Nothing here yet</td></tr>';
  }
}

document.getElementById('panels').addEventListener('click', (e) => {
  const link = e.target.closest('a[data-scan]');
  if (!link) return;
  e.preventDefault();
  input.value = link.dataset.scan;
  form.requestSubmit();
});

function renderResult(data) {
  const cards = data.report
    .map(
      (r) => `
      <div class="hcard ${r.present ? 'ok' : 'miss'}">
        <div class="hname">${esc(r.header)}</div>
        ${r.present ? `<div class="hvalue">${esc(r.value)}</div>` : `<div class="hwhy">${esc(r.why)}</div>`}
      </div>`
    )
    .join('');

  const notes = [...data.notes, ...data.warnings];
  const notesHtml = notes.length
    ? `<ul class="notes">${notes.map((n) => `<li>${esc(n)}</li>`).join('')}</ul>`
    : '';

  const raw = Object.entries(data.rawHeaders)
    .map(([k, v]) => `<span class="rk">${esc(k)}</span>: ${esc(v)}`)
    .join('\n');

  resultEl.innerHTML = `
    <div class="result-card">
      <div class="result-top">
        <div class="grade-stamp" style="background:${GRADE_COLORS[data.grade]}">${esc(data.grade)}</div>
        <div class="result-meta">
          <h2>${esc(data.finalUrl)}</h2>
          <p>HTTP ${data.status} · scanned ${new Date(data.scannedAt).toLocaleString()}</p>
        </div>
      </div>
      <div class="headers-grid">${cards}</div>
      ${notesHtml}
      <div class="raw-block">${raw}</div>
    </div>`;
  resultEl.classList.remove('hidden');
}

function list(items, empty) {
  if (!items || !items.length) return `<span class="muted">${esc(empty)}</span>`;
  return items.map((i) => `<span class="tag">${esc(i)}</span>`).join('');
}

function renderOsint(data) {
  const d = data.dns;
  const cert = data.certificate;
  const reg = data.registration;

  const dnsRows = [
    ['A', d.a],
    ['AAAA', d.aaaa],
    ['MX', d.mx],
    ['NS', d.ns],
    ['TXT', d.txt],
    ['CAA', d.caa],
  ]
    .map(
      ([k, v]) =>
        `<tr><td class="rk">${k}</td><td>${v && v.length ? v.map((x) => esc(x)).join('<br>') : '<span class="muted">—</span>'}</td></tr>`
    )
    .join('');

  const emailCards = data.email
    .map(
      (f) => `<div class="hcard ${f.ok ? 'ok' : 'miss'}">
        <div class="hname">${esc(f.label)}</div>
        <div class="hwhy">${esc(f.detail)}</div>
      </div>`
    )
    .join('');

  const certBlock = cert
    ? `<table class="kv">
        <tr><td class="rk">Subject</td><td>${esc(cert.subject || '—')}</td></tr>
        <tr><td class="rk">Issuer</td><td>${esc(cert.issuer || '—')}</td></tr>
        <tr><td class="rk">Valid</td><td>${esc(cert.validFrom || '?')} → ${esc(cert.validTo || '?')}</td></tr>
        <tr><td class="rk">Expires in</td><td>${cert.daysLeft} days${cert.daysLeft < 15 ? ' ⚠' : ''}</td></tr>
        <tr><td class="rk">SAN</td><td>${list(cert.altNames, 'none')}</td></tr>
      </table>`
    : '<span class="muted">No TLS certificate on port 443.</span>';

  const regBlock = reg
    ? `<table class="kv">
        <tr><td class="rk">Registrar</td><td>${esc(reg.registrar || '—')}</td></tr>
        <tr><td class="rk">Created</td><td>${esc(reg.created || '—')}</td></tr>
        <tr><td class="rk">Expires</td><td>${esc(reg.expires || '—')}</td></tr>
        <tr><td class="rk">Status</td><td>${list(reg.status, '—')}</td></tr>
        <tr><td class="rk">Nameservers</td><td>${list(reg.nameservers, '—')}</td></tr>
      </table>`
    : '<span class="muted">No RDAP registration data available for this TLD.</span>';

  osintEl.innerHTML = `
    <div class="osint-card">
      <div class="osint-head">
        <h2>OSINT recon</h2>
        <span class="muted">${esc(data.domain)}</span>
      </div>
      <div class="osint-grid">
        <div class="recon-box span-2">
          <h3>DNS records</h3>
          <table class="kv">${dnsRows}</table>
          ${d.soa ? `<div class="muted soa">SOA: ${esc(d.soa)}</div>` : ''}
        </div>
        <div class="recon-box">
          <h3>Email authentication</h3>
          <div class="email-cards">${emailCards}</div>
        </div>
        <div class="recon-box">
          <h3>TLS certificate</h3>
          ${certBlock}
        </div>
        <div class="recon-box">
          <h3>Domain registration</h3>
          ${regBlock}
        </div>
        <div class="recon-box">
          <h3>Subdomains <span class="muted">(cert transparency)</span></h3>
          <div class="subs">${
            data.subdomains.length
              ? data.subdomains.map((s) => `<a href="#" data-scan="${esc(s)}" class="tag link">${esc(s)}</a>`).join('')
              : '<span class="muted">None found in public CT logs.</span>'
          }</div>
        </div>
      </div>
    </div>`;
  osintEl.classList.remove('hidden');
}

async function loadOsint(domain) {
  osintEl.classList.remove('hidden');
  osintEl.innerHTML = '<div class="osint-card"><h2>OSINT recon</h2><p class="muted">Gathering DNS, TLS, subdomains and registration…</p></div>';
  try {
    const res = await fetch('/api/osint?domain=' + encodeURIComponent(domain));
    const data = await res.json();
    if (!res.ok) {
      osintEl.innerHTML = `<div class="osint-card"><h2>OSINT recon</h2><p class="muted">${esc(data.error || 'Recon failed.')}</p></div>`;
    } else {
      renderOsint(data);
    }
  } catch {
    osintEl.classList.add('hidden');
  }
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = input.value.trim();
  if (!url) return;

  btn.disabled = true;
  btn.textContent = 'Scanning…';
  resultEl.classList.remove('hidden');
  resultEl.innerHTML = '<div class="result-card">Fetching headers…</div>';
  osintEl.classList.add('hidden');

  const params = new URLSearchParams({
    url,
    follow: document.getElementById('opt-follow').checked ? '1' : '0',
    hide: document.getElementById('opt-hide').checked ? '1' : '0',
  });

  try {
    const res = await fetch('/api/scan?' + params);
    const data = await res.json();
    if (!res.ok) {
      resultEl.innerHTML = `<div class="result-error">${esc(data.error || 'Scan failed.')}</div>`;
    } else {
      renderResult(data);
      loadStats();
      loadOsint(new URL(data.finalUrl).hostname);
    }
  } catch {
    resultEl.innerHTML = '<div class="result-error">Could not reach the scanner. Is the server running?</div>';
  } finally {
    btn.disabled = false;
    btn.textContent = 'Scan';
  }
});

loadStats();
