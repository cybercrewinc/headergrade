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

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = input.value.trim();
  if (!url) return;

  btn.disabled = true;
  btn.textContent = 'Scanning…';
  resultEl.classList.remove('hidden');
  resultEl.innerHTML = '<div class="result-card">Fetching headers…</div>';

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
    }
  } catch {
    resultEl.innerHTML = '<div class="result-error">Could not reach the scanner. Is the server running?</div>';
  } finally {
    btn.disabled = false;
    btn.textContent = 'Scan';
  }
});

loadStats();
