// ---------------------------------------------------------------------------
// Internationalisation
// ---------------------------------------------------------------------------

const I18N = {
  en: {
    'meta.title': 'HeaderGrade — Free Security Header Scanner (A+ to F grades)',
    'meta.description':
      "Free online scanner for HTTP security headers. Check Content-Security-Policy, HSTS, X-Frame-Options and more, and get an instant A+ to F grade for any website.",
    'nav.home': 'Home',
    'nav.about': 'About',
    'nav.grading': 'Grading',
    'nav.api': 'API',
    'feat.headers': '6 security headers',
    'feat.email': 'Email auth',
    'feat.whois': 'WHOIS / RDAP',
    'grade.title': 'How we grade',
    'grade.intro':
      "Your grade starts at A and drops one letter for each of the six security headers you're missing. A strong Content-Security-Policy lifts a perfect score to A+.",
    'grade.aplus': 'All six headers present, with a Content-Security-Policy free of unsafe-inline and unsafe-eval.',
    'grade.a': 'All six security headers present.',
    'grade.b': 'One security header missing.',
    'grade.c': 'Two security headers missing.',
    'grade.d': 'Three missing — or the site was served over plain HTTP.',
    'grade.e': 'Four security headers missing.',
    'grade.f': 'Five or more security headers missing.',
    'scan.scanning': 'Scanning',
    'scan.analyzing': 'Analysing response headers…',
    'hero.title': 'Scan your site now',
    'hero.sub': "Six response headers decide most of your browser-side security. See which ones you're missing.",
    'hero.placeholder': 'example.com',
    'hero.scan': 'Scan',
    'hero.scanning': 'Scanning…',
    'hero.hide': 'Hide results',
    'hero.follow': 'Follow redirects',
    'panel.totals': 'Grand totals',
    'panel.recent': 'Recent scans',
    'panel.fame': 'Hall of fame',
    'about.title': 'About',
    'about.p1':
      'HeaderGrade fetches a page the way a browser would and inspects the HTTP response headers that control browser-side security: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy and Permissions-Policy. Each missing header lowers the grade one step from A down to F. A site with all six — and a Content-Security-Policy free of unsafe-inline — earns an A+.',
    'about.p2':
      'Every scan also runs a passive OSINT recon pass: DNS records, email authentication (SPF, DMARC, MX), the live TLS certificate, subdomains discovered from public certificate transparency logs, and domain registration from RDAP. All of it reads public data — nothing probes ports or sends unsolicited traffic.',
    'api.title': 'API',
    'api.intro': 'Everything on this page is available as JSON:',
    'footer.note': 'Grades reflect header presence only — they are a starting point, not a full audit.',
    'table.total': 'Total',
    'table.empty': 'Nothing here yet',
    'result.loading': 'Fetching headers…',
    'result.httpline': 'HTTP {status} · scanned {date}',
    'err.missing_url': 'Please enter a URL.',
    'err.missing_domain': 'Please enter a domain.',
    'err.timeout': 'The site took too long to respond.',
    'err.scan_failed': 'Scan failed.',
    'err.osint_failed': 'OSINT lookup failed.',
    'err.private_host': 'Refusing to scan private or internal addresses.',
    'err.invalid_domain': 'Enter a valid domain name.',
    'err.unreachable': 'Could not reach the scanner. Is the server running?',
    'err.rate_limited': 'Too many requests. Please wait a minute and try again.',
    'why.strict-transport-security':
      'Forces browsers to only connect over HTTPS, preventing protocol downgrade attacks and cookie hijacking.',
    'why.content-security-policy':
      'Controls which resources the browser may load, the strongest defence against XSS and injection attacks.',
    'why.x-frame-options': 'Stops the site being embedded in frames on other origins, protecting against clickjacking.',
    'why.x-content-type-options':
      'Prevents MIME-type sniffing, which can turn an innocent upload into executable content.',
    'why.referrer-policy': 'Controls how much referrer information leaves your site with outbound requests.',
    'why.permissions-policy':
      'Declares which browser features (camera, geolocation, etc.) the site and embedded frames may use.',
    'note.csp_weak': 'Content-Security-Policy contains unsafe-inline or unsafe-eval, which weakens XSS protection.',
    'note.http_scheme':
      'The site was served over plain HTTP. Serve it over HTTPS to allow HSTS and secure cookies.',
    'warn.leaky_header': '{header} header exposes server software details ({value}). Consider removing it.',
    'osint.title': 'OSINT recon',
    'osint.loading': 'Gathering DNS, TLS, subdomains and registration…',
    'osint.dns': 'DNS records',
    'osint.email': 'Email authentication',
    'osint.tls': 'TLS certificate',
    'osint.reg': 'Domain registration',
    'osint.subs': 'Subdomains',
    'osint.ct': '(cert transparency)',
    'kv.subject': 'Subject',
    'kv.issuer': 'Issuer',
    'kv.valid': 'Valid',
    'kv.expiresIn': 'Expires in',
    'kv.san': 'SAN',
    'kv.registrar': 'Registrar',
    'kv.created': 'Created',
    'kv.expires': 'Expires',
    'kv.status': 'Status',
    'kv.nameservers': 'Nameservers',
    'unit.days': 'days',
    'val.none': 'none',
    'subs.empty': 'None found in public CT logs.',
    'cert.none': 'No TLS certificate on port 443.',
    'reg.none': 'No RDAP registration data available for this TLD.',
    'email.spf_missing': 'No SPF record — the domain can be spoofed in email From headers.',
    'email.dmarc_missing': 'No DMARC policy — receivers have no instruction for failed SPF/DKIM.',
    'email.mx_ok': 'Mail exchangers are configured.',
    'email.mx_missing': 'No MX records — the domain does not receive email.',
  },
  ja: {
    'meta.title': 'HeaderGrade — 無料セキュリティヘッダースキャナー（A+〜F評価）',
    'meta.description':
      'HTTPセキュリティヘッダーを無料でオンライン診断。Content-Security-Policy、HSTS、X-Frame-Optionsなどを検査し、どのサイトでも即座にA+〜Fの評価を表示します。',
    'nav.home': 'ホーム',
    'nav.about': '概要',
    'nav.grading': '評価基準',
    'nav.api': 'API',
    'feat.headers': '6つのセキュリティヘッダー',
    'feat.email': 'メール認証',
    'feat.whois': 'WHOIS / RDAP',
    'grade.title': '評価の仕組み',
    'grade.intro':
      '評価はAから始まり、6つのセキュリティヘッダーが1つ欠けるごとに1段階ずつ下がります。強力なContent-Security-Policyがあれば満点はA+に引き上げられます。',
    'grade.aplus': '6つのヘッダーがすべて揃い、Content-Security-Policyにunsafe-inlineとunsafe-evalが含まれていない。',
    'grade.a': '6つのセキュリティヘッダーがすべて揃っている。',
    'grade.b': 'セキュリティヘッダーが1つ欠けている。',
    'grade.c': 'セキュリティヘッダーが2つ欠けている。',
    'grade.d': '3つ欠けている、またはサイトが平文のHTTPで配信されている。',
    'grade.e': 'セキュリティヘッダーが4つ欠けている。',
    'grade.f': 'セキュリティヘッダーが5つ以上欠けている。',
    'scan.scanning': 'スキャン中',
    'scan.analyzing': 'レスポンスヘッダーを解析中…',
    'hero.title': '今すぐサイトをスキャン',
    'hero.sub': 'ブラウザ側のセキュリティは6つのレスポンスヘッダーでほぼ決まります。不足しているものを確認しましょう。',
    'hero.placeholder': 'example.com',
    'hero.scan': 'スキャン',
    'hero.scanning': 'スキャン中…',
    'hero.hide': '結果を非表示',
    'hero.follow': 'リダイレクトを追跡',
    'panel.totals': '総合集計',
    'panel.recent': '最近のスキャン',
    'panel.fame': '殿堂入り',
    'about.title': '概要',
    'about.p1':
      'HeaderGradeはブラウザと同じようにページを取得し、ブラウザ側のセキュリティを制御するHTTPレスポンスヘッダーを検査します：Strict-Transport-Security、Content-Security-Policy、X-Frame-Options、X-Content-Type-Options、Referrer-Policy、Permissions-Policy。ヘッダーが1つ欠けるごとに評価はAからFへ1段階下がります。6つすべてが揃い、Content-Security-Policyにunsafe-inlineが含まれていなければA+になります。',
    'about.p2':
      '各スキャンでは受動的なOSINT調査も実行します：DNSレコード、メール認証（SPF、DMARC、MX）、稼働中のTLS証明書、公開された証明書透明性ログから見つかったサブドメイン、RDAPによるドメイン登録情報。すべて公開データを読み取るだけで、ポートスキャンや不要な通信は一切行いません。',
    'api.title': 'API',
    'api.intro': 'このページのすべての情報はJSONで取得できます：',
    'footer.note': '評価はヘッダーの有無のみを反映します。これは出発点であり、完全な監査ではありません。',
    'table.total': '合計',
    'table.empty': 'まだ何もありません',
    'result.loading': 'ヘッダーを取得中…',
    'result.httpline': 'HTTP {status} ・ {date} にスキャン',
    'err.missing_url': 'URLを入力してください。',
    'err.missing_domain': 'ドメインを入力してください。',
    'err.timeout': 'サイトの応答に時間がかかりすぎました。',
    'err.scan_failed': 'スキャンに失敗しました。',
    'err.osint_failed': 'OSINT調査に失敗しました。',
    'err.private_host': 'プライベートまたは内部アドレスのスキャンは拒否されました。',
    'err.invalid_domain': '有効なドメイン名を入力してください。',
    'err.unreachable': 'スキャナーに接続できませんでした。サーバーは稼働していますか？',
    'err.rate_limited': 'リクエストが多すぎます。1分ほど待ってから再度お試しください。',
    'why.strict-transport-security':
      'ブラウザにHTTPS接続のみを強制し、プロトコルのダウングレード攻撃やCookieの乗っ取りを防ぎます。',
    'why.content-security-policy':
      'ブラウザが読み込めるリソースを制御し、XSSやインジェクション攻撃に対する最も強力な防御となります。',
    'why.x-frame-options': '他オリジンのフレームへの埋め込みを防ぎ、クリックジャッキングから保護します。',
    'why.x-content-type-options':
      'MIMEタイプの推測を防ぎ、無害なアップロードが実行可能なコンテンツに変わるのを防ぎます。',
    'why.referrer-policy': '外部リクエストとともにサイトから送信されるリファラー情報の量を制御します。',
    'why.permissions-policy':
      'サイトや埋め込みフレームが使用できるブラウザ機能（カメラ、位置情報など）を宣言します。',
    'note.csp_weak':
      'Content-Security-Policyにunsafe-inlineまたはunsafe-evalが含まれており、XSS防御が弱まっています。',
    'note.http_scheme':
      'サイトが平文のHTTPで配信されました。HSTSやセキュアCookieを有効にするにはHTTPSで配信してください。',
    'warn.leaky_header':
      '{header}ヘッダーがサーバーソフトウェアの詳細（{value}）を公開しています。削除を検討してください。',
    'osint.title': 'OSINT調査',
    'osint.loading': 'DNS、TLS、サブドメイン、登録情報を収集中…',
    'osint.dns': 'DNSレコード',
    'osint.email': 'メール認証',
    'osint.tls': 'TLS証明書',
    'osint.reg': 'ドメイン登録',
    'osint.subs': 'サブドメイン',
    'osint.ct': '（証明書透明性）',
    'kv.subject': 'サブジェクト',
    'kv.issuer': '発行者',
    'kv.valid': '有効期間',
    'kv.expiresIn': '有効期限まで',
    'kv.san': 'SAN',
    'kv.registrar': 'レジストラ',
    'kv.created': '登録日',
    'kv.expires': '有効期限',
    'kv.status': 'ステータス',
    'kv.nameservers': 'ネームサーバー',
    'unit.days': '日',
    'val.none': 'なし',
    'subs.empty': '公開CTログにサブドメインは見つかりませんでした。',
    'cert.none': 'ポート443にTLS証明書がありません。',
    'reg.none': 'このTLDのRDAP登録情報は取得できません。',
    'email.spf_missing': 'SPFレコードがありません。メールのFromヘッダーでドメインが偽装される可能性があります。',
    'email.dmarc_missing': 'DMARCポリシーがありません。SPF/DKIM失敗時の受信側の対応が定義されていません。',
    'email.mx_ok': 'メールエクスチェンジャーが設定されています。',
    'email.mx_missing': 'MXレコードがありません。このドメインはメールを受信しません。',
  },
};

let LANG = 'en';

function detectLang() {
  const param = new URLSearchParams(location.search).get('lang');
  if (param === 'ja' || param === 'en') return param;
  const saved = localStorage.getItem('lang');
  if (saved === 'ja' || saved === 'en') return saved;
  return (navigator.language || 'en').toLowerCase().startsWith('ja') ? 'ja' : 'en';
}

function t(key, params) {
  let s = (I18N[LANG] && I18N[LANG][key]) || I18N.en[key] || key;
  if (params) for (const [k, v] of Object.entries(params)) s = s.replaceAll('{' + k + '}', v);
  return s;
}

function applyLang(lang) {
  LANG = lang;
  localStorage.setItem('lang', lang);
  document.documentElement.lang = lang;

  document.querySelectorAll('[data-i18n]').forEach((el) => {
    const key = el.getAttribute('data-i18n');
    if (key === 'meta.title') document.title = t(key);
    else el.textContent = t(key);
  });
  document.querySelectorAll('[data-i18n-attr]').forEach((el) => {
    const [attr, key] = el.getAttribute('data-i18n-attr').split(':');
    el.setAttribute(attr, t(key));
  });

  const desc = document.querySelector('meta[name="description"]');
  if (desc) desc.setAttribute('content', t('meta.description'));
  const ogLocale = document.getElementById('og-locale');
  if (ogLocale) ogLocale.setAttribute('content', lang === 'ja' ? 'ja_JP' : 'en_US');

  document.querySelectorAll('#lang-toggle [data-lang]').forEach((el) => {
    el.classList.toggle('active', el.getAttribute('data-lang') === lang);
  });

  const url = new URL(location.href);
  url.searchParams.set('lang', lang);
  history.replaceState(null, '', url);

  loadStats();
  if (lastResult) renderResult(lastResult);
  if (lastOsint) renderOsint(lastOsint);
}

// ---------------------------------------------------------------------------
// Scanner UI
// ---------------------------------------------------------------------------

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

let lastResult = null;
let lastOsint = null;

function esc(s) {
  const d = document.createElement('div');
  d.textContent = String(s);
  return d.innerHTML;
}

function gradeChip(grade) {
  return `<span class="grade-chip" style="color:${GRADE_COLORS[grade] || 'inherit'}">${esc(grade)}</span>`;
}

function noteText(n) {
  if (n.code === 'leaky_header') return t('warn.leaky_header', { header: n.header, value: n.value });
  return t('note.' + n.code);
}

async function loadStats() {
  try {
    const res = await fetch('/api/stats');
    const stats = await res.json();

    document.getElementById('totals-table').innerHTML =
      stats.totals
        .map((r) => `<tr><td>${gradeChip(r.grade)}</td><td class="num">${r.count.toLocaleString()}</td></tr>`)
        .join('') +
      `<tr><td><strong>${esc(t('table.total'))}</strong></td><td class="num"><strong>${stats.total.toLocaleString()}</strong></td></tr>`;

    for (const [id, rows] of [
      ['recent-table', stats.recent],
      ['fame-table', stats.fame],
    ]) {
      const el = document.getElementById(id);
      if (!el) continue;
      el.innerHTML = rows.length
        ? rows
            .map(
              (r) =>
                `<tr><td class="host"><a href="#" data-scan="${esc(r.host)}">${esc(r.host)}</a></td><td class="num">${gradeChip(r.grade)}</td></tr>`
            )
            .join('')
        : `<tr><td class="empty">${esc(t('table.empty'))}</td></tr>`;
    }
  } catch {
    /* stats are non-critical */
  }
}

document.getElementById('panels').addEventListener('click', (e) => {
  const link = e.target.closest('a[data-scan]');
  if (!link) return;
  e.preventDefault();
  input.value = link.dataset.scan;
  form.requestSubmit();
});

const SCAN_HEADERS = [
  'Strict-Transport-Security',
  'Content-Security-Policy',
  'X-Frame-Options',
  'X-Content-Type-Options',
  'Referrer-Policy',
  'Permissions-Policy',
];

function renderScanning(host) {
  const rows = SCAN_HEADERS.map(
    (h, i) => `<div class="scan-line" style="animation-delay:${i * 0.18}s"><span class="scan-dot"></span><span class="scan-name">${esc(h)}</span></div>`
  ).join('');
  resultEl.innerHTML = `
    <div class="result-card scanning-card">
      <div class="radar">
        <span class="radar-sweep"></span>
        <span class="radar-core">${esc(host.charAt(0).toUpperCase())}</span>
      </div>
      <div class="scanning-body">
        <div class="scanning-title">${esc(t('scan.scanning'))} <span class="scanning-host">${esc(host)}</span></div>
        <div class="scanning-sub">${esc(t('scan.analyzing'))}</div>
        <div class="scan-lines">${rows}</div>
      </div>
    </div>`;
}

function renderResult(data) {
  lastResult = data;
  const cards = data.report
    .map(
      (r) => `
      <div class="hcard ${r.present ? 'ok' : 'miss'}">
        <div class="hname">${esc(r.header)}</div>
        ${r.present ? `<div class="hvalue">${esc(r.value)}</div>` : `<div class="hwhy">${esc(t('why.' + r.key))}</div>`}
      </div>`
    )
    .join('');

  const notes = [...(data.notes || []), ...(data.warnings || [])];
  const notesHtml = notes.length
    ? `<ul class="notes">${notes.map((n) => `<li>${esc(noteText(n))}</li>`).join('')}</ul>`
    : '';

  const raw = Object.entries(data.rawHeaders)
    .map(([k, v]) => `<span class="rk">${esc(k)}</span>: ${esc(v)}`)
    .join('\n');

  const when = new Date(data.scannedAt).toLocaleString(LANG === 'ja' ? 'ja-JP' : 'en-US');

  resultEl.innerHTML = `
    <div class="result-card">
      <div class="result-top">
        <div class="grade-stamp" style="background:${GRADE_COLORS[data.grade]}">${esc(data.grade)}</div>
        <div class="result-meta">
          <h2>${esc(data.finalUrl)}</h2>
          <p>${esc(t('result.httpline', { status: data.status, date: when }))}</p>
        </div>
      </div>
      <div class="headers-grid">${cards}</div>
      ${notesHtml}
      <div class="raw-block">${raw}</div>
    </div>`;
  resultEl.classList.remove('hidden');
}

function list(items, emptyKey) {
  if (!items || !items.length) return `<span class="muted">${esc(t(emptyKey))}</span>`;
  return items.map((i) => `<span class="tag">${esc(i)}</span>`).join('');
}

function renderOsint(data) {
  lastOsint = data;
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
    .map((f) => {
      const detail = f.code === 'spf_ok' || f.code === 'dmarc_ok' ? esc(f.record) : esc(t('email.' + f.code));
      return `<div class="hcard ${f.ok ? 'ok' : 'miss'}">
        <div class="hname">${esc(f.label)}</div>
        <div class="hwhy">${detail}</div>
      </div>`;
    })
    .join('');

  const certBlock = cert
    ? `<table class="kv">
        <tr><td class="rk">${esc(t('kv.subject'))}</td><td>${esc(cert.subject || '—')}</td></tr>
        <tr><td class="rk">${esc(t('kv.issuer'))}</td><td>${esc(cert.issuer || '—')}</td></tr>
        <tr><td class="rk">${esc(t('kv.valid'))}</td><td>${esc(cert.validFrom || '?')} → ${esc(cert.validTo || '?')}</td></tr>
        <tr><td class="rk">${esc(t('kv.expiresIn'))}</td><td>${cert.daysLeft} ${esc(t('unit.days'))}${cert.daysLeft < 15 ? ' ⚠' : ''}</td></tr>
        <tr><td class="rk">${esc(t('kv.san'))}</td><td>${list(cert.altNames, 'val.none')}</td></tr>
      </table>`
    : `<span class="muted">${esc(t('cert.none'))}</span>`;

  const regBlock = reg
    ? `<table class="kv">
        <tr><td class="rk">${esc(t('kv.registrar'))}</td><td>${esc(reg.registrar || '—')}</td></tr>
        <tr><td class="rk">${esc(t('kv.created'))}</td><td>${esc(reg.created || '—')}</td></tr>
        <tr><td class="rk">${esc(t('kv.expires'))}</td><td>${esc(reg.expires || '—')}</td></tr>
        <tr><td class="rk">${esc(t('kv.status'))}</td><td>${list(reg.status, 'val.none')}</td></tr>
        <tr><td class="rk">${esc(t('kv.nameservers'))}</td><td>${list(reg.nameservers, 'val.none')}</td></tr>
      </table>`
    : `<span class="muted">${esc(t('reg.none'))}</span>`;

  osintEl.innerHTML = `
    <div class="osint-card">
      <div class="osint-head">
        <h2>${esc(t('osint.title'))}</h2>
        <span class="muted">${esc(data.domain)}</span>
      </div>
      <div class="osint-grid">
        <div class="recon-box span-2">
          <h3>${esc(t('osint.dns'))}</h3>
          <table class="kv">${dnsRows}</table>
          ${d.soa ? `<div class="muted soa">SOA: ${esc(d.soa)}</div>` : ''}
        </div>
        <div class="recon-box">
          <h3>${esc(t('osint.email'))}</h3>
          <div class="email-cards">${emailCards}</div>
        </div>
        <div class="recon-box">
          <h3>${esc(t('osint.tls'))}</h3>
          ${certBlock}
        </div>
        <div class="recon-box">
          <h3>${esc(t('osint.reg'))}</h3>
          ${regBlock}
        </div>
        <div class="recon-box">
          <h3>${esc(t('osint.subs'))} <span class="muted">${esc(t('osint.ct'))}</span></h3>
          <div class="subs">${
            data.subdomains.length
              ? data.subdomains.map((s) => `<a href="#" data-scan="${esc(s)}" class="tag link">${esc(s)}</a>`).join('')
              : `<span class="muted">${esc(t('subs.empty'))}</span>`
          }</div>
        </div>
      </div>
    </div>`;
  osintEl.classList.remove('hidden');
}

async function loadOsint(domain) {
  osintEl.classList.remove('hidden');
  osintEl.innerHTML = `<div class="osint-card"><h2>${esc(t('osint.title'))}</h2><p class="muted">${esc(t('osint.loading'))}</p></div>`;
  try {
    const res = await fetch('/api/osint?domain=' + encodeURIComponent(domain));
    const data = await res.json();
    if (!res.ok) {
      lastOsint = null;
      osintEl.innerHTML = `<div class="osint-card"><h2>${esc(t('osint.title'))}</h2><p class="muted">${esc(t('err.' + (data.errorCode || 'osint_failed')))}</p></div>`;
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

  const scanHost = url.replace(/^https?:\/\//i, '').split('/')[0] || url;
  btn.disabled = true;
  btn.classList.add('is-scanning');
  const label = btn.querySelector('.btn-label');
  if (label) label.textContent = t('hero.scanning');
  resultEl.classList.remove('hidden');
  renderScanning(scanHost);
  resultEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  osintEl.classList.add('hidden');
  lastResult = null;
  lastOsint = null;

  const params = new URLSearchParams({
    url,
    follow: document.getElementById('opt-follow').checked ? '1' : '0',
    hide: document.getElementById('opt-hide').checked ? '1' : '0',
  });

  try {
    const res = await fetch('/api/scan?' + params);
    const data = await res.json();
    if (!res.ok) {
      resultEl.innerHTML = `<div class="result-error">${esc(t('err.' + (data.errorCode || 'scan_failed')))}</div>`;
    } else {
      renderResult(data);
      loadStats();
      loadOsint(new URL(data.finalUrl).hostname);
    }
  } catch {
    resultEl.innerHTML = `<div class="result-error">${esc(t('err.unreachable'))}</div>`;
  } finally {
    btn.disabled = false;
    btn.classList.remove('is-scanning');
    const l = btn.querySelector('.btn-label');
    if (l) l.textContent = t('hero.scan');
  }
});

document.getElementById('lang-toggle').addEventListener('click', () => {
  applyLang(LANG === 'en' ? 'ja' : 'en');
});

applyLang(detectLang());
