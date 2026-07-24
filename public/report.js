// ---------------------------------------------------------------------------
// PDF report generation
//
// Builds a clean, offscreen "print" version of the current scan + OSINT result,
// rasterises it one block at a time, then lays the blocks onto A4 pages. A block
// is atomic: if it doesn't fit in the space left on the page it moves whole to
// the next page — content is never split across a page boundary (only a single
// block taller than a full page is sliced, which is unavoidable). Every page
// gets a "Page X of Y" footer.
// ---------------------------------------------------------------------------

(function () {
  const A4 = { w: 210, h: 297 };
  const MARGIN = { top: 15, bottom: 15, side: 14 };
  const CONTENT_W = A4.w - MARGIN.side * 2; // 182mm
  const BLOCK_BOTTOM = A4.h - 20; // leave room for footer
  const RENDER_W = 760; // px width of the offscreen document

  const HG = () => window.HG || {};
  const t = (k, p) => (HG().t ? HG().t(k, p) : k);

  // -- offscreen DOM helpers -------------------------------------------------

  function esc(s) {
    const d = document.createElement('div');
    d.textContent = String(s == null ? '' : s);
    return d.innerHTML;
  }

  const STYLE_ID = 'pdfdoc-style';
  function ensureStyle() {
    if (document.getElementById(STYLE_ID)) return;
    const css = `
      .pdfdoc { position: fixed; left: -10000px; top: 0; width: ${RENDER_W}px;
        background: #fff; color: #1c2a3a; font-family: 'Inter','Noto Sans JP',system-ui,sans-serif;
        line-height: 1.5; padding: 0; }
      .pdfdoc .rblock { padding: 0 4px; }
      .pdfdoc .rcover { background: #0b1a30; color: #fff; border-radius: 12px; padding: 26px 28px;
        display: flex; align-items: center; gap: 22px; }
      .pdfdoc .rcover .rgrade { font-family: 'Space Grotesk',sans-serif; font-weight: 700; font-size: 44px;
        width: 92px; height: 92px; border-radius: 12px; display: flex; align-items: center;
        justify-content: center; color: #fff; flex-shrink: 0; }
      .pdfdoc .rcover .rbrand { font-family: 'Space Grotesk',sans-serif; font-size: 13px; letter-spacing: 2px;
        text-transform: uppercase; color: #35c6f4; }
      .pdfdoc .rcover h1 { font-family: 'Space Grotesk',sans-serif; font-size: 24px; margin: 4px 0 2px; }
      .pdfdoc .rcover .rsub { color: #a9bad2; font-size: 13px; }
      .pdfdoc .rcover .rtarget { font-family: 'JetBrains Mono',monospace; font-size: 14px; color: #fff;
        margin-top: 12px; word-break: break-all; }
      .pdfdoc .rmeta { display: flex; flex-wrap: wrap; gap: 6px 26px; margin-top: 10px; }
      .pdfdoc .rmeta span { font-size: 12px; color: #c8d4e8; }
      .pdfdoc .rmeta b { color: #fff; font-weight: 600; }
      .pdfdoc .rheading { font-family: 'Space Grotesk',sans-serif; font-size: 17px; font-weight: 700;
        color: #0b1a30; padding: 4px; border-bottom: 2px solid #2f7bf6; margin: 0 4px; }
      .pdfdoc .rsummary { font-size: 14px; color: #1c2a3a; padding: 2px 4px; }
      .pdfdoc .rcard { border: 1px solid #e4e9f0; border-left-width: 3px; border-radius: 10px;
        padding: 12px 15px; background: #fff; }
      .pdfdoc .rcard.ok { border-left-color: #2ba24c; }
      .pdfdoc .rcard.miss { border-left-color: #d62f2f; background: #fdf6f6; border-color: #eccfcf; }
      .pdfdoc .rcard .rrow { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
      .pdfdoc .rcard .rname { font-family: 'JetBrains Mono',monospace; font-weight: 600; font-size: 14px; }
      .pdfdoc .rpill { font-size: 11px; font-weight: 600; padding: 2px 9px; border-radius: 999px;
        white-space: nowrap; }
      .pdfdoc .rpill.ok { background: #e6f4ea; color: #12a150; }
      .pdfdoc .rpill.miss { background: #fbe3e3; color: #d62f2f; }
      .pdfdoc .rcard .rval { font-family: 'JetBrains Mono',monospace; font-size: 12px; color: #5b6b80;
        margin-top: 7px; word-break: break-all; }
      .pdfdoc .rcard .rwhy { font-size: 12.5px; color: #5b6b80; margin-top: 7px; }
      .pdfdoc .rnote { font-size: 13px; color: #8a5a10; padding: 9px 13px; background: #fff9ef;
        border: 1px solid #f0e2c2; border-radius: 8px; }
      .pdfdoc .rraw { background: #0b1a30; color: #cfe0f5; font-family: 'JetBrains Mono',monospace;
        font-size: 11px; border-radius: 10px; padding: 16px 18px; white-space: pre-wrap; word-break: break-all; }
      .pdfdoc .rraw .rk { color: #35c6f4; }
      .pdfdoc .rbox { border: 1px solid #e4e9f0; border-radius: 10px; padding: 14px 16px; background: #fbfcfe; }
      .pdfdoc .rbox h3 { font-family: 'Space Grotesk',sans-serif; font-size: 14px; margin-bottom: 8px; color: #0b1a30; }
      .pdfdoc table.kv { width: 100%; border-collapse: collapse; font-size: 13px; }
      .pdfdoc table.kv td { padding: 5px 8px; vertical-align: top; border-bottom: 1px solid #eef2f8; }
      .pdfdoc table.kv tr:last-child td { border-bottom: 0; }
      .pdfdoc table.kv .rk { font-family: 'JetBrains Mono',monospace; color: #2f7bf6; white-space: nowrap;
        width: 110px; font-size: 12px; }
      .pdfdoc .tag { display: inline-block; font-family: 'JetBrains Mono',monospace; font-size: 12px;
        background: #eef2f8; color: #1c2a3a; padding: 3px 8px; border-radius: 6px; margin: 0 5px 5px 0;
        word-break: break-all; }
      .pdfdoc .muted { color: #5b6b80; }
    `;
    const style = document.createElement('style');
    style.id = STYLE_ID;
    style.textContent = css;
    document.head.appendChild(style);
  }

  function kvTable(rows) {
    const body = rows
      .map(([k, v]) => `<tr><td class="rk">${esc(k)}</td><td>${v}</td></tr>`)
      .join('');
    return `<table class="kv">${body}</table>`;
  }

  function tagList(items, emptyKey) {
    if (!items || !items.length) return `<span class="muted">${esc(t(emptyKey || 'val.none'))}</span>`;
    return items.map((i) => `<span class="tag">${esc(i)}</span>`).join('');
  }

  function noteText(n) {
    if (n.code === 'leaky_header') return t('warn.leaky_header', { header: n.header, value: n.value });
    return t('note.' + n.code);
  }

  // -- block builders --------------------------------------------------------

  function block(cls, html) {
    const el = document.createElement('div');
    el.className = 'rblock ' + cls;
    el.innerHTML = html;
    return { el, heading: cls.indexOf('rheading') !== -1 };
  }

  function buildBlocks(result, osint) {
    const lang = HG().lang === 'ja' ? 'ja-JP' : 'en-US';
    const gradeColor = HG().gradeColor ? HG().gradeColor(result.grade) : '#5b6b80';
    const present = result.report.filter((r) => r.present).length;
    const total = result.report.length;
    const scanned = new Date(result.scannedAt).toLocaleString(lang);
    const generated = new Date().toLocaleString(lang);
    const blocks = [];

    // Cover
    blocks.push(
      block(
        'rcover',
        `<div class="rgrade" style="background:${gradeColor}">${esc(result.grade)}</div>
         <div style="flex:1;min-width:0">
           <div class="rbrand">HeaderGrade</div>
           <h1>${esc(t('report.docTitle'))}</h1>
           <div class="rsub">${esc(t('report.subtitle'))}</div>
           <div class="rtarget">${esc(result.finalUrl)}</div>
           <div class="rmeta">
             <span><b>${esc(t('report.grade'))}:</b> ${esc(result.grade)}</span>
             <span><b>${esc(t('report.status'))}:</b> ${esc(result.status)}</span>
             <span><b>${esc(t('report.scanned'))}:</b> ${esc(scanned)}</span>
             <span><b>${esc(t('report.generatedAt'))}:</b> ${esc(generated)}</span>
           </div>
         </div>`
      )
    );

    // Summary + headers
    blocks.push(block('rheading', esc(t('report.sectionHeaders'))));
    blocks.push(block('rsummary', esc(t('report.summaryLine', { present, total }))));
    result.report.forEach((r) => {
      const detail = r.present
        ? `<div class="rval">${esc(r.value)}</div>`
        : `<div class="rwhy">${esc(t('why.' + r.key))}</div>`;
      const pill = r.present
        ? `<span class="rpill ok">${esc(t('report.present'))}</span>`
        : `<span class="rpill miss">${esc(t('report.missing'))}</span>`;
      blocks.push(
        block(
          'rcard ' + (r.present ? 'ok' : 'miss'),
          `<div class="rrow"><span class="rname">${esc(r.header)}</span>${pill}</div>${detail}`
        )
      );
    });

    // Notes & warnings
    const notes = [...(result.notes || []), ...(result.warnings || [])];
    if (notes.length) {
      blocks.push(block('rheading', esc(t('report.sectionNotes'))));
      notes.forEach((n) => blocks.push(block('rnote', esc(noteText(n)))));
    }

    // Raw headers
    blocks.push(block('rheading', esc(t('report.sectionRaw'))));
    const raw = Object.entries(result.rawHeaders || {})
      .map(([k, v]) => `<span class="rk">${esc(k)}</span>: ${esc(v)}`)
      .join('\n');
    blocks.push(block('rraw', raw || '<span class="muted">—</span>'));

    // OSINT
    if (osint) blocks.push(...buildOsintBlocks(osint));

    return blocks;
  }

  function buildOsintBlocks(o) {
    const blocks = [block('rheading', esc(t('osint.title')))];
    const dash = '<span class="muted">—</span>';

    // DNS
    const d = o.dns || {};
    const dnsRows = [
      ['A', d.a],
      ['AAAA', d.aaaa],
      ['MX', d.mx],
      ['NS', d.ns],
      ['TXT', d.txt],
      ['CAA', d.caa],
    ].map(([k, v]) => [k, v && v.length ? v.map((x) => esc(x)).join('<br>') : dash]);
    blocks.push(box(t('osint.dns'), kvTable(dnsRows) + (d.soa ? `<div class="muted" style="margin-top:6px;font-size:12px">SOA: ${esc(d.soa)}</div>` : '')));

    // Email auth
    if (o.email && o.email.length) {
      const rows = o.email.map((f) => {
        const detail = f.code === 'spf_ok' || f.code === 'dmarc_ok' ? esc(f.record) : esc(t('email.' + f.code));
        return [f.label, `${f.ok ? '✓' : '✗'} ${detail}`];
      });
      blocks.push(box(t('osint.email'), kvTable(rows)));
    }

    // TLS certificate
    const c = o.certificate;
    if (c) {
      blocks.push(
        box(
          t('osint.tls'),
          kvTable([
            [t('kv.subject'), esc(c.subject || '—')],
            [t('kv.issuer'), esc(c.issuer || '—')],
            [t('kv.valid'), `${esc(c.validFrom || '?')} → ${esc(c.validTo || '?')}`],
            [t('kv.expiresIn'), `${esc(c.daysLeft)} ${esc(t('unit.days'))}`],
            [t('kv.san'), tagList(c.altNames, 'val.none')],
          ])
        )
      );
    }

    // Registration
    const r = o.registration;
    if (r) {
      blocks.push(
        box(
          t('osint.reg'),
          kvTable([
            [t('kv.registrar'), esc(r.registrar || '—')],
            [t('kv.created'), esc(r.created || '—')],
            [t('kv.expires'), esc(r.expires || '—')],
            [t('kv.status'), tagList(r.status, 'val.none')],
            [t('kv.nameservers'), tagList(r.nameservers, 'val.none')],
          ])
        )
      );
    }

    // Location
    const loc = o.location;
    if (loc) {
      blocks.push(
        box(
          t('osint.location'),
          kvTable([
            [t('kv.city'), esc(loc.city || '—')],
            [t('kv.country'), `${esc(loc.country || '—')}${loc.countryCode ? ` (${esc(loc.countryCode)})` : ''}`],
            [t('kv.timezone'), esc(loc.timezone || '—')],
            [t('kv.coords'), loc.lat != null ? esc(loc.lat + ', ' + loc.lon) : '—'],
            [t('kv.org'), esc(loc.org || loc.isp || '—')],
            [t('kv.asn'), esc(loc.asn || '—')],
          ])
        )
      );
    }

    // Firewall
    const fw = o.firewall || { detected: false };
    blocks.push(box(t('osint.firewall'), fw.detected ? `✓ ${esc(fw.name)}` : `<span class="muted">${esc(t('fw.none'))}</span>`));

    // Ports
    const ports = o.ports || { open: [] };
    blocks.push(
      box(
        t('osint.ports'),
        ports.open && ports.open.length
          ? ports.open.map((p) => `<span class="tag">${esc(p)}</span>`).join('')
          : `<span class="muted">${esc(t('ports.none'))}</span>`
      )
    );

    // Carbon
    const cb = o.carbon;
    if (cb) {
      blocks.push(
        box(
          t('osint.carbon'),
          kvTable([
            [t('carbon.size'), `${esc(cb.sizeKb)} KB`],
            [t('carbon.co2'), `${esc(cb.co2mg)} mg`],
            [t('carbon.energy'), `${esc(cb.energyMwh)} mWh`],
          ])
        )
      );
    }

    // Host names
    blocks.push(box(t('osint.hostnames'), tagList(o.hostNames, 'val.none')));

    // Subdomains
    blocks.push(box(`${t('osint.subs')} ${t('osint.ct')}`, tagList(o.subdomains, 'subs.empty')));

    // Social tags
    const s = o.social;
    if (s) {
      blocks.push(
        box(
          t('osint.social'),
          kvTable([
            [t('kv.title'), esc(s.title || '—')],
            [t('kv.description'), esc(s.description || '—')],
            [t('kv.keywords'), esc(s.keywords || '—')],
            [t('kv.image'), s.image ? esc(s.image) : '—'],
          ])
        )
      );
    }

    return blocks;
  }

  function box(title, inner) {
    return block('rbox', `<h3>${esc(title)}</h3>${inner}`);
  }

  // -- render + paginate -----------------------------------------------------

  async function generateReport(btn) {
    const result = HG().lastResult;
    if (!result) return;
    if (!window.jspdf || !window.html2canvas) {
      alert(t('report.failed'));
      return;
    }

    const label = btn && btn.querySelector('.report-btn-label');
    const original = label ? label.textContent : '';
    if (btn) btn.disabled = true;
    if (label) label.textContent = t('report.generating');

    ensureStyle();
    const doc = document.createElement('div');
    doc.className = 'pdfdoc';
    document.body.appendChild(doc);

    try {
      const blocks = buildBlocks(result, HG().lastOsint);
      blocks.forEach((b) => doc.appendChild(b.el));
      // Let fonts settle before rasterising.
      if (document.fonts && document.fonts.ready) await document.fonts.ready;

      const { jsPDF } = window.jspdf;
      const pdf = new jsPDF({ unit: 'mm', format: 'a4', compress: true });

      let y = MARGIN.top;
      for (let i = 0; i < blocks.length; i++) {
        const b = blocks[i];
        const canvas = await window.html2canvas(b.el, {
          scale: 2,
          backgroundColor: '#ffffff',
          logging: false,
          useCORS: true,
        });
        const hmm = (CONTENT_W * canvas.height) / canvas.width;
        const gapAfter = b.heading ? 3 : 6;

        if (b.heading) {
          // Keep a heading with the block that follows it — never orphan it.
          if (y + hmm + 24 > BLOCK_BOTTOM && y > MARGIN.top) {
            pdf.addPage();
            y = MARGIN.top;
          }
        } else if (y + hmm > BLOCK_BOTTOM) {
          if (hmm <= BLOCK_BOTTOM - MARGIN.top) {
            // Fits on a fresh page: move the whole block down, don't split.
            pdf.addPage();
            y = MARGIN.top;
          } else {
            // Taller than a full page: slice at page boundaries (unavoidable).
            y = sliceTall(pdf, canvas, y);
            continue;
          }
        }

        const img = canvas.toDataURL('image/png');
        pdf.addImage(img, 'PNG', MARGIN.side, y, CONTENT_W, hmm);
        y += hmm + gapAfter;
      }

      addFooters(pdf);

      const host = safeHost(result.finalUrl);
      const stamp = new Date().toISOString().slice(0, 10);
      pdf.save(`headergrade-${host}-${stamp}.pdf`);
    } catch (err) {
      console.error('report generation failed', err);
      alert(t('report.failed'));
    } finally {
      doc.remove();
      if (btn) btn.disabled = false;
      if (label) label.textContent = original;
    }
  }

  function sliceTall(pdf, canvas, y) {
    const pxPerMm = canvas.width / CONTENT_W;
    let srcY = 0;
    let remainingMm = BLOCK_BOTTOM - y;
    while (srcY < canvas.height) {
      let sliceHpx = Math.floor(remainingMm * pxPerMm);
      sliceHpx = Math.min(sliceHpx, canvas.height - srcY);
      if (sliceHpx <= 0) {
        pdf.addPage();
        y = MARGIN.top;
        remainingMm = BLOCK_BOTTOM - MARGIN.top;
        continue;
      }
      const tmp = document.createElement('canvas');
      tmp.width = canvas.width;
      tmp.height = sliceHpx;
      const ctx = tmp.getContext('2d');
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(0, 0, tmp.width, tmp.height);
      ctx.drawImage(canvas, 0, srcY, canvas.width, sliceHpx, 0, 0, canvas.width, sliceHpx);
      const sliceMm = sliceHpx / pxPerMm;
      pdf.addImage(tmp.toDataURL('image/png'), 'PNG', MARGIN.side, y, CONTENT_W, sliceMm);
      srcY += sliceHpx;
      if (srcY < canvas.height) {
        pdf.addPage();
        y = MARGIN.top;
        remainingMm = BLOCK_BOTTOM - MARGIN.top;
      } else {
        y += sliceMm + 6;
      }
    }
    return y;
  }

  function addFooters(pdf) {
    const total = pdf.getNumberOfPages();
    for (let i = 1; i <= total; i++) {
      pdf.setPage(i);
      pdf.setDrawColor(228, 233, 240);
      pdf.setLineWidth(0.2);
      pdf.line(MARGIN.side, A4.h - 12, A4.w - MARGIN.side, A4.h - 12);
      pdf.setFontSize(8);
      pdf.setTextColor(140, 150, 165);
      // ASCII only, so it renders in every language with the built-in font.
      pdf.text(t('report.confidential'), MARGIN.side, A4.h - 7);
      pdf.text(`Page ${i} / ${total}`, A4.w - MARGIN.side, A4.h - 7, { align: 'right' });
    }
  }

  function safeHost(url) {
    try {
      return new URL(url).host.replace(/[^a-z0-9.-]/gi, '_');
    } catch {
      return 'report';
    }
  }

  window.generateReport = generateReport;
})();
