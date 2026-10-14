export function downloadJSON(data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `exploration-${data.target}-${Date.now()}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function exportPrintableReport(data) {
  const win = window.open('', '_blank');
  if (!win) {
    alert('El navegador bloqueó la ventana nueva. Permití pop-ups para este sitio y probá de nuevo.');
    return;
  }
  win.document.write(buildReportHtml(data));
  win.document.close();
  win.onload = () => {
    win.focus();
    win.print();
  };
}

function esc(value) {
  if (value === null || value === undefined) return '';
  return String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function buildReportHtml(data) {
  const sections = (data.results || []).map(subdomainSection).join('');
  return `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8" />
<title>eXploration — Reporte de ${esc(data.target)}</title>
<style>
  body { font-family: -apple-system, Segoe UI, Arial, sans-serif; color: #111; margin: 32px; line-height: 1.5; }
  h1 { font-size: 20px; margin-bottom: 2px; }
  h2 { font-size: 15px; border-bottom: 1px solid #ccc; padding-bottom: 4px; margin-top: 30px; }
  h3 { font-size: 12px; color: #555; text-transform: uppercase; letter-spacing: 0.4px; margin: 14px 0 4px; }
  .meta { color: #555; font-size: 12px; margin-bottom: 24px; }
  table { width: 100%; border-collapse: collapse; font-size: 11.5px; margin-bottom: 4px; }
  td, th { border: 1px solid #ddd; padding: 4px 8px; text-align: left; vertical-align: top; word-break: break-word; }
  th { background: #f4f4f4; }
  .sub { page-break-inside: avoid; margin-bottom: 20px; }
  .empty { color: #888; font-style: italic; font-size: 11.5px; margin: 0 0 6px; }
  .kv { font-size: 12px; margin: 0 0 6px; }
  @media print {
    a { color: inherit; text-decoration: none; }
  }
</style>
</head>
<body>
  <h1>eXploration — Reporte de reconocimiento</h1>
  <div class="meta">
    Objetivo: <b>${esc(data.target)}</b> &nbsp;·&nbsp;
    Modo: ${esc(data.mode)} &nbsp;·&nbsp;
    Subdominios únicos: ${esc(data.total_subdomains)} &nbsp;·&nbsp;
    Analizados: ${esc((data.results || []).length)} &nbsp;·&nbsp;
    Generado: ${esc(new Date().toLocaleString())}
  </div>
  ${sections || '<p class="empty">Sin resultados.</p>'}
</body>
</html>`;
}

function subdomainSection(r) {
  return `
  <div class="sub">
    <h2>${esc(r.subdomain)}${r.ip ? ` (${esc(r.ip)})` : ''}</h2>
    <p class="kv"><b>Puertos abiertos:</b> ${esc((r.open_ports || []).join(', ') || '—')}</p>
    <p class="kv"><b>Tecnologías:</b> ${esc((r.technologies || []).join(', ') || '—')}</p>
    ${securityHeadersTable(r.security_headers)}
    ${corsBlock(r.cors)}
    ${dictTable('Paneles admin', r.admin_endpoints)}
    ${dictTable('Rutas sensibles', r.sensitive_paths)}
    ${dictTable('Endpoints API', r.api_endpoints)}
    ${cvesTable(r.cves)}
    ${sslBlock(r.ssl_certs)}
    ${wafBlock(r)}
  </div>`;
}

function securityHeadersTable(sec) {
  if (!sec) return '';
  const rows = [
    ['Strict-Transport-Security', sec.hsts],
    ['Content-Security-Policy', sec.csp],
    ['X-Frame-Options', sec.x_frame_options],
    ['X-Content-Type-Options', sec.x_content_type_options],
    ['Referrer-Policy', sec.referrer_policy],
  ]
    .map(([k, v]) => `<tr><td>${esc(k)}</td><td>${v ? 'OK' : 'FALTA'}</td></tr>`)
    .join('');
  return `<h3>Headers de seguridad</h3><table>${rows}</table>`;
}

function corsBlock(cors) {
  if (!cors) return '';
  return `<h3>CORS</h3><p class="kv">Allow-Origin: ${esc(cors.origin || '—')} · Allow-Credentials: ${esc(String(cors.credentials))} · ${cors.risky ? 'RIESGOSA' : 'Segura'}</p>`;
}

function dictTable(title, obj) {
  if (!obj || Object.keys(obj).length === 0) {
    return `<h3>${esc(title)}</h3><p class="empty">Ninguno detectado.</p>`;
  }
  const rows = Object.entries(obj)
    .map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`)
    .join('');
  return `<h3>${esc(title)}</h3><table><tr><th>Ruta</th><th>Código</th></tr>${rows}</table>`;
}

function cvesTable(cves) {
  if (!cves || cves.length === 0) {
    return `<h3>CVEs</h3><p class="empty">Ninguno encontrado.</p>`;
  }
  const rows = cves
    .map(
      (c) =>
        `<tr><td>${esc(c.cve_id)}</td><td>${esc(c.severity)}</td><td>${esc(c.score)}</td><td>${esc(c.software)}</td></tr>`
    )
    .join('');
  return `<h3>CVEs</h3><table><tr><th>ID</th><th>Severidad</th><th>Score</th><th>Software</th></tr>${rows}</table>`;
}

function sslBlock(certs) {
  if (!certs || certs.length === 0) return '';
  return `<h3>Certificado SSL</h3><p class="kv">${esc(certs.join(', '))}</p>`;
}

function wafBlock(r) {
  const waf = (r.waf_cdn || []).join(', ') || 'No detectado';
  const payload = r.waf_payload;
  const real = r.real_ip?.origin_found
    ? `IP real filtrada: ${(r.real_ip.direct_connect_matches || []).join(', ') || '—'}`
    : 'Protección del CDN efectiva';
  const payloadLine = payload
    ? ` · Payload-based: ${payload.waf_detected ? 'DETECTADO' : 'no detectado'}${payload.vendor ? ` (${payload.vendor})` : ''}`
    : '';
  return `<h3>WAF / CDN</h3><p class="kv">${esc(waf)}${payloadLine}</p><p class="kv">${esc(real)}</p>`;
}