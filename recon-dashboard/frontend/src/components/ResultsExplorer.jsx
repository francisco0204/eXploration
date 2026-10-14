import { useMemo, useState } from 'react';
import { useMediaQuery } from '../hooks';
import { Badge, CodeList, EmptyRow, KeyValueRow, Panel, Row, StatCard, Tabs, preStyle } from './ui';

const TABS = [
  { id: 'resumen', label: 'Resumen' },
  { id: 'red', label: 'Red' },
  { id: 'seguridad', label: 'Seguridad' },
  { id: 'descubrimiento', label: 'Descubrimiento' },
  { id: 'ssl', label: 'SSL' },
  { id: 'cves', label: 'CVEs' },
  { id: 'waf', label: 'WAF & CDN bypass' },
];

function severityTone(sev) {
  if (!sev) return 'muted';
  const s = sev.toUpperCase();
  if (s === 'CRITICAL' || s === 'HIGH') return 'danger';
  if (s === 'MEDIUM') return 'warn';
  return 'ok';
}

const MOBILE_QUERY = '(max-width: 760px)';

export default function ResultsExplorer({ results }) {
  const isMobile = useMediaQuery(MOBILE_QUERY);
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState(null);
  const [tab, setTab] = useState('resumen');

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return results;
    return results.filter((r) => r.subdomain.toLowerCase().includes(q));
  }, [query, results]);

  // En desktop siempre hay algo seleccionado (fallback al primero).
  // En mobile, si no eligieron nada todavía, no mostramos ningún detalle:
  // así la primera pantalla que ven es la lista, no el detalle del primero.
  const active = selected
    ? results.find((r) => r.subdomain === selected)
    : !isMobile
      ? filtered[0]
      : null;

  function selectSub(sub) {
    setSelected(sub);
    setTab('resumen');
  }

  const showList = !isMobile || !active;
  const showDetail = (!isMobile && !!active) || (isMobile && !!active);

  return (
    <div style={{ display: 'flex', flex: 1, minHeight: 0, overflow: 'hidden' }}>
      {/* LIST */}
      {showList && (
        <aside
          style={{
            width: isMobile ? '100%' : 300,
            flexShrink: 0,
            borderRight: isMobile ? 'none' : '1px solid var(--line)',
            display: 'flex',
            flexDirection: 'column',
            minHeight: 0,
          }}
        >
          <div style={{ padding: 16, borderBottom: '1px solid var(--line)' }}>
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filtrar subdominios…"
              className="mono"
              style={{
                width: '100%',
                background: 'var(--surface)',
                border: '1px solid var(--line)',
                borderRadius: 7,
                color: 'var(--text)',
                fontSize: 16, // 16px fijo: evita zoom automático de iOS
                padding: '10px 12px',
                outline: 'none',
              }}
            />
          </div>
          <div style={{ overflowY: 'auto', flex: 1 }}>
            {filtered.map((r, i) => (
              <ListItem
                key={r.subdomain}
                item={r}
                index={i}
                active={active?.subdomain === r.subdomain}
                onClick={() => selectSub(r.subdomain)}
              />
            ))}
            {filtered.length === 0 && (
              <p style={{ color: 'var(--muted)', fontSize: 13, padding: 18 }}>Sin coincidencias.</p>
            )}
          </div>
        </aside>
      )}

      {/* DETAIL */}
      {showDetail && (
        <main
          style={{
            flex: 1,
            overflowY: 'auto',
            minWidth: 0,
            display: 'flex',
            flexDirection: 'column',
            animation: isMobile ? 'slideInRight 0.22s ease' : 'none',
          }}
        >
          {isMobile && (
            <button
              onClick={() => setSelected(null)}
              className="mono"
              style={{
                background: 'var(--surface)',
                border: 'none',
                borderBottom: '1px solid var(--line)',
                color: 'var(--signal)',
                fontWeight: 600,
                textAlign: 'left',
                padding: '14px 16px',
                fontSize: 12.5,
                cursor: 'pointer',
              }}
            >
              ← Volver a la lista
            </button>
          )}

          <div style={{ padding: 'clamp(20px, 5vw, 26px) clamp(16px, 4.5vw, 24px) 18px', borderBottom: '1px solid var(--line)' }}>
            <h2 className="mono" style={{ margin: 0, fontSize: 'clamp(17px, 4.5vw, 20px)', fontWeight: 700, wordBreak: 'break-word' }}>
              {active.subdomain}
            </h2>
            <p className="mono" style={{ margin: '8px 0 0', fontSize: 13, color: 'var(--muted)' }}>
              {active.ip || 'IP no resuelta'}
            </p>
          </div>

          <Tabs tabs={TABS} active={tab} onChange={setTab} />

          <div key={tab} style={{ flex: 1, animation: 'fadeUp 0.25s ease' }}>
            {tab === 'resumen' && <ResumenTab item={active} onJump={setTab} />}
            {tab === 'red' && <RedTab item={active} />}
            {tab === 'seguridad' && <SeguridadTab item={active} />}
            {tab === 'descubrimiento' && <DescubrimientoTab item={active} />}
            {tab === 'ssl' && <SSLTab item={active} />}
            {tab === 'cves' && <CVEsTab item={active} />}
            {tab === 'waf' && <WafTab item={active} />}
          </div>
        </main>
      )}
    </div>
  );
}

function ListItem({ item, index, active, onClick }) {
  const wafFlag = !!item.waf_payload?.waf_detected || (item.waf_cdn?.length ?? 0) > 0;
  const portsCount = item.open_ports?.length ?? 0;
  const cveCount = item.cves?.length ?? 0;

  return (
    <button
      onClick={onClick}
      className="list-item"
      style={{
        display: 'block',
        width: '100%',
        textAlign: 'left',
        background: active ? 'var(--surface)' : 'transparent',
        border: 'none',
        borderLeft: active ? '2px solid var(--signal)' : '2px solid transparent',
        borderBottom: '1px solid var(--line)',
        padding: '14px 18px',
        cursor: 'pointer',
        animation: 'fadeUp 0.3s ease backwards',
        animationDelay: `${Math.min(index * 25, 400)}ms`,
      }}
    >
      <div
        className="mono"
        style={{
          fontSize: 13,
          fontWeight: 600,
          color: active ? 'var(--signal)' : 'var(--text)',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }}
      >
        {item.subdomain}
      </div>
      <div className="mono" style={{ fontSize: 11, color: 'var(--muted)', marginTop: 4 }}>
        {item.ip || 'sin resolver'}
      </div>
      <div style={{ display: 'flex', gap: 6, marginTop: 10, flexWrap: 'wrap' }}>
        {portsCount > 0 && <Badge tone="info">{portsCount} puertos</Badge>}
        {cveCount > 0 && <Badge tone="danger">{cveCount} CVEs</Badge>}
        {wafFlag && <Badge tone="warn">WAF</Badge>}
        {item.real_ip?.origin_found && <Badge tone="danger">IP real filtrada</Badge>}
        {item.cors?.risky && <Badge tone="danger">CORS riesgoso</Badge>}
      </div>
    </button>
  );
}

// ---------- RESUMEN ----------
function ResumenTab({ item, onJump }) {
  const sec = item.security_headers ?? {};
  const headersOk = Object.values(sec).filter(Boolean).length;
  const headersTotal = Object.keys(sec).length;
  const adminCount = Object.keys(item.admin_endpoints ?? {}).length;
  const sensitiveCount = Object.keys(item.sensitive_paths ?? {}).length;
  const wafDetected = !!item.waf_payload?.waf_detected || (item.waf_cdn?.length ?? 0) > 0;
  const cveCount = item.cves?.length ?? 0;

  return (
    <Panel>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 22 }}>
        <StatCard label="Puertos abiertos" value={item.open_ports?.length ?? 0} tone="info" />
        <StatCard label="CVEs conocidos" value={cveCount} tone={cveCount > 0 ? 'danger' : 'ok'} />
        <StatCard
          label="Headers de seguridad"
          value={`${headersOk}/${headersTotal || 5}`}
          tone={headersOk === headersTotal ? 'ok' : 'warn'}
        />
        <StatCard label="Paneles admin" value={adminCount} tone={adminCount > 0 ? 'warn' : 'ok'} />
        <StatCard label="Rutas sensibles" value={sensitiveCount} tone={sensitiveCount > 0 ? 'danger' : 'ok'} />
        <StatCard label="WAF / CDN" value={wafDetected ? 'Detectado' : 'No detectado'} tone={wafDetected ? 'warn' : 'muted'} />
        <StatCard
          label="IP real tras CDN"
          value={item.real_ip?.origin_found ? 'Filtrada' : 'Protegida'}
          tone={item.real_ip?.origin_found ? 'danger' : 'ok'}
        />
      </div>

      {item.technologies?.length > 0 && (
        <div style={{ marginBottom: 22 }}>
          <div className="mono" style={{ fontSize: 11, color: 'var(--muted)', marginBottom: 10, letterSpacing: 0.4 }}>
            TECNOLOGÍAS
          </div>
          <div style={{ display: 'flex', gap: 7, flexWrap: 'wrap' }}>
            {item.technologies.map((t) => (
              <Badge key={t}>{t}</Badge>
            ))}
          </div>
        </div>
      )}

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <JumpButton onClick={() => onJump('red')} label="Ver red y banners" />
        <JumpButton onClick={() => onJump('seguridad')} label="Ver seguridad y CORS" />
        <JumpButton onClick={() => onJump('descubrimiento')} label="Ver rutas y endpoints" />
        <JumpButton onClick={() => onJump('cves')} label="Ver CVEs" />
        <JumpButton onClick={() => onJump('waf')} label="Ver WAF y CDN bypass" />
      </div>
    </Panel>
  );
}

function JumpButton({ onClick, label }) {
  return (
    <button
      onClick={onClick}
      className="mono hover-lift"
      style={{
        background: 'var(--surface-2)',
        border: '1px solid var(--line)',
        color: 'var(--text)',
        borderRadius: 7,
        padding: '10px 14px',
        fontSize: 12,
        cursor: 'pointer',
      }}
    >
      {label} →
    </button>
  );
}

// ---------- RED ----------
function RedTab({ item }) {
  return (
    <Panel title="PUERTOS Y BANNERS">
      <div style={{ display: 'flex', gap: 7, flexWrap: 'wrap', marginBottom: 18 }}>
        {(item.open_ports ?? []).length > 0 ? (
          item.open_ports.map((p) => (
            <Badge key={p} tone="info">
              :{p}
            </Badge>
          ))
        ) : (
          <EmptyRow>No se detectaron puertos abiertos entre los chequeados.</EmptyRow>
        )}
      </div>

      {item.http_banner || item.https_banner ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {item.http_banner && <pre style={preStyle}>{`[80]\n${item.http_banner}`}</pre>}
          {item.https_banner && <pre style={preStyle}>{`[443]\n${item.https_banner}`}</pre>}
        </div>
      ) : (
        <EmptyRow>Sin banners capturados.</EmptyRow>
      )}
    </Panel>
  );
}

// ---------- SEGURIDAD ----------
function SeguridadTab({ item }) {
  const sec = item.security_headers;
  const cors = item.cors;

  return (
    <>
      <Panel title="HEADERS DE SEGURIDAD">
        {sec ? (
          <div>
            <KeyValueRow label="Strict-Transport-Security" ok={sec.hsts} />
            <KeyValueRow label="Content-Security-Policy" ok={sec.csp} />
            <KeyValueRow label="X-Frame-Options" ok={sec.x_frame_options} />
            <KeyValueRow label="X-Content-Type-Options" ok={sec.x_content_type_options} />
            <KeyValueRow label="Referrer-Policy" ok={sec.referrer_policy} />
          </div>
        ) : (
          <EmptyRow>No disponible (requiere modo DEEP).</EmptyRow>
        )}
      </Panel>

      <Panel title="CORS">
        {cors ? (
          <div>
            <Row label="Access-Control-Allow-Origin" value={cors.origin || '—'} />
            <Row label="Allow-Credentials" value={String(cors.credentials)} />
            <Row
              label="Configuración"
              value={<Badge tone={cors.risky ? 'danger' : 'ok'}>{cors.risky ? 'RIESGOSA' : 'SEGURA'}</Badge>}
            />
          </div>
        ) : (
          <EmptyRow>No disponible.</EmptyRow>
        )}
      </Panel>

      <Panel title="PANELES ADMIN">
        {item.admin_endpoints && Object.keys(item.admin_endpoints).length > 0 ? (
          <CodeList items={item.admin_endpoints} />
        ) : (
          <EmptyRow>No se detectaron paneles admin.</EmptyRow>
        )}
      </Panel>
    </>
  );
}

// ---------- DESCUBRIMIENTO ----------
function DescubrimientoTab({ item }) {
  return (
    <>
      <Panel title="RUTAS SENSIBLES">
        {item.sensitive_paths && Object.keys(item.sensitive_paths).length > 0 ? (
          <CodeList items={item.sensitive_paths} />
        ) : (
          <EmptyRow>Ninguna ruta sensible detectada.</EmptyRow>
        )}
      </Panel>

      <Panel title="ENDPOINTS API">
        {item.api_endpoints && Object.keys(item.api_endpoints).length > 0 ? (
          <CodeList items={item.api_endpoints} />
        ) : (
          <EmptyRow>Ninguno respondió con código relevante.</EmptyRow>
        )}
      </Panel>

      <Panel title="ENDPOINTS EN JS">
        {item.js_endpoints && item.js_endpoints.length > 0 ? (
          <div className="mono" style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12.5 }}>
            {item.js_endpoints.map((ep) => (
              <div key={ep} style={{ color: 'var(--text)', wordBreak: 'break-word' }}>
                {ep}
              </div>
            ))}
          </div>
        ) : (
          <EmptyRow>No se detectaron endpoints en archivos JS.</EmptyRow>
        )}
      </Panel>
    </>
  );
}

// ---------- SSL ----------
function SSLTab({ item }) {
  return (
    <Panel title="CERTIFICADO SSL">
      {item.ssl_certs && item.ssl_certs.length > 0 ? (
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {item.ssl_certs.map((n) => (
            <Badge key={n}>{n}</Badge>
          ))}
        </div>
      ) : (
        <EmptyRow>Puerto 443 cerrado o sin nombres disponibles.</EmptyRow>
      )}
    </Panel>
  );
}

// ---------- CVES ----------
function CVEsTab({ item }) {
  const cves = item.cves ?? [];

  return (
    <Panel title="CVES CONOCIDOS (por software detectado en headers)">
      {cves.length > 0 ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {cves.map((c) => (
            <div
              key={c.cve_id}
              className="hover-lift"
              style={{ border: '1px solid var(--line)', borderRadius: 8, padding: 14 }}
            >
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  gap: 10,
                  marginBottom: 8,
                  flexWrap: 'wrap',
                }}
              >
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${c.cve_id}`}
                  target="_blank"
                  rel="noreferrer"
                  className="mono"
                  style={{ color: 'var(--signal)', fontWeight: 700, fontSize: 13, textDecoration: 'none' }}
                >
                  {c.cve_id} ↗
                </a>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {c.severity && <Badge tone={severityTone(c.severity)}>{c.severity}</Badge>}
                  {c.score != null && <Badge tone="muted">CVSS {c.score}</Badge>}
                </div>
              </div>
              <div className="mono" style={{ fontSize: 11, color: 'var(--muted)', marginBottom: 8 }}>
                {c.software}
              </div>
              {c.summary && (
                <p style={{ margin: 0, fontSize: 12.5, color: 'var(--text)', lineHeight: 1.6 }}>{c.summary}</p>
              )}
            </div>
          ))}
        </div>
      ) : (
        <EmptyRow>
          No se encontraron CVEs conocidos — ya sea porque el software no tiene vulnerabilidades
          públicas registradas, o porque los headers no expusieron una versión identificable.
        </EmptyRow>
      )}
    </Panel>
  );
}

// ---------- WAF / CDN BYPASS ----------
function WafTab({ item }) {
  const payload = item.waf_payload;
  const real = item.real_ip;

  return (
    <>
      <Panel title="WAF / CDN DETECTADO">
        {item.waf_cdn && item.waf_cdn.length > 0 ? (
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: payload ? 18 : 0 }}>
            {item.waf_cdn.map((w) => (
              <Badge key={w} tone="warn">
                {w}
              </Badge>
            ))}
          </div>
        ) : (
          <EmptyRow>No se detectó WAF/CDN por headers o rangos IP.</EmptyRow>
        )}

        {payload && (
          <div style={{ border: '1px solid var(--line)', borderRadius: 8, padding: 16 }}>
            <Row
              label="Payload-based detection"
              value={
                <Badge tone={payload.waf_detected ? 'warn' : 'ok'}>
                  {payload.waf_detected ? 'DETECTADO' : 'NO DETECTADO'}
                </Badge>
              }
            />
            <Row label="Vendor" value={payload.vendor || 'Desconocido'} />
            <Row label="Motivo" value={payload.reason || '—'} />
          </div>
        )}
      </Panel>

      <Panel title="IP REAL DETRÁS DEL CDN (CDN BYPASS)">
        {real ? (
          <div>
            <Row
              label="¿Detrás de Cloudflare?"
              value={<Badge tone={real.behind_cloudflare ? 'warn' : 'muted'}>{String(real.behind_cloudflare)}</Badge>}
            />
            <Row label="DNS globales" value={(real.origin_leaked_global_dns ?? []).join(', ') || '—'} />
            <Row
              label="Resultado"
              value={
                real.origin_found ? (
                  <Badge tone="danger">
                    IP REAL FILTRADA{real.direct_connect_matches?.length ? `: ${real.direct_connect_matches.join(', ')}` : ''}
                  </Badge>
                ) : (
                  <Badge tone="ok">Protección del CDN efectiva</Badge>
                )
              }
            />
          </div>
        ) : (
          <EmptyRow>No disponible.</EmptyRow>
        )}
      </Panel>
    </>
  );
}