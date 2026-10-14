// Primitivas compartidas por el panel de resultados.

export function statusTone(code) {
  if (!code) return 'muted';
  if (code >= 200 && code < 300) return 'ok';
  if (code === 301 || code === 302) return 'info';
  if (code === 401 || code === 403) return 'warn';
  if (code >= 500) return 'danger';
  return 'muted';
}

const TONE_COLORS = {
  ok: '#3ecf8e',
  info: '#6fb8ff',
  warn: '#ffc857',
  danger: '#ff5c5c',
  muted: '#8995a8',
};

export function StatusChip({ code }) {
  const tone = statusTone(code);
  const color = TONE_COLORS[tone];
  return (
    <span
      className="mono"
      style={{
        fontSize: 11,
        fontWeight: 600,
        color,
        background: `${color}1f`,
        border: `1px solid ${color}45`,
        borderRadius: 5,
        padding: '3px 8px',
        lineHeight: 1.4,
        flexShrink: 0,
      }}
    >
      {code}
    </span>
  );
}

export function Badge({ children, tone = 'muted' }) {
  const color = TONE_COLORS[tone] || TONE_COLORS.muted;
  return (
    <span
      className="mono"
      style={{
        fontSize: 11,
        fontWeight: 600,
        letterSpacing: 0.2,
        color,
        background: `${color}1a`,
        border: `1px solid ${color}45`,
        borderRadius: 5,
        padding: '4px 9px',
        whiteSpace: 'nowrap',
        display: 'inline-block',
      }}
    >
      {children}
    </span>
  );
}

export function Tabs({ tabs, active, onChange }) {
  return (
    <div
      className="hscroll"
      style={{
        display: 'flex',
        gap: 4,
        padding: '0 clamp(14px, 4vw, 24px)',
        borderBottom: '1px solid var(--line)',
      }}
    >
      {tabs.map((t) => {
        const isActive = active === t.id;
        return (
          <button
            key={t.id}
            onClick={() => onChange(t.id)}
            className="mono"
            style={{
              background: 'transparent',
              border: 'none',
              borderBottom: isActive ? '2px solid var(--signal)' : '2px solid transparent',
              color: isActive ? 'var(--signal)' : 'var(--muted)',
              fontSize: 12,
              fontWeight: 600,
              letterSpacing: 0.3,
              padding: 'clamp(12px, 3vw, 14px) clamp(12px, 3vw, 16px)',
              cursor: 'pointer',
              whiteSpace: 'nowrap',
              transition: 'color 0.15s ease',
              flexShrink: 0,
            }}
          >
            {t.label}
          </button>
        );
      })}
    </div>
  );
}

export function Panel({ title, children }) {
  return (
    <div style={{ padding: 'clamp(18px, 5vw, 22px) clamp(16px, 4.5vw, 24px)' }}>
      {title && (
        <h3
          className="mono"
          style={{
            fontSize: 11.5,
            fontWeight: 700,
            letterSpacing: 0.5,
            color: 'var(--muted)',
            margin: '0 0 16px',
          }}
        >
          {title}
        </h3>
      )}
      {children}
    </div>
  );
}

export function EmptyRow({ children }) {
  return <p style={{ color: 'var(--muted)', fontSize: 13, margin: '4px 0', lineHeight: 1.6 }}>{children}</p>;
}

export function KeyValueRow({ label, ok, okLabel = 'OK', missingLabel = 'FALTA' }) {
  const tone = ok ? 'ok' : 'danger';
  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        gap: 16,
        padding: '11px 0',
        borderBottom: '1px solid var(--line)',
        fontSize: 13.5,
      }}
    >
      <span style={{ color: 'var(--text)' }}>{label}</span>
      <Badge tone={tone}>{ok ? okLabel : missingLabel}</Badge>
    </div>
  );
}

export function CodeList({ items }) {
  if (!items || Object.keys(items).length === 0) return null;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {Object.entries(items).map(([path, code]) => (
        <div
          key={path}
          className="mono"
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            gap: 14,
            fontSize: 12.5,
            color: 'var(--text)',
            background: 'var(--surface-2)',
            border: '1px solid var(--line)',
            borderRadius: 7,
            padding: '9px 12px',
          }}
        >
          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{path}</span>
          <StatusChip code={code} />
        </div>
      ))}
    </div>
  );
}

export function Row({ label, value }) {
  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        gap: 20,
        padding: '9px 0',
        borderBottom: '1px solid var(--line)',
        fontSize: 13.5,
      }}
    >
      <span style={{ color: 'var(--muted)', flexShrink: 0 }}>{label}</span>
      <span className="mono" style={{ color: 'var(--text)', textAlign: 'right', wordBreak: 'break-word' }}>
        {value}
      </span>
    </div>
  );
}

export function StatCard({ label, value, tone = 'muted' }) {
  const color = TONE_COLORS[tone] || TONE_COLORS.muted;
  return (
    <div
      className="hover-lift"
      style={{
        background: 'var(--surface-2)',
        border: '1px solid var(--line)',
        borderRadius: 10,
        padding: '14px 16px',
        minWidth: 128,
        flex: '1 1 128px',
      }}
    >
      <div className="mono" style={{ fontSize: 10.5, color: 'var(--muted)', marginBottom: 8, letterSpacing: 0.4 }}>
        {label}
      </div>
      <div className="mono" style={{ fontSize: 16, fontWeight: 700, color }}>
        {value}
      </div>
    </div>
  );
}

export const preStyle = {
  margin: 0,
  background: 'var(--surface-2)',
  border: '1px solid var(--line)',
  borderRadius: 8,
  padding: '12px 14px',
  fontSize: 12,
  lineHeight: 1.6,
  color: 'var(--text)',
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-word',
  maxHeight: 220,
  overflowY: 'auto',
};