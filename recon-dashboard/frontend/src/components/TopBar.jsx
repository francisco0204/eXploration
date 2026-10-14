import { useMediaQuery } from '../hooks';
import { downloadJSON, exportPrintableReport } from '../export';

export default function TopBar({ summary, onReset }) {
  const isMobile = useMediaQuery('(max-width: 760px)');

  if (isMobile) {
    return (
      <header style={{ borderBottom: '1px solid var(--line)' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 12,
            padding: '12px 14px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
            <span
              style={{
                width: 8,
                height: 8,
                borderRadius: '50%',
                background: 'var(--signal)',
                boxShadow: '0 0 8px var(--signal)',
                flexShrink: 0,
              }}
            />
            <span className="mono" style={{ fontSize: 13, fontWeight: 700, flexShrink: 0 }}>
              eXploration
            </span>
          </div>

          <button
            onClick={onReset}
            className="mono"
            style={{
              background: 'transparent',
              border: '1px solid var(--line)',
              color: 'var(--muted)',
              borderRadius: 8,
              padding: '8px 12px',
              fontSize: 11.5,
              fontWeight: 600,
              letterSpacing: 0.2,
              cursor: 'pointer',
              flexShrink: 0,
              whiteSpace: 'nowrap',
            }}
          >
            ❯ NUEVA BÚSQUEDA
          </button>
        </div>

        <div style={{ padding: '0 14px 10px' }}>
          <div
            className="mono"
            style={{ fontSize: 15, fontWeight: 700, color: 'var(--text)', overflowWrap: 'anywhere' }}
          >
            {summary.target}
          </div>
        </div>

        <div className="hscroll" style={{ display: 'flex', gap: 20, padding: '0 14px 10px' }}>
          <Stat label="Modo" value={summary.mode} />
          <Stat label="Subdominios" value={summary.total_subdomains} />
          <Stat label="Analizados" value={summary.results?.length ?? 0} />
        </div>

        <div className="hscroll" style={{ display: 'flex', gap: 8, padding: '0 14px 12px' }}>
          <ExportButton onClick={() => downloadJSON(summary)} label="⬇ JSON" />
          <ExportButton onClick={() => exportPrintableReport(summary)} label="🖨 PDF" />
        </div>
      </header>
    );
  }

  return (
    <header
      style={{
        borderBottom: '1px solid var(--line)',
        padding: '16px 24px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 20,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 28, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
          <span
            style={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              background: 'var(--signal)',
              boxShadow: '0 0 8px var(--signal)',
            }}
          />
          <span className="mono" style={{ fontSize: 14, fontWeight: 700 }}>
            eXploration
          </span>
        </div>

        <Stat label="Objetivo" value={summary.target} mono />
        <Stat label="Modo" value={summary.mode} />
        <Stat label="Subdominios" value={summary.total_subdomains} />
        <Stat label="Analizados" value={summary.results?.length ?? 0} />
      </div>

      <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
        <ExportButton onClick={() => downloadJSON(summary)} label="⬇ JSON" />
        <ExportButton onClick={() => exportPrintableReport(summary)} label="🖨 PDF" />
        <button
          onClick={onReset}
          className="mono"
          style={{
            background: 'transparent',
            border: '1px solid var(--line)',
            color: 'var(--muted)',
            borderRadius: 8,
            padding: '9px 16px',
            fontSize: 12,
            fontWeight: 600,
            letterSpacing: 0.3,
            cursor: 'pointer',
            whiteSpace: 'nowrap',
          }}
        >
          ❯ NUEVA BÚSQUEDA
        </button>
      </div>
    </header>
  );
}

function ExportButton({ onClick, label }) {
  return (
    <button
      onClick={onClick}
      className="mono"
      style={{
        background: 'var(--surface-2)',
        border: '1px solid var(--line)',
        color: 'var(--text)',
        borderRadius: 8,
        padding: '9px 13px',
        fontSize: 11.5,
        fontWeight: 600,
        letterSpacing: 0.2,
        cursor: 'pointer',
        whiteSpace: 'nowrap',
        flexShrink: 0,
      }}
    >
      {label}
    </button>
  );
}

function Stat({ label, value, mono }) {
  return (
    <div style={{ flexShrink: 0 }}>
      <div
        className="mono"
        style={{ fontSize: 10, letterSpacing: 0.5, color: 'var(--muted)', marginBottom: 3, whiteSpace: 'nowrap' }}
      >
        {label}
      </div>
      <div
        className={mono ? 'mono' : undefined}
        style={{ fontSize: 14.5, fontWeight: 600, color: 'var(--text)', whiteSpace: 'nowrap' }}
      >
        {value}
      </div>
    </div>
  );
}