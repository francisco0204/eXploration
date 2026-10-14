import { useState } from 'react';

export default function Hero({ onScan, disabled }) {
  const [value, setValue] = useState('');
  const [mode, setMode] = useState('2'); // '2' = DEEP, '1' = FAST
  const [authorized, setAuthorized] = useState(false);
  const [infoOpen, setInfoOpen] = useState(false);

  const canSubmit = value.trim().length > 0 && authorized && !disabled;

  function submit(e) {
    e.preventDefault();
    const clean = value.trim().replace(/^https?:\/\//, '').replace(/\/$/, '');
    if (!clean || !authorized || disabled) return;
    onScan(clean, mode, authorized);
  }

  return (
    <div
      style={{
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 'clamp(16px, 6vw, 24px)',
        filter: disabled ? 'blur(6px)' : 'none',
        opacity: disabled ? 0.5 : 1,
        transition: 'filter 0.3s ease, opacity 0.3s ease',
        animation: 'fadeUp 0.5s ease',
        pointerEvents: disabled ? 'none' : 'auto',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          marginBottom: 'clamp(20px, 6vw, 28px)',
        }}
      >
        <span
          style={{
            width: 9,
            height: 9,
            borderRadius: '50%',
            background: 'var(--signal)',
            boxShadow: '0 0 10px var(--signal)',
          }}
        />
        <span className="mono" style={{ fontSize: 15, fontWeight: 700, color: 'var(--muted)' }}>
          eXploration
        </span>
      </div>

      <h1
        className="mono"
        style={{
          margin: 0,
          fontSize: 'clamp(22px, 7vw, 38px)',
          fontWeight: 700,
          textAlign: 'center',
          maxWidth: 680,
          lineHeight: 1.3,
        }}
      >
        Reconocé un dominio en segundos
      </h1>
      <p
        style={{
          color: 'var(--muted)',
          fontSize: 'clamp(13px, 3.4vw, 14.5px)',
          textAlign: 'center',
          maxWidth: 460,
          margin: 'clamp(10px, 3vw, 14px) 0 clamp(26px, 7vw, 36px)',
          padding: '0 8px',
        }}
      >
        Subdominios, puertos, tecnologías, headers de seguridad y WAF/CDN — todo en una
        pasada.
      </p>

      <form onSubmit={submit} style={{ width: '100%', maxWidth: 560 }}>
        <div
          className="mono"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            background: 'var(--surface)',
            border: '1px solid var(--line)',
            borderRadius: 12,
            padding: '6px 6px 6px clamp(12px, 4vw, 18px)',
            boxShadow: '0 20px 60px -20px rgba(0,0,0,0.6)',
          }}
        >
          <span style={{ color: 'var(--signal)', fontSize: 16, flexShrink: 0 }}>❯</span>
          <input
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="ejemplo.com"
            autoCapitalize="none"
            autoCorrect="off"
            style={{
              flex: 1,
              minWidth: 0,
              background: 'transparent',
              border: 'none',
              outline: 'none',
              color: 'var(--text)',
              fontFamily: 'var(--mono)',
              fontSize: 16, // 16px fijo: evita el zoom automático de iOS al enfocar el input
              padding: '14px 0',
            }}
          />
          <button
            type="submit"
            disabled={!canSubmit}
            className="mono"
            style={{
              background: canSubmit ? 'var(--signal)' : 'var(--surface-2)',
              color: canSubmit ? '#1a0f04' : 'var(--muted)',
              border: 'none',
              borderRadius: 8,
              padding: '14px clamp(14px, 4vw, 22px)',
              fontSize: 13,
              fontWeight: 700,
              letterSpacing: 0.3,
              cursor: value.trim() ? 'pointer' : 'default',
              whiteSpace: 'nowrap',
              flexShrink: 0,
            }}
          >
            ESCANEAR
          </button>
        </div>

        <p
          className="mono"
          style={{
            textAlign: 'center',
            color: 'var(--muted)',
            fontSize: 11.5,
            marginTop: 14,
            letterSpacing: 0.2,
            padding: '0 8px',
          }}
        >
          Escaneá tu dominio o subdominio aquí — sin el http:// ni la barra final
        </p>

        <div
          style={{
            display: 'flex',
            justifyContent: 'center',
            gap: 6,
            marginTop: 'clamp(16px, 5vw, 22px)',
          }}
        >
          <ModeButton active={mode === '1'} onClick={() => setMode('1')} label="RÁPIDO" hint="Solo subdominios + puertos" />
          <ModeButton active={mode === '2'} onClick={() => setMode('2')} label="DEEP" hint="Análisis completo de seguridad" />
        </div>

        <p
          style={{
            textAlign: 'center',
            color: 'var(--muted)',
            fontSize: 12,
            marginTop: 10,
            padding: '0 12px',
            lineHeight: 1.5,
          }}
        >
          {mode === '1'
            ? 'Enumera subdominios y chequea qué puertos tienen abiertos. Lo más rápido.'
            : 'Además analiza tecnologías, headers de seguridad, CORS, rutas sensibles, paneles admin y WAF/CDN de cada subdominio. ~1 minuto.'}
        </p>

        <button
          type="button"
          onClick={() => setInfoOpen((v) => !v)}
          className="mono"
          style={{
            display: 'block',
            margin: 'clamp(16px, 5vw, 20px) auto 0',
            background: 'transparent',
            border: 'none',
            color: 'var(--signal)',
            fontSize: 12,
            fontWeight: 600,
            letterSpacing: 0.2,
            cursor: 'pointer',
            padding: '6px 10px',
          }}
        >
          {infoOpen ? '− Ocultar detalle' : 'ⓘ ¿Qué hace esta herramienta?'}
        </button>

        {infoOpen && (
          <div
            style={{
              marginTop: 10,
              background: 'var(--surface)',
              border: '1px solid var(--line)',
              borderRadius: 12,
              padding: 'clamp(16px, 5vw, 22px)',
              animation: 'fadeUp 0.3s ease',
              textAlign: 'left',
            }}
          >
            <InfoBlock title="Qué analiza">
              Enumera subdominios cruzando BufferOver, crt.sh, ThreatMiner, AlienVault OTX y
              fuerza bruta contra una wordlist. A cada uno que resuelve le revisa puertos
              abiertos, banners HTTP/HTTPS, tecnologías, headers de seguridad, CORS, paneles
              admin, rutas sensibles, endpoints de API y de JS, certificado SSL, y detección
              de WAF/CDN — incluyendo un intento de encontrar la IP real detrás del CDN.
            </InfoBlock>
            <InfoBlock title="Modo RÁPIDO" last={false}>
              Solo descubre subdominios y chequea qué puertos (21, 22, 25, 80, 443, 8080)
              están abiertos. No manda payloads ni analiza seguridad. Pensado para un
              reconocimiento inicial veloz.
            </InfoBlock>
            <InfoBlock title="Modo DEEP" last>
              Todo lo anterior, más el análisis de seguridad completo por subdominio:
              headers, CORS, rutas sensibles, paneles admin, y pruebas activas de WAF con
              payloads de SQLi/XSS/LFI/command injection. Tarda más (~1 minuto) porque hace
              muchas más requests.
            </InfoBlock>
          </div>
        )}

        <label
          style={{
            display: 'flex',
            alignItems: 'flex-start',
            gap: 10,
            marginTop: 'clamp(18px, 5vw, 24px)',
            padding: '0 8px',
            cursor: 'pointer',
          }}
        >
          <input
            type="checkbox"
            checked={authorized}
            onChange={(e) => setAuthorized(e.target.checked)}
            style={{
              width: 18,
              height: 18,
              marginTop: 1,
              flexShrink: 0,
              accentColor: 'var(--signal)',
              cursor: 'pointer',
            }}
          />
          <span style={{ fontSize: 12.5, color: 'var(--muted)', lineHeight: 1.5 }}>
            Confirmo que soy dueño de este dominio o tengo autorización explícita para
            escanearlo. Esta herramienta prueba payloads de seguridad (SQLi, XSS, fuerza
            bruta de rutas) contra el objetivo.
          </span>
        </label>
      </form>
    </div>
  );
}

function InfoBlock({ title, children, last }) {
  return (
    <div style={{ marginBottom: last ? 0 : 16 }}>
      <div
        className="mono"
        style={{ fontSize: 11, fontWeight: 700, color: 'var(--signal)', marginBottom: 6, letterSpacing: 0.3 }}
      >
        {title}
      </div>
      <p style={{ margin: 0, fontSize: 12.5, color: 'var(--muted)', lineHeight: 1.6 }}>{children}</p>
    </div>
  );
}

function ModeButton({ active, onClick, label, hint }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="mono"
      title={hint}
      style={{
        background: active ? 'rgba(255,138,66,0.12)' : 'transparent',
        color: active ? 'var(--signal)' : 'var(--muted)',
        border: `1px solid ${active ? 'var(--signal-dim)' : 'var(--line)'}`,
        borderRadius: 999,
        padding: '9px 16px',
        fontSize: 11.5,
        fontWeight: 700,
        letterSpacing: 0.4,
        cursor: 'pointer',
      }}
    >
      {label}
    </button>
  );
}