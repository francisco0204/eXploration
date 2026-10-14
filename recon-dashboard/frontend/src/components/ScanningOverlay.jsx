import { useEffect, useState } from 'react';

const SCAN_STAGES = [
  'Consultando BufferOver…',
  'Consultando crt.sh…',
  'Consultando ThreatMiner…',
  'Consultando AlienVault OTX…',
  'Bruteforce de subdominios…',
  'Resolviendo DNS…',
  'Escaneando puertos…',
  'Banner grabbing HTTP/HTTPS…',
  'Detectando tecnologías…',
  'Revisando headers de seguridad…',
  'Buscando paneles admin…',
  'Revisando CORS…',
  'Buscando rutas sensibles…',
  'Extrayendo endpoints de JS…',
  'Leyendo certificados SSL…',
  'Detectando WAF / CDN…',
  'Probando payloads contra el WAF…',
  'Buscando IP real detrás del CDN…',
];

export default function ScanningOverlay({ active, closing, target }) {
  const [stageIndex, setStageIndex] = useState(0);

  useEffect(() => {
    if (!active) return;
    setStageIndex(0);
    const id = setInterval(() => setStageIndex((i) => (i + 1) % SCAN_STAGES.length), 1500);
    return () => clearInterval(id);
  }, [active]);

  if (!active) return null;

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'rgba(5, 7, 11, 0.6)',
        backdropFilter: 'blur(3px)',
        animation: `${closing ? 'backdropOut' : 'backdropIn'} 0.3s ease forwards`,
        zIndex: 50,
        padding: 16,
      }}
    >
      <div
        style={{
          width: 'min(340px, 88vw)',
          background: 'var(--surface)',
          border: '1px solid var(--line)',
          borderRadius: 16,
          padding: 'clamp(24px, 7vw, 32px) clamp(20px, 6vw, 28px)',
          textAlign: 'center',
          boxShadow: '0 30px 80px -20px rgba(0,0,0,0.7)',
          animation: `${closing ? 'popOut' : 'popIn'} 0.32s cubic-bezier(.2,.8,.2,1) forwards`,
        }}
      >
        <div
          style={{
            width: 46,
            height: 46,
            margin: '0 auto 20px',
            borderRadius: '50%',
            border: '3px solid var(--line)',
            borderTopColor: 'var(--signal)',
            animation: 'spin 0.85s linear infinite',
          }}
        />
        <p className="mono" style={{ margin: 0, fontSize: 13, fontWeight: 700, color: 'var(--text)', wordBreak: 'break-word' }}>
          Escaneando {target}
        </p>
        <p
          key={stageIndex}
          className="mono"
          style={{
            margin: '10px 0 0',
            fontSize: 12.5,
            color: 'var(--signal)',
            minHeight: 18,
            animation: 'fadeIn 0.25s ease',
          }}
        >
          {SCAN_STAGES[stageIndex]}
        </p>
        <p style={{ margin: '18px 0 0', fontSize: 11.5, color: 'var(--muted)', lineHeight: 1.5 }}>
          Un escaneo DEEP puede tardar alrededor de un minuto.
        </p>
      </div>
    </div>
  );
}