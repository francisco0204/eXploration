import { useState } from 'react';
import Hero from './components/Hero';
import ScanningOverlay from './components/ScanningOverlay';
import TopBar from './components/TopBar';
import ResultsExplorer from './components/ResultsExplorer';

// En desarrollo local usa localhost:3000. En producción, seteá la variable de
// entorno VITE_API_URL en Vercel (ej: https://tu-backend.onrender.com/api/scan).
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000/api/scan';

// Cuánto dura la animación de salida del popup antes de mostrar resultados/error.
const CLOSE_ANIM_MS = 360;

export default function App() {
  const [status, setStatus] = useState('idle'); // idle | scanning | success | error
  const [closing, setClosing] = useState(false);
  const [target, setTarget] = useState('');
  const [data, setData] = useState(null);
  const [errorMsg, setErrorMsg] = useState('');

  async function handleScan(domain, mode, authorized) {
    setTarget(domain);
    setStatus('scanning');
    setClosing(false);
    setData(null);
    setErrorMsg('');

    let res;
    try {
      res = await fetch(API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: domain, mode, authorized }),
      });
    } catch (networkErr) {
      console.error(networkErr);
      setErrorMsg('No se pudo conectar con el backend. Revisá que esté corriendo en :3000.');
      finishScanning('error');
      return;
    }

    try {
      const json = await res.json();
      if (!res.ok || json.status !== 'success') {
        throw new Error(json.error || 'El escaneo falló. Intentá de nuevo.');
      }
      setData(json.data);
      finishScanning('success');
    } catch (err) {
      console.error(err);
      setErrorMsg(err.message);
      finishScanning('error');
    }
  }

  function finishScanning(nextStatus) {
    setClosing(true);
    setTimeout(() => {
      setStatus(nextStatus);
      setClosing(false);
    }, CLOSE_ANIM_MS);
  }

  function handleReset() {
    setStatus('idle');
    setData(null);
    setErrorMsg('');
  }

  const showResults = status === 'success' && data?.results?.length > 0;
  const showEmptySuccess = status === 'success' && data?.results?.length === 0;

  return (
    <div
      className="app-shell"
      style={{
        display: 'flex',
        flexDirection: 'column',
        paddingTop: 'env(safe-area-inset-top, 0px)',
      }}
    >
      {(status === 'idle' || status === 'scanning' || status === 'error') && (
        <div style={{ flex: 1, minHeight: 0 }}>
          <Hero onScan={handleScan} disabled={status === 'scanning'} />
          {status === 'error' && (
            <p
              className="mono"
              style={{
                position: 'fixed',
                bottom: 'max(20px, env(safe-area-inset-bottom, 0px))',
                left: '50%',
                transform: 'translateX(-50%)',
                color: 'var(--danger)',
                fontSize: 12.5,
                textAlign: 'center',
                maxWidth: '92vw',
                padding: '0 12px',
                animation: 'fadeUp 0.3s ease',
              }}
            >
              {errorMsg}
            </p>
          )}
        </div>
      )}

      {showResults && (
        <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column', animation: 'fadeUp 0.4s ease' }}>
          <TopBar summary={data} onReset={handleReset} />
          <ResultsExplorer results={data.results} />
        </div>
      )}

      {showEmptySuccess && (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
          <TopBar summary={data} onReset={handleReset} />
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24 }}>
            <p className="mono" style={{ color: 'var(--muted)', fontSize: 13, textAlign: 'center' }}>
              No se encontraron subdominios activos para {data.target}.
            </p>
          </div>
        </div>
      )}

      <ScanningOverlay active={status === 'scanning'} closing={closing} target={target} />
    </div>
  );
}