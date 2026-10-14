import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { execFile } from 'child_process';
import fs from 'fs';
import path from 'path';

const app = express();
const port = process.env.PORT || 3000;

// Cuántos escaneos pueden correr al mismo tiempo en este servidor.
const MAX_CONCURRENT_SCANS = 2;
let activeScans = 0;

// Cuánto esperamos a que termine un escaneo antes de matarlo. En local un
// DEEP tarda ~1 min, pero en un plan free con CPU compartida (0.1 CPU) puede
// tardar bastante más — Render en sí no tiene timeout corto, así que este
// límite es nuestro, configurable por si hace falta más margen.
const SCAN_TIMEOUT_MS = parseInt(process.env.SCAN_TIMEOUT_MS || '480000', 10); // 8 min default

// En Windows/local normalmente es "python". En los contenedores Linux de
// Render/Railway casi siempre es "python3". Configurable por las dudas.
const PYTHON_BIN = process.env.PYTHON_BIN || 'python';

// En desarrollo (sin CORS_ORIGIN seteado) dejamos cualquier origen.
// En producción, seteá CORS_ORIGIN=https://tu-front.vercel.app
// Normalizamos (trim + sin barra final) porque un espacio o "/" de más en la
// variable de entorno rompe el match silenciosamente y es muy difícil de ver.
const corsOrigin = (process.env.CORS_ORIGIN || '*').trim().replace(/\/+$/, '');
console.log(`[+] CORS_ORIGIN configurado como: "${corsOrigin}"`);
app.use(cors({ origin: corsOrigin }));
app.use(express.json({ limit: '10kb' })); // el body solo tiene target/mode/authorized, no hace falta más

// Máximo 5 escaneos por IP cada 15 minutos.
const scanLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Alcanzaste el límite de escaneos. Probá de nuevo en unos minutos.' },
});

// Formato real de dominio: labels de 1-63 caracteres alfanuméricos/guiones
// (sin guion al principio/final), al menos 2 labels separados por punto,
// largo total razonable. Esto es más estricto que solo filtrar caracteres,
// porque además rechaza cosas como "--" o ".." que pasarían un filtro simple.
const DOMAIN_REGEX =
    /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$/;

function isValidDomain(target) {
    return typeof target === 'string' && target.length <= 253 && DOMAIN_REGEX.test(target);
}

app.post('/api/scan', scanLimiter, (req, res) => {
    const { target, mode, authorized } = req.body ?? {};

    if (!target) {
        return res.status(400).json({ error: 'Falta el objetivo (target)' });
    }

    const cleanTarget = String(target).trim().toLowerCase();

    if (!isValidDomain(cleanTarget)) {
        return res.status(400).json({ error: 'Formato de dominio inválido' });
    }

    if (authorized !== true) {
        return res.status(400).json({
            error: 'Debés confirmar que tenés autorización para escanear este dominio.',
        });
    }

    if (activeScans >= MAX_CONCURRENT_SCANS) {
        return res.status(429).json({
            error: 'El servidor está ocupado con otro escaneo. Probá de nuevo en un minuto.',
        });
    }

    // "1" = FAST, "2" = DEEP. Si no mandan nada o mandan algo raro, default DEEP.
    const scanMode = ['1', '2'].includes(mode) ? mode : '2';

    console.log(`[+] Iniciando escaneo real para: ${cleanTarget} (modo ${scanMode})`);

    activeScans++;

    const jsonFileName = `resultados_${Date.now()}_${process.hrtime.bigint()}.json`;
    const rootDir = path.resolve(process.cwd(), '../../');
    const jsonFilePath = path.join(rootDir, jsonFileName);

    // execFile (no exec): los argumentos van como array, nunca se arman como
    // string de shell, así que no hay forma de inyectar comandos aunque
    // isValidDomain tuviera un agujero. Esto es la defensa real; la regex de
    // arriba es la segunda capa, no la única.
    const args = ['main.py', '-d', cleanTarget, '-m', scanMode, '--json', jsonFileName];

    execFile(
        PYTHON_BIN,
        args,
        {
            cwd: rootDir,
            env: { ...process.env, PYTHONIOENCODING: 'utf-8' },
            timeout: SCAN_TIMEOUT_MS,
            maxBuffer: 10 * 1024 * 1024,
        },
        (error, stdout, stderr) => {
            activeScans--;

            if (error) {
                const timedOut = error.killed || error.signal === 'SIGTERM';
                console.error(`[!] Error en el script de Python: ${error.message}`);
                return res.status(500).json({
                    error: timedOut
                        ? 'El escaneo tardó demasiado y se canceló. Probá con modo RÁPIDO o un dominio con menos subdominios.'
                        : 'Error ejecutando el escaneo',
                });
            }

            fs.readFile(jsonFilePath, 'utf8', (err, data) => {
                if (err) {
                    console.error(`[!] Error leyendo el JSON: ${err}`);
                    return res.status(500).json({ error: 'No se pudo leer el resultado' });
                }

                try {
                    const parsedData = JSON.parse(data);
                    fs.unlink(jsonFilePath, () => {}); // limpieza best-effort, no bloquea la respuesta

                    console.log(`[+] Escaneo finalizado y enviado al frontend.`);

                    res.json({
                        status: 'success',
                        data: parsedData,
                    });
                } catch (parseError) {
                    console.error(`[!] Error parseando el JSON: ${parseError}`);
                    res.status(500).json({ error: 'El JSON generado es inválido' });
                }
            });
        }
    );
});

app.listen(port, () => {
    console.log(`🚀 Backend (Real) corriendo en http://localhost:${port}`);
});