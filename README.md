# eXploration — Advanced Subdomain & Web Recon Scanner

**eXploration** es una herramienta avanzada de reconocimiento para dominios y aplicaciones web.

Combina enumeración de subdominios, análisis de infraestructura, fingerprinting web y detección de WAF/CDN en una sola CLI.

> Desarrollado por Francisco Cherbavaz — 2025  
> Orientado a bug bounty, pentesting y recon ofensivo/defensivo.

---

## Características principales

### Subdomain Enumeration

Fuente múltiples de OSINT + fuerza bruta:

- BufferOver
- crt.sh
- ThreatMiner
- AlienVault OTX
- Bruteforce con `wordlist.txt`

### DNS & Infra

- Resolución de subdominios a IP
- Filtrado de subdominios válidos
- Preparado para integración futura de ASN/Cloud

### Service & Banner Grabbing

- Detección de servicios en IPs objetivo
- Banners HTTP y HTTPS
- Información útil para fingerprinting de stack y middleware

###  Web Recon (modo DEEP)

- Detección de tecnologías
- Análisis de headers de seguridad (HSTS, CSP, X-Frame-Options, etc.)
- Detección de posibles paneles admin
- Análisis de CORS
- Búsqueda de rutas sensibles comunes
- Extracción de endpoints desde JS
- Obtención de nombres del certificado SSL
- Detección de endpoints API comunes

###  WAF & CDN Detection

**Doble capa de detección:**

1. **Detector básico (`waf_detector`)**
   - Identificación de CDN (Cloudflare, etc.)
   - Detección de WAF por headers y rangos IP

2. **Payload-Based WAF Detection (`waf_payload_detection`)**
   - Envía payloads típicos de:
     - SQL Injection
     - XSS
     - LFI / Path Traversal
     - Command Injection
   - Compara contra una respuesta baseline
   - Marca:
     - Respuestas que parecen página de bloqueo
     - Cambios de código HTTP (200 → 403/406/429)
   - Intenta fingerprint del vendor:
     - Cloudflare
     - Akamai
     - Sucuri
     - Imperva/Incapsula
     - F5 BIG-IP
     - ModSecurity

---

##  Instalación

Clona el repositorio y entra en la carpeta:

```bash
git clone https://github.com/TU-USUARIO/eXploration.git
cd eXploration
```

Instala las dependencias
```bash
pip install -r requirements.txt
```

Uso
Ejecutar:
```bash
python3 main.py
```

El programa te pedirá:
1. Un dominio objetivo, por ejemplo:
```bash
    Ingrese un dominio (ej: example.com): ejemplo.com
```
2. El modo de escaneo:
```bash
    [1] FAST (rápido, sin análisis profundo)
    [2] DEEP (completo, recon avanzado)
```

Estructura del proyecto
```bash
eXploration/
├── main.py                # Punto de entrada de la herramienta
├── modules/
│   ├── crtsh.py           # Integración con crt.sh
│   ├── bruteforce.py      # Bruteforce de subdominios
│   ├── resolver.py        # Resolución DNS
│   ├── bufferover.py      # Integración con BufferOver
│   ├── banner.py          # Banner grabbing
│   ├── threatminer.py     # Integración con ThreatMiner
│   ├── otx.py             # Integración con OTX (AlienVault)
│   ├── api_detector.py    # Detección de endpoints API comunes
│   ├── tech_and_security.py   # Tecnologías + headers de seguridad
│   ├── advanced_recon.py      # CORS, rutas sensibles, JS, SSL
│   ├── waf_detector.py        # WAF/CDN básico
│   └── waf_payload_detection.py # WAF detection basado en payloads
├── wordlist.txt           # Wordlist para bruteforce de subdominios
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
```

Roadmap (futuras versiones)

Descubrimiento de IP real detrás de Cloudflare / CDN

Reportes en JSON/HTML listos para clientes

Modo stealth (rate-limit aware, menos ruidoso)

Integración con Shodan/Censys (si se dispone de API key)

Exportación de resultados a archivos CSV/JSON

Esta herramienta está pensada para fines educativos y de seguridad ofensiva legítima.
Solo debe usarse en dominios sobre los que tienes autorización explícita.

El autor no se hace responsable del uso indebido.