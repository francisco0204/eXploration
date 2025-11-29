import requests
import urllib3
import ssl
import socket
import re
from urllib.parse import urljoin

# Desactiva warnings de certificados SSL no verificados
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SENSITIVE_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/.git/",
    "/.env",
    "/env",
    "/backup.zip",
    "/backup.sql",
    "/db.sql",
    "/database.sql",
    "/adminer.php",
    "/phpinfo.php",
    "/config.php",
    "/config.json",
    "/settings.json",
    "/.well-known/security.txt",
    "/.well-known/change-password",
    "/.well-known/assetlinks.json",
    "/debug",
    "/debug/",
    "/internal",
    "/internal/",
    "/test",
    "/test/",
    "/old",
    "/old/",
]

# Patrones simples para rutas de API dentro de JS
JS_ENDPOINT_PATTERNS = [
    r"/api/[a-zA-Z0-9_\-\/]*",
    r"/v1/[a-zA-Z0-9_\-\/]*",
    r"/v2/[a-zA-Z0-9_\-\/]*",
    r"/auth/[a-zA-Z0-9_\-\/]*",
    r"/admin/[a-zA-Z0-9_\-\/]*",
]


def analyze_cors(headers: dict) -> dict:
    """
    Analiza configuración básica de CORS.
    Devuelve origin, credentials y si es potencialmente riesgoso.
    """
    origin = headers.get("Access-Control-Allow-Origin")
    credentials = headers.get("Access-Control-Allow-Credentials")

    risky = False
    if origin == "*" and credentials and credentials.lower() == "true":
        
        risky = True

    return {
        "origin": origin,
        "credentials": credentials,
        "risky": risky,
    }


def scan_sensitive_paths(base_url: str) -> dict:
    """
    Escanea rutas 'sensibles' típicas.
    Devuelve path -> status_code para las que parecen existir.
    """
    found = {}

    for path in SENSITIVE_PATHS:
        url = urljoin(base_url, path)
        try:
            r = requests.get(url, timeout=4, verify=False, allow_redirects=True)
            if r.status_code in [200, 301, 302, 401, 403]:
                found[path] = r.status_code
        except Exception:
            continue

    return found


def _extract_script_urls(html: str, base_url: str) -> list:
    """
    Extrae URLs de <script src="..."> del HTML.
    Devuelve URLs absolutas.
    """
    urls = set()
    # Busca src en tags <script>
    for match in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, flags=re.IGNORECASE):
        src = match.strip()
        if src.startswith("http://") or src.startswith("https://"):
            urls.add(src)
        else:
            urls.add(urljoin(base_url, src))
    return list(urls)


def find_js_endpoints(base_url: str) -> set:
    """
    Descarga la página principal, busca scripts, descarga JS
    y extrae posibles endpoints interesantes.
    """
    endpoints = set()

    try:
        resp = requests.get(base_url, timeout=5, verify=False, allow_redirects=True)
        html = resp.text
    except Exception:
        return endpoints

    script_urls = _extract_script_urls(html, base_url)

    for js_url in script_urls:
        try:
            r = requests.get(js_url, timeout=5, verify=False)
            if r.status_code != 200:
                continue
            text = r.text
            
            if len(text) > 200_000:
                text = text[:200_000]

            for pattern in JS_ENDPOINT_PATTERNS:
                for match in re.findall(pattern, text):
                    endpoints.add(match)
        except Exception:
            continue

    return endpoints


def get_cert_names(hostname: str) -> set:
    """
    Intenta conectarse por HTTPS al hostname y extraer nombres
    del certificado (CN y SANs).
    """
    names = set()
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        # SubjectAltName
        for typ, val in cert.get("subjectAltName", []):
            if typ == "DNS":
                names.add(val.lower())

        # CommonName
        for entry in cert.get("subject", []):
            for key, val in entry:
                if key == "commonName":
                    names.add(val.lower())

    except Exception:
        pass

    return names
