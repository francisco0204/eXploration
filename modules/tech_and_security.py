import requests
import urllib3

# Desactivar warnings de certificados 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Endpoints típicos de paneles admin / login
COMMON_ADMIN_ENDPOINTS = [
    "/admin",
    "/admin/",
    "/login",
    "/login/",
    "/wp-admin",
    "/wp-login.php",
    "/cpanel",
    "/dashboard",
    "/user/login",
    "/manager",
]


def fingerprint_technologies(html: str, headers: dict) -> list:
    """
    Devuelve una lista de 'tags' de tecnologías detectadas
    basadas en headers y en el HTML.
    """
    techs = set()
    server = headers.get("Server", "").lower()
    powered = headers.get("X-Powered-By", "").lower()

    text = (html or "").lower()

    # Servidores
    if "apache" in server:
        techs.add("Apache")
    if "nginx" in server:
        techs.add("Nginx")
    if "cloudflare" in server:
        techs.add("Cloudflare")
    if "litespeed" in server:
        techs.add("LiteSpeed")

    # CMS / plataformas
    if "wp-content" in text or "wp-json" in text:
        techs.add("WordPress")
    if "shopify" in text or "x-shopify-stage" in headers:
        techs.add("Shopify")
    if "kajabi" in text or "x-kajabi" in headers:
        techs.add("Kajabi")
    if "squarespace" in text:
        techs.add("Squarespace")
    if "wix.com" in text or "wix-static" in text:
        techs.add("Wix")
    if "ghost" in text:
        techs.add("Ghost CMS")

    # Frameworks / runtimes
    if "php" in powered:
        techs.add("PHP")
    if "express" in powered or "x-powered-by" in headers and "express" in powered:
        techs.add("Node.js / Express")
    if "asp.net" in powered or "asp.net" in server:
        techs.add("ASP.NET")
    if "django" in text:
        techs.add("Django")
    if "laravel" in text:
        techs.add("Laravel")

    # Frontend
    if "react" in text or "next.js" in text:
        techs.add("React / Next.js")
    if "vue" in text:
        techs.add("Vue.js")
    if "angular" in text:
        techs.add("Angular")

    return sorted(techs)


def analyze_security_headers(headers: dict) -> dict:
    """
    Revisa presencia de headers de seguridad importantes.
    True = presente, False = ausente.
    """
    checks = {
        "Strict-Transport-Security": "hsts",
        "Content-Security-Policy": "csp",
        "X-Frame-Options": "x_frame_options",
        "X-Content-Type-Options": "x_content_type_options",
        "Referrer-Policy": "referrer_policy",
    }

    result = {}
    for header_name, key in checks.items():
        result[key] = header_name in headers

    return result


def check_admin_endpoints(base_url: str) -> dict:
    """
    Chequea algunos endpoints típicos de admin/login.
    Devuelve endpoint -> status_code (o None si no respondió).
    """
    found = {}

    for endpoint in COMMON_ADMIN_ENDPOINTS:
        url = base_url + endpoint
        try:
            r = requests.get(url, timeout=4, verify=False, allow_redirects=True)
            
            if r.status_code in [200, 301, 302, 401, 403]:
                found[endpoint] = r.status_code
        except Exception:
            continue

    return found


def analyze_tech_and_security(subdomain: str, use_https: bool = True) -> dict:
    """
    Hace:
      - petición al sitio (HTML + headers)
      - fingerprint de tecnologías
      - análisis de headers de seguridad
      - búsqueda de paneles admin
    """
    protocol = "https" if use_https else "http"
    base_url = f"{protocol}://{subdomain}"

    try:
        resp = requests.get(base_url, timeout=5, verify=False, allow_redirects=True)
        html = resp.text[:50000] 
        headers = {k: v for k, v in resp.headers.items()}
    except Exception:
        html = ""
        headers = {}

    techs = fingerprint_technologies(html, headers)
    security = analyze_security_headers(headers)
    admin_endpoints = check_admin_endpoints(base_url)

    return {
        "url": base_url,
        "technologies": techs,
        "security_headers": security,
        "admin_endpoints": admin_endpoints,
        "raw_headers": headers,
    }
