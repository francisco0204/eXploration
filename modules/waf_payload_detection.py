import requests
import concurrent.futures
import urllib.parse
from typing import Dict, List, Any, Optional

# Timeout por defecto para las requests
DEFAULT_TIMEOUT = 7
DEFAULT_WORKERS = 10

# Payloads básicos
PAYLOADS = [
    # SQLi
    "' OR '1'='1",
    "' UNION SELECT NULL--",
    "'; DROP TABLE users;--",
    # XSS
    "<script>alert(1)</script>",
    "\" onmouseover=\"alert(1)",
    # LFI / path traversal
    "../../etc/passwd",
    "../../../../../../windows/win.ini",
    # Comandos
    "; cat /etc/passwd",
    "|| ping -c 1 127.0.0.1 ||",
]

# Frases típicas en páginas de bloqueo
BLOCK_STRINGS = [
    "access denied",
    "request blocked",
    "forbidden",
    "not allowed",
    "malicious",
    "suspicious",
    "waf",
    "web application firewall",
    "your request has been blocked",
    "security check",
    "mod_security",
]

# Signatures simples 
WAF_SIGNATURES = {
    "Cloudflare": [
        "cloudflare",
        "__cfduid",
        "cf-ray",
        "cf-cache-status",
    ],
    "Akamai": [
        "akamai",
        "akamai ghost",
        "akamaiGHost",
    ],
    "Sucuri": [
        "sucuri",
        "x-sucuri-id",
        "sucuri cloudproxy",
    ],
    "Imperva/Incapsula": [
        "incapsula",
        "imperva",
    ],
    "F5 BIG-IP": [
        "bigip",
        "f5 networks",
    ],
    "ModSecurity": [
        "mod_security",
        "modsecurity",
    ],
}


def _safe_request(
    method: str,
    url: str,
    params: Optional[Dict[str, str]] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Optional[requests.Response]:
    """
    Envuelve una request de requests para que nunca rompa el flujo del programa.
    Devuelve None si hay error (timeout, SSL, conexión, etc).
    """
    try:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (compatible; SubdomainScanner/1.0; "
                "+https://example.com)"
            )
        }
        resp = requests.request(
            method=method,
            url=url,
            params=params,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
            verify=False,  
        )
        return resp
    except requests.RequestException:
        return None


def _extract_basic_info(resp: requests.Response) -> Dict[str, Any]:
    """
    Extrae info básica de una respuesta para luego compararla.
    """
    body = resp.text or ""
    return {
        "status_code": resp.status_code,
        "headers": {k.lower(): v for k, v in resp.headers.items()},
        "body_length": len(body),
        "body_sample": body[:500].lower(),
    }


def _guess_waf_vendor(headers: Dict[str, str], body_sample: str) -> Optional[str]:
    """
    Usa headers + body_sample para intentar adivinar el WAF.
    """
    text_to_search = " ".join(
        [headers.get("server", ""), headers.get("via", ""), body_sample]
    ).lower()

    for vendor, sigs in WAF_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in text_to_search:
                return vendor

    return None


def _looks_like_block_page(info: Dict[str, Any]) -> bool:
    """
    Determina si la respuesta 'parece' una página de bloqueo.
    """
    status = info["status_code"]
    body_sample = info["body_sample"]

    
    if status in (403, 406, 429):
        return True

    
    for word in BLOCK_STRINGS:
        if word in body_sample:
            return True

    return False


def detect_waf_for_url(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """
    Hace detección de WAF para una sola URL usando payloads.

    Devuelve un dict con:
    - url
    - waf_detected (bool)
    - vendor (str | None)
    - reason (str)
    - baseline (info básica)
    - payload_results (lista de resultados por payload)
    """

    
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    result: Dict[str, Any] = {
        "url": url,
        "waf_detected": False,
        "vendor": None,
        "reason": "",
        "baseline": None,
        "payload_results": [],
    }

    # 1) Request base
    baseline_resp = _safe_request("GET", url, timeout=timeout)
    if baseline_resp is None:
        result["reason"] = "No se pudo obtener respuesta base"
        return result

    baseline_info = _extract_basic_info(baseline_resp)
    result["baseline"] = baseline_info

    # 2) Probar payloads en un parámetro de query (ej: ?q=PAYLOAD)
    payload_results = []

    for payload in PAYLOADS:
        params = {"q": payload}
        resp = _safe_request("GET", url, params=params, timeout=timeout)
        if resp is None:
            payload_results.append(
                {
                    "payload": payload,
                    "error": "sin_respuesta",
                }
            )
            continue

        info = _extract_basic_info(resp)
        blocked = _looks_like_block_page(info)

        payload_results.append(
            {
                "payload": payload,
                "status_code": info["status_code"],
                "body_length": info["body_length"],
                "blocked_like": blocked,
            }
        )

    result["payload_results"] = payload_results

    # 3) Analizar diferencias entre baseline y payloads
    baseline_status = baseline_info["status_code"]
    baseline_len = baseline_info["body_length"]

    blocked_count = 0
    different_status_count = 0

    for pr in payload_results:
        if "error" in pr:
            continue

        if pr["blocked_like"]:
            blocked_count += 1

        if pr["status_code"] != baseline_status:
            different_status_count += 1

        
        if abs(pr["body_length"] - baseline_len) > (baseline_len * 0.5 + 2000):
            
            pr["blocked_like"] = True
            blocked_count += 1

    if blocked_count > 0 or different_status_count >= 2:
        result["waf_detected"] = True
        result["reason"] = (
            f"Se detectaron {blocked_count} respuestas que parecen bloqueo "
            f"y {different_status_count} códigos distintos al baseline."
        )

        
        vendor = _guess_waf_vendor(
            baseline_info["headers"], baseline_info["body_sample"]
        )
        if vendor:
            result["vendor"] = vendor

    else:
        result["reason"] = (
            "No se observaron cambios significativos entre requests normales "
            "y con payloads maliciosos."
        )

    return result


def detect_waf_for_multiple_urls(
    urls: List[str],
    timeout: int = DEFAULT_TIMEOUT,
    max_workers: int = DEFAULT_WORKERS,
) -> List[Dict[str, Any]]:
    """
    Corre la detección de WAF con payloads para muchas URLs en paralelo.
    """
    results: List[Dict[str, Any]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {
            executor.submit(detect_waf_for_url, url, timeout): url for url in urls
        }
        for future in concurrent.futures.as_completed(future_to_url):
            try:
                res = future.result()
                results.append(res)
            except Exception:
                
                url = future_to_url[future]
                results.append(
                    {
                        "url": url,
                        "waf_detected": False,
                        "vendor": None,
                        "reason": "Error interno al analizar la URL",
                        "baseline": None,
                        "payload_results": [],
                    }
                )

    return results
