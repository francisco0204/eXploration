import os
import re
import threading
import time
import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Si tenés una API key gratuita de NVD (https://nvd.nist.gov/developers/request-an-api-key),
# ponela en esta variable de entorno para subir el límite de 5 a 50 requests/30s.
NVD_API_KEY = os.environ.get("NVD_API_KEY")

# Throttle global: la API pública de NVD banea si te pasás de 5 req/30s sin key
# (50/30s con key). Esto lo respeta entre TODOS los threads, no por thread.
_WINDOW_SECONDS = 30
_MAX_REQUESTS = 45 if NVD_API_KEY else 4
_request_times = []
_throttle_lock = threading.Lock()

# Patrón "producto/version" o "producto version" típico de headers Server / X-Powered-By
_VERSION_PATTERN = re.compile(r"([A-Za-z][A-Za-z0-9_.+-]{1,30})[/ ]([0-9]+(?:\.[0-9]+){1,3})")


def _throttle():
    """Bloquea lo necesario para no superar el rate limit de NVD entre todos los threads."""
    with _throttle_lock:
        now = time.time()
        _request_times[:] = [t for t in _request_times if now - t < _WINDOW_SECONDS]
        if len(_request_times) >= _MAX_REQUESTS:
            sleep_for = _WINDOW_SECONDS - (now - _request_times[0]) + 0.2
            time.sleep(max(sleep_for, 0))
            now = time.time()
            _request_times[:] = [t for t in _request_times if now - t < _WINDOW_SECONDS]
        _request_times.append(time.time())


def extract_software_banners(headers: dict) -> list:
    """
    Busca strings tipo 'nginx 1.18.0' en headers Server / X-Powered-By.
    Ignora valores sin número de versión (ej: 'nginx' solo, sin versión,
    da demasiados falsos positivos en la búsqueda de CVEs).
    """
    found = []
    for header_name in ("Server", "X-Powered-By"):
        value = headers.get(header_name, "")
        if not value:
            continue
        match = _VERSION_PATTERN.search(value)
        if match:
            software = f"{match.group(1)} {match.group(2)}"
            if software not in found:
                found.append(software)
    return found


def _extract_severity(metrics: dict):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            severity = entries[0].get("baseSeverity") or cvss_data.get("baseSeverity")
            score = cvss_data.get("baseScore")
            return severity, score
    return None, None


def lookup_cves(software_list: list, max_per_software: int = 5, max_total: int = 8, timeout: int = 8) -> list:
    """
    Busca CVEs conocidos para cada string 'producto version' usando la API
    pública de NVD (keywordSearch). Devuelve una lista ordenada por severidad
    (los más críticos primero), máximo max_total resultados.
    """
    results = []
    seen = set()

    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

    for software in software_list:
        try:
            _throttle()
            r = requests.get(
                NVD_API_URL,
                params={"keywordSearch": software, "resultsPerPage": max_per_software},
                headers=headers,
                timeout=timeout,
            )
            if r.status_code != 200:
                continue

            data = r.json()
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id")
                if not cve_id or cve_id in seen:
                    continue
                seen.add(cve_id)

                descriptions = cve.get("descriptions", [])
                summary = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

                severity, score = _extract_severity(cve.get("metrics", {}))

                results.append({
                    "software": software,
                    "cve_id": cve_id,
                    "severity": severity,
                    "score": score,
                    "summary": summary[:320],
                })
        except Exception:
            continue

    results.sort(key=lambda x: (x["score"] if x["score"] is not None else -1), reverse=True)
    return results[:max_total]