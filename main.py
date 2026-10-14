import sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import argparse
import json
from modules.crtsh import get_subdomains_from_crtsh
from modules.bruteforce import bruteforce_subdomains
from modules.resolver import resolve_subdomains
from modules.bufferover import get_subdomains_from_bufferover
from modules.banner import process_ip
from modules.threatminer import get_subdomains_from_threatminer
from modules.otx import get_subdomains_from_otx

from modules.api_detector import detect_api_endpoints
from modules.tech_and_security import analyze_tech_and_security
from modules.advanced_recon import analyze_cors, scan_sensitive_paths, find_js_endpoints, get_cert_names
from modules.waf_detector import detect_waf_and_cdn
from modules.waf_payload_detection import detect_waf_for_url
from modules.cdn_bypass import detect_real_ip
from modules.cve_lookup import extract_software_banners, lookup_cves

from concurrent.futures import ThreadPoolExecutor, as_completed

# Subdominios en paralelo durante banner grabbing + análisis DEEP combinado.
# Cada tarea abre bastantes conexiones (port scan + ~5 módulos con sus propios
# sub-workers), así que no conviene ponerlo tan alto como los 30 que tenía
# el banner grabbing solo. Subilo/bajalo según cómo responda tu CPU/red.
PIPELINE_WORKERS = 12


def _json_safe(obj):
    """Convierte a algo serializable cualquier tipo que json.dump no entienda
    (sets, etc.) sin importar en qué módulo se haya generado."""
    if isinstance(obj, (set, frozenset)):
        return list(obj)
    return str(obj)


def _safe_source(func, args, label):
    """Corre una fuente de subdominios sin que una excepción tire abajo el
    resto de las fuentes que están corriendo en paralelo."""
    try:
        return label, func(*args)
    except Exception as e:
        print(f" - [{label}] no disponible ({e})")
        return label, set()


def analyze_subdomain(item, deep_scan):
    """Hace todo el análisis (pasos 8 a 16) para UN subdominio, a partir del
    resultado de banner grabbing (item)."""
    sub = item["subdomain"]
    ip = item["ip"]

    sub_data = {
        "subdomain": sub,
        "ip": ip,
        "open_ports": [p for p, state in item["ports"].items() if state],
        "http_banner": item["http"],
        "https_banner": item["https"],
    }

    if not deep_scan:
        return sub_data

    analysis = {"raw_headers": {}, "url": f"https://{sub}"}

    try:
        sub_data["api_endpoints"] = detect_api_endpoints(sub)
    except Exception as e:
        sub_data["api_endpoints"] = {}
        print(f"  [!] {sub}: error en api_detector -> {e}")

    try:
        analysis = analyze_tech_and_security(sub, use_https=True)
        sub_data["technologies"] = analysis["technologies"]
        sub_data["security_headers"] = analysis["security_headers"]
        sub_data["admin_endpoints"] = analysis["admin_endpoints"]
    except Exception as e:
        sub_data["technologies"] = []
        sub_data["security_headers"] = {}
        sub_data["admin_endpoints"] = {}
        print(f"  [!] {sub}: error en tech_and_security -> {e}")

    try:
        sub_data["cors"] = analyze_cors(analysis["raw_headers"])
    except Exception as e:
        sub_data["cors"] = {}
        print(f"  [!] {sub}: error en analyze_cors -> {e}")

    try:
        software = extract_software_banners(analysis["raw_headers"])
        sub_data["cves"] = lookup_cves(software) if software else []
    except Exception as e:
        sub_data["cves"] = []
        print(f"  [!] {sub}: error en cve_lookup -> {e}")

    base_url = analysis["url"]

    try:
        sub_data["sensitive_paths"] = scan_sensitive_paths(base_url)
    except Exception as e:
        sub_data["sensitive_paths"] = {}
        print(f"  [!] {sub}: error en scan_sensitive_paths -> {e}")

    try:
        sub_data["js_endpoints"] = find_js_endpoints(base_url)
    except Exception as e:
        sub_data["js_endpoints"] = []
        print(f"  [!] {sub}: error en find_js_endpoints -> {e}")

    if 443 in sub_data["open_ports"]:
        try:
            sub_data["ssl_certs"] = get_cert_names(sub)
        except Exception as e:
            sub_data["ssl_certs"] = []
            print(f"  [!] {sub}: error en get_cert_names -> {e}")
    else:
        sub_data["ssl_certs"] = []

    try:
        sub_data["waf_cdn"] = detect_waf_and_cdn(
            subdomain=sub,
            ip=ip,
            headers=analysis["raw_headers"],
            body=item["http"] or item["https"] or "",
            status=200,
        )
    except Exception as e:
        sub_data["waf_cdn"] = []
        print(f"  [!] {sub}: error en detect_waf_and_cdn -> {e}")

    try:
        sub_data["waf_payload"] = detect_waf_for_url(f"https://{sub}")
    except Exception as e:
        sub_data["waf_payload"] = {}
        print(f"  [!] {sub}: error en detect_waf_for_url -> {e}")

    try:
        sub_data["real_ip"] = detect_real_ip(sub, ip)
    except Exception as e:
        sub_data["real_ip"] = {}
        print(f"  [!] {sub}: error en detect_real_ip -> {e}")

    print(f"[+] Análisis completo: {sub}")
    return sub_data


def process_target(target, deep_scan):
    """Pipeline completo de UN subdominio: banner grabbing + análisis DEEP,
    pensado para correr como una sola tarea dentro del pool."""
    banner = process_ip(target)
    return analyze_subdomain(banner, deep_scan)


def main():
    parser = argparse.ArgumentParser(description="eXploration - Advanced Recon")
    parser.add_argument("-d", "--domain", required=True, help="Dominio objetivo (ej: example.com)")
    parser.add_argument("-m", "--mode", choices=["1", "2"], default="2", help="Modo: 1 (FAST) o 2 (DEEP)")
    parser.add_argument("--json", help="Ruta para exportar el resultado en JSON", default=None)
    args = parser.parse_args()

    domain = args.domain.strip()
    deep_scan = (args.mode == "2")

    export_data = {
        "target": domain,
        "mode": "DEEP" if deep_scan else "FAST",
        "total_subdomains": 0,
        "results": [],
    }

    print(f"\nModo seleccionado: {'DEEP' if deep_scan else 'FAST'}\n")

    # ============================
    # 1-5 - Todas las fuentes de subdominios EN PARALELO
    # ============================
    print("[1-5] Recolectando subdominios (BufferOver, crt.sh, ThreatMiner, OTX, Bruteforce) en paralelo...\n")

    sources = [
        (get_subdomains_from_bufferover, (domain,), "BufferOver"),
        (get_subdomains_from_crtsh, (domain,), "crt.sh"),
        (get_subdomains_from_threatminer, (domain,), "ThreatMiner"),
        (get_subdomains_from_otx, (domain,), "OTX"),
        (bruteforce_subdomains, (domain, "wordlist.txt"), "Bruteforce"),
    ]

    gathered = {}
    with ThreadPoolExecutor(max_workers=len(sources)) as executor:
        futures = {executor.submit(_safe_source, fn, fn_args, label): label for fn, fn_args, label in sources}
        for future in as_completed(futures):
            label, result = future.result()
            gathered[label] = result
            print(f" - {label}: {len(result)} encontrados")

    # ============================
    # UNIÓN
    # ============================
    all_subdomains = set().union(*gathered.values()) if gathered else set()

    export_data["total_subdomains"] = len(all_subdomains)
    print(f"\nTotal subdominios únicos: {len(all_subdomains)}\n")

    # ============================
    # 6 - Resolver DNS
    # ============================
    print("[6] Resolviendo subdominios...\n")
    resolved = resolve_subdomains(all_subdomains)
    print(f"Subdominios válidos: {len(resolved)}")

    for item in resolved[:50]:
        print(f" - {item['subdomain']} -> {item['ip']}")

    # ============================
    # 7-16 - PIPELINE POR SUBDOMINIO (banner grabbing + análisis DEEP juntos)
    # ============================
    targets = resolved[:50]
    print(f"\n[7-16] Procesando {len(targets)} subdominios ({PIPELINE_WORKERS} en paralelo)...\n")

    with ThreadPoolExecutor(max_workers=PIPELINE_WORKERS) as executor:
        futures = [executor.submit(process_target, t, deep_scan) for t in targets]
        for future in futures:
            export_data["results"].append(future.result())

    # ============================
    # EXPORTACIÓN A JSON FINAL
    # ============================
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=4, default=_json_safe)
        print(f"\n[+] Resultados guardados exitosamente en {args.json}\n")


if __name__ == "__main__":
    main()