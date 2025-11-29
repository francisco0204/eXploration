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

from concurrent.futures import ThreadPoolExecutor


def main():
    domain = input("Ingrese un dominio (ej: example.com): ").strip()

    print("\nSeleccione modo de escaneo:")
    print("[1] FAST (rápido, sin análisis profundo)")
    print("[2] DEEP (completo, recon avanzado)")
    mode = input("Opción: ").strip()

    deep_scan = (mode == "2")
    print(f"\nModo seleccionado: {'DEEP' if deep_scan else 'FAST'}\n")

    # ============================
    # 1 - BufferOver
    # ============================
    print(f"[1] Obteniendo subdominios de BufferOver...")
    try:
        subs_bufferover = get_subdomains_from_bufferover(domain)
        print(f" - {len(subs_bufferover)} encontrados")
    except:
        subs_bufferover = set()
        print(" - No disponible")

    # ============================
    # 2 - crt.sh
    # ============================
    print(f"\n[2] Obteniendo subdominios de crt.sh...")
    subs_crtsh = get_subdomains_from_crtsh(domain)
    print(f" - {len(subs_crtsh)} encontrados")

    # ============================
    # 3 - ThreatMiner
    # ============================
    print(f"\n[3] Obteniendo subdominios de ThreatMiner...")
    subs_tm = get_subdomains_from_threatminer(domain)
    print(f" - {len(subs_tm)} encontrados")

    # ============================
    # 4 - OTX
    # ============================
    print(f"\n[4] Obteniendo subdominios de OTX...")
    subs_otx = get_subdomains_from_otx(domain)
    print(f" - {len(subs_otx)} encontrados")

    # ============================
    # 5 - Bruteforce
    # ============================
    print(f"\n[5] Bruteforce de subdominios...")
    subs_bruteforce = bruteforce_subdomains(domain, "wordlist.txt")
    print(f" - {len(subs_bruteforce)} encontrados")

    # ============================
    # UNIÓN 
    # ============================
    all_subdomains = set().union(
        subs_bufferover,
        subs_crtsh,
        subs_tm,
        subs_otx,
        subs_bruteforce
    )

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
    # 7 - Banner grabbing (paralelo)
    # ============================
    print(f"\n[7] Banner grabbing en paralelo...\n")

    targets = resolved[:50]  # limitar

    results = []
    with ThreadPoolExecutor(max_workers=30) as executor:
        for item in executor.map(process_ip, targets):
            results.append(item)

    # ============================
    # ANÁLISIS POR SUBDOMINIO
    # ============================
    for r in results:
        sub = r["subdomain"]
        ip = r["ip"]

        print("\n====================================")
        print(f"=== {sub} ({ip}) ===")
        print("====================================")

        # PUERTOS ABIERTOS
        open_ports = [p for p, state in r["ports"].items() if state]
        print("\nPuertos abiertos:", open_ports if open_ports else "Ninguno")

        # HTTP Banner
        if r["http"]:
            print("\n[HTTP 80]\n", r["http"])

        # HTTPS Banner
        if r["https"]:
            print("\n[HTTPS 443]\n", r["https"])

        # ============================
        # 8 - API endpoints
        # ============================
        if deep_scan:
            print("\n[8] Endpoints API comunes:\n")
            api_results = detect_api_endpoints(sub)
            for endpoint, code in api_results.items():
                if code in [200, 301, 302, 401, 403]:
                    print(f" - {endpoint} → {code}")
        else:
            print("\n[8] API endpoints: SKIPPED (FAST mode)")

        # ============================
        # 9 - Tecnologías y Seguridad
        # ============================
        if deep_scan:
            print("\n[9] Tecnologías y Seguridad:\n")

            analysis = analyze_tech_and_security(sub, use_https=True)

            techs = analysis["technologies"]
            print("Tecnologías:", ", ".join(techs) if techs else "(ninguna detectada)")

            sec = analysis["security_headers"]
            print("\nHeaders de seguridad:")
            print(f" - HSTS:      {'OK' if sec['hsts'] else 'FALTA'}")
            print(f" - CSP:       {'OK' if sec['csp'] else 'FALTA'}")
            print(f" - X-Frame:   {'OK' if sec['x_frame_options'] else 'FALTA'}")
            print(f" - X-Content: {'OK' if sec['x_content_type_options'] else 'FALTA'}")
            print(f" - Referrer:  {'OK' if sec['referrer_policy'] else 'FALTA'}")

            admin_eps = analysis["admin_endpoints"]
            if admin_eps:
                print("\nPaneles admin encontrados:")
                for ep, code in admin_eps.items():
                    print(f" - {ep} → {code}")
            else:
                print("Paneles admin no detectados.")
        else:
            print("\n[9] Tecnologías: SKIPPED (FAST mode)")

        # ============================
        # 10 - CORS
        # ============================
        if deep_scan:
            print("\n[10] CORS:\n")
            cors = analyze_cors(analysis["raw_headers"])
            print(f" - Allow-Origin:      {cors['origin']}")
            print(f" - Allow-Credentials: {cors['credentials']}")
            print(f" - Config. riesgosa:  {'SÍ' if cors['risky'] else 'no'}")
        else:
            print("\n[10] CORS: SKIPPED")

        # ============================
        # 11 - Rutas sensibles
        # ============================
        if deep_scan:
            print("\n[11] Rutas sensibles:\n")
            base_url = analysis["url"]
            sensitive = scan_sensitive_paths(base_url)
            if sensitive:
                for path, code in sensitive.items():
                    print(f" - {path} → {code}")
            else:
                print("Ninguna ruta sensible detectada.")
        else:
            print("\n[11] Sensitive Paths: SKIPPED")

        # ============================
        # 12 - JS Endpoints
        # ============================
        if deep_scan:
            print("\n[12] Endpoints en JS:\n")
            js_eps = find_js_endpoints(base_url)
            if js_eps:
                for ep in sorted(js_eps):
                    print(f" - {ep}")
            else:
                print("No se detectaron endpoints en JS.")
        else:
            print("\n[12] JS Endpoints: SKIPPED")

        # ============================
        # 13 - Certificado SSL
        # ============================
        if deep_scan:
            print("\n[13] Certificado SSL:\n")
            if 443 in open_ports:
                cert_names = get_cert_names(sub)
                if cert_names:
                    for name in sorted(cert_names):
                        print(f" - {name}")
                else:
                    print("No se pudieron obtener nombres del certificado.")
            else:
                print("Puerto 443 cerrado.")
        else:
            print("\n[13] SSL: SKIPPED")

        # ============================
        # 14 - WAF / CDN DETECTION 
        # ============================
        if deep_scan:
            print("\n[14] WAF / CDN Detection:\n")
            waf_results = detect_waf_and_cdn(
                subdomain=sub,
                ip=ip,
                headers=analysis["raw_headers"],
                body=r["http"] or r["https"] or "",
                status=200
            )
            if waf_results:
                for w in waf_results:
                    print(f" - {w}")
            else:
                print("No se detectó WAF/CDN.")
        else:
            print("\n[14] WAF/CDN: SKIPPED (FAST)")

        # ============================
        # 15 - Payload-Based WAF Detection 
        # ============================
        if deep_scan:
            print("\n[15] Payload-Based WAF Detection:\n")

            url = f"https://{sub}"
            waf_payload_result = detect_waf_for_url(url)

            print(f" - URL: {waf_payload_result['url']}")
            print(f" - WAF Detectado: {waf_payload_result['waf_detected']}")
            print(f" - Vendor: {waf_payload_result['vendor']}")
            print(f" - Motivo: {waf_payload_result['reason']}")

            print("\n   Payloads:")
            for p in waf_payload_result["payload_results"][:3]:
                if "error" in p:
                    print(f"    * {p['payload'][:25]} → error")
                else:
                    print(f"    * {p['payload'][:25]} → status {p['status_code']}, blocked={p['blocked_like']}")

        else:
            print("\n[15] Payload-Based WAF: SKIPPED (FAST)")


if __name__ == "__main__":
    main()
