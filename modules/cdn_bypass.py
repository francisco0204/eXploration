import socket
import dns.resolver
import requests

CLOUDFLARE_IP_RANGES = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]

def ip_in_cf_range(ip):
    from ipaddress import ip_address, ip_network
    try:
        ip_obj = ip_address(ip)
        for net in CLOUDFLARE_IP_RANGES:
            if ip_obj in ip_network(net):
                return True
    except:
        pass
    return False


GLOBAL_DNS = [
    "1.1.1.1",        # Cloudflare
    "8.8.8.8",        # Google
    "9.9.9.9",        # Quad9
    "114.114.114.114",# China
    "208.67.222.222", # OpenDNS
]


def resolve_global(domain):
    """Prueba resolver con DNS globales por si algún nodo filtra la IP real."""
    leaked_ips = []

    for dns_server in GLOBAL_DNS:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        try:
            answers = resolver.resolve(domain, "A", lifetime=3)
            for r in answers:
                leaked_ips.append(str(r))
        except:
            pass

    return list(set(leaked_ips))


def direct_connect_test(ip, hostname):
    """Intenta conectar con la IP pasada por parámetro saltando Cloudflare."""
    try:
        url = f"http://{ip}"
        headers = {"Host": hostname}

        resp = requests.get(url, headers=headers, timeout=5)

        return {
            "ip": ip,
            "status": resp.status_code,
            "server": resp.headers.get("server"),
            "length": len(resp.text),
            "body_sample": resp.text[:200].lower(),
        }
    except:
        return None


def detect_real_ip(domain, known_ip):
    """
    Intenta detectar si la IP real está expuesta saltando Cloudflare.
    """

    result = {
        "behind_cloudflare": ip_in_cf_range(known_ip),
        "origin_leaked_global_dns": [],
        "direct_connect_matches": [],
        "origin_found": False
    }

    
    dns_ips = resolve_global(domain)
    result["origin_leaked_global_dns"] = dns_ips

    
    for ip in dns_ips:
        if not ip_in_cf_range(ip):
            result["origin_found"] = True
            return result

    
    for ip in dns_ips:
        test = direct_connect_test(ip, domain)
        if test is None:
            continue

        
        if "cloudflare" not in (test["server"] or "").lower():
            result["origin_found"] = True
            result["direct_connect_matches"].append(ip)
            break

    return result
