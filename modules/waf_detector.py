import requests
import urllib3
import ipaddress

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# RANGOS DE IP de CDNs/WAFs 
CLOUDFLARE_RANGES = [
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
]

def ip_in_ranges(ip, ranges):
    """Check if an IP belongs to known ranges."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in ipaddress.ip_network(r) for r in ranges)
    except:
        return False


def detect_waf_and_cdn(subdomain: str, ip: str, headers: dict, body: str, status: int):
    detections = []

    server = headers.get("Server", "").lower()
    cookies = "; ".join(headers.get("Set-Cookie", "").lower().split())
    body_low = (body or "").lower()

    # CLOUDLARE (CDN + WAF)
    if "cloudflare" in server or "__cfduid" in cookies or "cf-ray" in headers:
        detections.append("Cloudflare (CDN + WAF activo)")
    if ip_in_ranges(ip, CLOUDFLARE_RANGES):
        detections.append("Cloudflare (por rango IP)")

    # AWS CLOUDFRONT
    if "cloudfront" in server or "x-amz-cf-id" in headers:
        detections.append("AWS CloudFront (CDN)")

    # AKAMAI
    if "akamai" in server or "akamai" in cookies or "akamai" in body_low:
        detections.append("Akamai (CDN/WAF)")

    if "akamai-ghost" in server:
        detections.append("Akamai Ghost (CDN)")

    # FASTLY
    if "fastly" in server or "fastly" in body_low or "x-served-by" in headers and "fastly" in headers["x-served-by"].lower():
        detections.append("Fastly (CDN)")

    # IMPERVA / INCAPSULA
    if "incapsula" in server or "visid_incap" in cookies or "incap_ses" in cookies:
        detections.append("Imperva Incapsula (WAF)")

    # SUCURI
    if "sucuri" in server or "x-sucuri-id" in headers:
        detections.append("Sucuri WAF")

    # F5 BIG-IP
    if "bigip" in cookies or "bigip" in server:
        detections.append("F5 BIG-IP (WAF/LB)")

    # REBLAZE
    if "rbzid" in cookies or "rbz" in body_low:
        detections.append("Reblaze (WAF)")

    # STACKPATH
    if "__sp__" in cookies:
        detections.append("StackPath CDN")

    # ARBOR
    if "arbor" in body_low:
        detections.append("Arbor (DDoS protection)")

    # DETECCIÓN POR CÓDIGOS ESPECIALES
    if status in [406, 501] and "cloudflare" in server:
        detections.append("Cloudflare WAF (detección por comportamiento)")

    # DETECCIÓN POR MENSAJES TÍPICOS
    if "access denied" in body_low and "cloudfront" in server:
        detections.append("AWS Shield / CloudFront WAF")

    return detections
