import requests

def get_subdomains_from_bufferover(domain: str) -> set:
    url = f"https://dns.bufferover.run/dns?q=.{domain}"
    subdomains = set()

    try:
        response = requests.get(url, timeout=15)
        data = response.json()

        results = data.get("FDNS_A", []) + data.get("RDNS", [])

        for item in results:
            # formato: "1.2.3.4,sub.domain.com"
            parts = item.split(",")
            if len(parts) == 2:
                sub = parts[1].strip().lower()
                if sub.endswith(domain):
                    subdomains.add(sub)

    except Exception as e:
        print(f"[WARN] BufferOver error: {e}")

    return subdomains
