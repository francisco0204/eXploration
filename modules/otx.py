import requests

def get_subdomains_from_otx(domain: str) -> set:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    subdomains = set()

    try:
        response = requests.get(url, timeout=15)
        data = response.json()

        for entry in data.get("passive_dns", []):
            sub = entry.get("hostname", "").lower()
            if sub.endswith(domain):
                subdomains.add(sub)

    except Exception as e:
        print(f"[WARN] OTX error: {e}")

    return subdomains
