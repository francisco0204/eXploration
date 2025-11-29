import requests

def get_subdomains_from_threatminer(domain: str) -> set:
    url = f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5"
    subdomains = set()

    try:
        response = requests.get(url, timeout=15)
        data = response.json()

        results = data.get("results", [])

        for sub in results:
            sub = sub.lower().strip()
            if sub.endswith(domain):
                subdomains.add(sub)

    except Exception as e:
        print(f"[WARN] ThreatMiner error: {e}")

    return subdomains
