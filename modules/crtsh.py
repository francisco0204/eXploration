import requests
import time

def get_subdomains_from_crtsh(domain: str, retries: int = 3) -> set:
    url = f"https://crt.sh/?q={domain}&output=json"
    subdomains = set()

    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=20) 
            response.raise_for_status()
            data = response.json()

            for entry in data:
                name_value = entry.get("name_value", "")
                for sub in name_value.split("\n"):
                    sub = sub.strip().lower()

                    if "*" in sub:
                        sub = sub.replace("*.", "")

                    if sub.endswith(domain):
                        subdomains.add(sub)

            return subdomains  

        except Exception as e:
            print(f"[WARN] crt.sh intento {attempt+1}/{retries} falló: {e}")
            time.sleep(2)  

    print("[ERROR] crt.sh no respondió luego de varios intentos.")
    return subdomains
