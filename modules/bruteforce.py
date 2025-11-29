import socket

def bruteforce_subdomains(domain: str, wordlist_path: str) -> set:
    """
    Genera subdominios usando una wordlist y verifica cuáles existen.
    Retorna un set con los subdominios válidos (resuelven DNS).
    """
    valid_subdomains = set()

    try:
        with open(wordlist_path, "r", encoding="utf-8") as f:
            words = f.read().splitlines()

        for word in words:
            subdomain = f"{word}.{domain}"

            try:
                # Si resuelve DNS → existe
                socket.gethostbyname(subdomain)
                valid_subdomains.add(subdomain)
            except socket.gaierror:
                pass  # No existe, seguimos

    except Exception as e:
        print(f"[ERROR] Bruteforce error: {e}")

    return valid_subdomains
