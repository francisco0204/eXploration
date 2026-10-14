import socket
from concurrent.futures import ThreadPoolExecutor


def _check_word(args):
    word, domain = args
    subdomain = f"{word}.{domain}"
    try:
        socket.gethostbyname(subdomain)
        return subdomain
    except Exception:
        return None


def bruteforce_subdomains(domain: str, wordlist_path: str, max_workers: int = 30) -> set:
    """
    Genera subdominios usando una wordlist y verifica EN PARALELO cuáles
    existen. Retorna un set con los subdominios válidos (resuelven DNS).
    """
    valid_subdomains = set()

    try:
        with open(wordlist_path, "r", encoding="utf-8") as f:
            words = [w.strip() for w in f.read().splitlines() if w.strip()]
    except Exception as e:
        print(f"[ERROR] Bruteforce error: {e}")
        return valid_subdomains

    tasks = [(word, domain) for word in words]

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for result in executor.map(_check_word, tasks):
            if result:
                valid_subdomains.add(result)

    return valid_subdomains