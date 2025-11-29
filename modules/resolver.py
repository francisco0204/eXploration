import socket
from concurrent.futures import ThreadPoolExecutor

def resolve_single(subdomain):
    try:
        ip = socket.gethostbyname(subdomain)
        return {"subdomain": subdomain, "ip": ip}
    except:
        return None


def resolve_subdomains(subdomain_list: set) -> list:
    results = []

    with ThreadPoolExecutor(max_workers=50) as executor:
        for result in executor.map(resolve_single, subdomain_list):
            if result:
                results.append(result)

    return results
