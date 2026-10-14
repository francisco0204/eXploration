import socket
import ssl
import concurrent.futures

COMMON_PORTS = [21, 22, 25, 80, 443, 8080]


def grab_http_banner(ip, port=80, timeout=3):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.send(b"HEAD / HTTP/1.1\r\nHost: test\r\n\r\n")
            data = sock.recv(1024).decode(errors="ignore")
        return data.strip()
    except Exception:
        return None


def grab_https_banner(ip, port=443, timeout=3):
    try:
        # ssl.wrap_socket() fue eliminado en Python 3.12+, por eso esto
        # nunca devolvía nada antes: tiraba AttributeError y caía al except.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as wrapped:
                wrapped.send(b"HEAD / HTTP/1.1\r\nHost: test\r\n\r\n")
                data = wrapped.recv(1024).decode(errors="ignore")
        return data.strip()
    except Exception:
        return None


def _check_port(args):
    ip, port, timeout = args
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return port, True
    except Exception:
        return port, False


def scan_ports(ip, ports=None, timeout=2, max_workers=6):
    """Escanea los puertos EN PARALELO en vez de uno por uno."""
    if ports is None:
        ports = COMMON_PORTS

    open_ports = {}
    tasks = [(ip, port, timeout) for port in ports]

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for port, is_open in executor.map(_check_port, tasks):
            open_ports[port] = is_open

    return open_ports


# BANNER GRABBING COMPLETO PARA UNA IP
def process_ip(target):
    """
    Recibe {"subdomain": "...", "ip": "..."} y devuelve
    un diccionario con puertos + banners encontrados.
    """
    sub = target["subdomain"]
    ip = target["ip"]

    result = {
        "subdomain": sub,
        "ip": ip,
        "ports": {},
        "http": None,
        "https": None,
    }

    ports = scan_ports(ip)
    result["ports"] = ports

    # HTTP y HTTPS banner EN PARALELO (antes era uno después del otro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        http_future = executor.submit(grab_http_banner, ip) if ports.get(80) else None
        https_future = executor.submit(grab_https_banner, ip) if ports.get(443) else None

        if http_future:
            banner = http_future.result()
            if banner:
                result["http"] = banner

        if https_future:
            banner = https_future.result()
            if banner:
                result["https"] = banner

    return result