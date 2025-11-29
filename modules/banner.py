import socket
import ssl

def grab_http_banner(ip, port=80):
    try:
        sock = socket.socket()
        sock.settimeout(3)
        sock.connect((ip, port))
        sock.send(b"HEAD / HTTP/1.1\r\nHost: test\r\n\r\n")
        data = sock.recv(1024).decode(errors="ignore")
        sock.close()
        return data.strip()
    except:
        return None


def grab_https_banner(ip, port=443):
    try:
        sock = socket.socket()
        sock.settimeout(3)
        wrapped = ssl.wrap_socket(sock)
        wrapped.connect((ip, port))
        wrapped.send(b"HEAD / HTTP/1.1\r\nHost: test\r\n\r\n")
        data = wrapped.recv(1024).decode(errors="ignore")
        wrapped.close()
        return data.strip()
    except:
        return None


def scan_ports(ip, ports=[21, 22, 25, 80, 443, 8080]):
    open_ports = {}

    for port in ports:
        try:
            sock = socket.socket()
            sock.settimeout(2)
            sock.connect((ip, port))
            open_ports[port] = True
            sock.close()
        except:
            open_ports[port] = False

    return open_ports


# 🔥🔥 NUEVO: BANNER GRABBING COMPLETO PARA UNA IP
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
        "https": None
    }

    ports = scan_ports(ip)
    result["ports"] = ports

    # HTTP
    if ports.get(80):
        http_banner = grab_http_banner(ip)
        if http_banner:
            result["http"] = http_banner

    # HTTPS
    if ports.get(443):
        https_banner = grab_https_banner(ip)
        if https_banner:
            result["https"] = https_banner

    return result
