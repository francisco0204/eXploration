import requests
import urllib3
import concurrent.futures

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


COMMON_API_ENDPOINTS = [
    "/api",
    "/api/",
    "/api/v1",
    "/api/v1/",
    "/api/v2",
    "/api/v2/",
    "/v1",
    "/v1/",
    "/v2",
    "/v2/",
    "/graphql",
    "/graphiql",
    "/swagger",
    "/swagger.json",
    "/swagger.yaml",
    "/openapi",
    "/openapi.json",
    "/openapi.yaml",
    "/docs",
    "/documentation",
    "/rest",
    "/rest/",
    "/api-docs",
    "/redoc",
    "/health",
    "/status",
]


def _check_endpoint(args):
    base_url, endpoint, timeout = args
    url = base_url + endpoint
    try:
        r = requests.get(url, timeout=timeout, verify=False)
        if r.status_code in [200, 301, 302, 401, 403]:
            return endpoint, r.status_code
    except Exception:
        pass
    return endpoint, None


def detect_api_endpoints(subdomain: str, https: bool = True, timeout: int = 3, max_workers: int = 10) -> dict:
    """
    Prueba endpoints comunes de API EN PARALELO.
    Devuelve endpoint -> status_code, solo para los que respondieron
    con un código relevante (antes devolvía TODOS, incluidos los None;
    ahora queda más liviano y consistente con el resto de los módulos).
    """
    protocol = "https" if https else "http"
    base_url = f"{protocol}://{subdomain}"

    results = {}
    tasks = [(base_url, endpoint, timeout) for endpoint in COMMON_API_ENDPOINTS]

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for endpoint, code in executor.map(_check_endpoint, tasks):
            if code is not None:
                results[endpoint] = code

    return results