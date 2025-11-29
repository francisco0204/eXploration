import requests
import requests
import urllib3

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
    "/status"
]

def detect_api_endpoints(subdomain: str, https=True):
    results = {}
    
    protocol = "https" if https else "http"
    base_url = f"{protocol}://{subdomain}"

    for endpoint in COMMON_API_ENDPOINTS:
        url = base_url + endpoint
        try:
            r = requests.get(url, timeout=4, verify=False)
            results[endpoint] = r.status_code
        except:
            results[endpoint] = None  # No respuesta / error

    return results
