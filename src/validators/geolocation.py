import ipaddress
import requests

_IPAPI_FIELDS = (
    "status,message,country,countryCode,regionName,city,"
    "zip,lat,lon,timezone,isp,org,as,proxy,hosting,query"
)
IPAPI_ENDPOINT = "http://ip-api.com/json/{ip}?fields=" + _IPAPI_FIELDS

# Riutilizziamo la sessione passata o ne creiamo una interna
_session = requests.Session()
_session.headers.update({"User-Agent": "FishStop/1.0", "Accept": "application/json"})

def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False  # Stringa non valida, verrà intercettata dall'API o dal blocco try

def geolocate_ip(ip: str) -> dict:
    base = {
        "ip": ip, "country": "", "country_code": "", "region": "",
        "city": "", "zip": "", "lat": None, "lon": None,
        "timezone": "", "isp": "", "org": "", "asn": "",
        "is_proxy": False, "is_hosting": False,
    }

    if not ip:
        return {**base, "status": "skipped", "message": "Nessun IP fornito"}

    if _is_private(ip):
        return {**base, "status": "skipped",
                "message": f"`{ip}` è un indirizzo privato/riservato — nessuna geo disponibile"}

    url = IPAPI_ENDPOINT.format(ip=ip)
    try:
        # requests gestisce internamente pooling e timeout in modo efficiente
        resp = _session.get(url, timeout=5)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.RequestException as exc:
        return {**base, "status": "error", "message": f"Errore ip-api.com: {exc}"}

    if data.get("status") != "success":
        return {**base, "status": "skipped",
                "message": f"ip-api.com: {data.get('message', 'risposta non valida')} per `{ip}`"}

    return {
        "status":       "ok",
        "ip":           data.get("query", ip),
        "country":      data.get("country", ""),
        "country_code": data.get("countryCode", ""),
        "region":       data.get("regionName", ""),
        "city":         data.get("city", ""),
        "zip":          data.get("zip", ""),
        "lat":          data.get("lat"),
        "lon":          data.get("lon"),
        "timezone":     data.get("timezone", ""),
        "isp":          data.get("isp", ""),
        "org":          data.get("org", ""),
        "asn":          data.get("as", ""),
        "is_proxy":     bool(data.get("proxy")),
        "is_hosting":   bool(data.get("hosting")),
        "message":      (
            f"{data.get('city','')}, {data.get('regionName','')}, "
            f"{data.get('country','')} ({data.get('countryCode','')})"
            + (" — ⚠️ Proxy/VPN rilevato" if data.get("proxy") else "")
            + (" — ☁️ Datacenter/Hosting" if data.get("hosting") else "")
        ),
    }