import json
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
import requests

ABUSEIPDB_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"

# Creiamo una sessione globale per riutilizzare le connessioni TCP/TLS (Keep-Alive)
# Questo da solo riduce drasticamente i tempi di latenza HTTP
_session = requests.Session()
_session.headers.update({"Accept": "application/json"})


def _abuseipdb_call(api_key: str, ip: str) -> dict:
    """Chiamata ottimizzata all'API AbuseIPDB v2 usando requests.Session."""
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    headers = {"Key": api_key}

    # Ridotto il timeout a 4 secondi per evitare blocchi infiniti
    response = _session.get(
        ABUSEIPDB_ENDPOINT, params=params, headers=headers, timeout=4
    )

    # Lancia una HTTPError se il codice non è 2xx
    response.raise_for_status()

    return response.json().get("data", {})


def _format_abuseipdb(data: dict, lookup_key: str) -> dict:
    """Normalizza il dict 'data' di AbuseIPDB in un risultato uniforme."""
    score = int(data.get("abuseConfidenceScore") or 0)
    ip = data.get("ipAddress", lookup_key)
    return {
        "status": "ok",
        "ip": ip,
        "abuseConfidenceScore": score,
        "totalReports": int(data.get("totalReports") or 0),
        "numDistinctUsers": int(data.get("numDistinctUsers") or 0),
        "countryCode": data.get("countryCode") or "",
        "isp": data.get("isp") or "",
        "domain": data.get("domain") or "",
        "isWhitelisted": bool(data.get("isWhitelisted")),
        "usageType": data.get("usageType") or "",
        "lastReportedAt": data.get("lastReportedAt"),
        "url": f"https://www.abuseipdb.com/check/{ip}",
        "message": (
            f"Score: {score}/100 — {int(data.get('totalReports') or 0)} segnalazioni "
            f"da {int(data.get('numDistinctUsers') or 0)} utenti distinti"
        ),
    }


def check_ip_reputation(api_key: str, ip: str) -> dict:
    """Interroga AbuseIPDB v2 per la reputazione di un indirizzo IP."""
    base = {
        "ip": ip,
        "abuseConfidenceScore": 0,
        "totalReports": 0,
        "numDistinctUsers": 0,
        "countryCode": "",
        "isp": "",
        "domain": "",
        "isWhitelisted": False,
        "usageType": "",
        "lastReportedAt": None,
        "url": f"https://www.abuseipdb.com/check/{ip}",
    }
    if not ip:
        return {**base, "status": "skipped", "message": "Nessun IP fornito"}
    if not api_key:
        return {
            **base,
            "status": "skipped",
            "message": "API key AbuseIPDB non configurata — lookup saltato",
        }
    try:
        data = _abuseipdb_call(api_key, ip)
        return _format_abuseipdb(data, ip)
    except requests.exceptions.HTTPError as exc:
        return {
            **base,
            "status": "error",
            "message": f"AbuseIPDB HTTP {exc.response.status_code}: {exc.response.reason}",
        }
    except Exception as exc:
        return {
            **base,
            "status": "error",
            "message": f"Errore AbuseIPDB: {exc}",
        }


def check_domain_reputation(
    api_key: str, resolver: dns.resolver.Resolver, domain: str
) -> dict:
    """Controlla la reputazione di un dominio risolvendo prima il dominio in IP."""
    base = {
        "domain_queried": domain,
        "resolved_ip": "",
        "lookup_method": "error",
        "ip": "",
        "abuseConfidenceScore": 0,
        "totalReports": 0,
        "numDistinctUsers": 0,
        "countryCode": "",
        "isp": "",
        "domain": "",
        "isWhitelisted": False,
        "usageType": "",
        "lastReportedAt": None,
        "url": f"https://www.abuseipdb.com/check/{domain}",
        "message": "",
    }

    if not domain:
        return {
            **base,
            "status": "skipped",
            "lookup_method": "skipped",
            "message": "Nessun dominio fornito",
        }
    if not api_key:
        return {
            **base,
            "status": "skipped",
            "lookup_method": "skipped",
            "message": "API key AbuseIPDB non configurata — lookup saltato",
        }

    # Risoluzione DNS
    resolved_ip = ""
    try:
        answers = resolver.resolve(domain, "A")
        resolved_ip = str(answers[0])
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {
            **base,
            "status": "skipped",
            "lookup_method": "skipped",
            "message": f"Il dominio `{domain}` non esiste o non ha record A",
        }
    except dns.resolver.NoNameservers:
        return {
            **base,
            "status": "skipped",
            "lookup_method": "skipped",
            "message": f"Nessun nameserver raggiungibile per `{domain}`",
        }
    except dns.exception.Timeout:
        return {
            **base,
            "status": "skipped",
            "lookup_method": "skipped",
            "message": f"Timeout nella risoluzione DNS di `{domain}`",
        }
    except Exception as exc:
        return {
            **base,
            "status": "error",
            "lookup_method": "error",
            "message": f"Errore DNS per `{domain}`: {exc}",
        }

    # Lookup AbuseIPDB sull'IP risolto
    try:
        data = _abuseipdb_call(api_key, resolved_ip)
        result = _format_abuseipdb(data, resolved_ip)
        result["domain_queried"] = domain
        result["resolved_ip"] = resolved_ip
        result["lookup_method"] = "dns-resolved"
        return result
    except requests.exceptions.HTTPError as exc:
        return {
            **base,
            "status": "error",
            "lookup_method": "dns-resolved",
            "resolved_ip": resolved_ip,
            "message": f"AbuseIPDB HTTP {exc.response.status_code} per IP {resolved_ip}",
        }
    except Exception as exc:
        return {
            **base,
            "status": "error",
            "lookup_method": "dns-resolved",
            "resolved_ip": resolved_ip,
            "message": f"Errore AbuseIPDB per IP {resolved_ip}: {exc}",
        }


# =====================================================================
# ESEMPIO DI UTILIZZO MASSIVO IN PARALLELO (MULTITHREADING)
# =====================================================================
if __name__ == "__main__":
    import time

    # Configura qui i tuoi dati
    MY_API_KEY = "IL_TUO_TOKEN_ABUSEIPDB"

    # Lista di test (anche con duplicati per testare le performance)
    lista_ip = ["8.8.8.8", "1.1.1.1", "142.250.184.238", "9.9.9.9"] * 5

    # 1. Configurazione ottimale del Resolver DNS (bassi timeout)
    dns_resolver = dns.resolver.Resolver()
    dns_resolver.timeout = 1.0  # Singolo tentativo
    dns_resolver.lifetime = 2.0  # Tempo massimo totale per dominio

    print(f"Avvio controllo di {len(lista_ip)} IP in parallelo...")
    start_time = time.time()

    risultati = []

    # 2. Utilizzo del ThreadPoolExecutor per parallelizzare l'I/O bound
    # max_workers=20 significa che eseguiamo fino a 20 chiamate HTTP simultanee
    with ThreadPoolExecutor(max_workers=20) as executor:
        # Lanciamo tutti i task in background
        futures = [
            executor.submit(check_ip_reputation, MY_API_KEY, ip)
            for ip in lista_ip
        ]

        # Raccogliamo i risultati man mano che terminano
        for future in futures:
            try:
                res = future.result()
                risultati.append(res)
            except Exception as e:
                print(f"Errore imprevisto nel thread: {e}")

    end_time = time.time()

    # Mostriamo un estratto dei risultati
    for r in risultati[:3]:
        print(f"-> IP: {r['ip']} | Score: {r['abuseConfidenceScore']} | Status: {r['status']}")

    print(f"\nCompletato! Processati {len(risultati)} IP in {end_time - start_time:.2f} secondi.")