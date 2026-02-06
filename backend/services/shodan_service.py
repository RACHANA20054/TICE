import os
import shodan

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

def check_ip_shodan(ip: str):
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        host = api.host(ip)

        return {
            "source": "Shodan",
            "organization": host.get("org"),
            "country": host.get("country_name"),
            "open_ports": host.get("ports"),
            "vulns": list(host.get("vulns", []))
        }

    except shodan.APIError as e:
        return {
            "source": "Shodan",
            "error": str(e)
        }
