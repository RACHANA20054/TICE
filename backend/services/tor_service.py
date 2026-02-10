import requests

TOR_EXIT_LIST_URL = "https://check.torproject.org/exit-addresses"

def check_tor_exit(ip: str):
    try:
        response = requests.get(TOR_EXIT_LIST_URL, timeout=10)
        if response.status_code != 200:
            return {"is_tor": False}

        for line in response.text.splitlines():
            if line.startswith("ExitAddress"):
                tor_ip = line.split()[1]
                if tor_ip == ip:
                    return {"is_tor": True}

        return {"is_tor": False}

    except Exception:
        return {"is_tor": False}
