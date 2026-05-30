import requests
import urllib.parse

def gather_subdomains_passively(domain):
    """Queries public CT visibility logs to map asset scopes with 0 server stress."""
    url = f"https://crt.sh/?q={urllib.parse.quote('%.' + domain)}&output=json"
    subdomains = set()
    try:
        res = requests.get(url, timeout=20)
        if res.status_code == 200:
            for cert in res.json():
                for name in cert.get("name_value", "").split("\n"):
                    name = name.strip().lower()
                    if name and "*" not in name and name.endswith(domain):
                        subdomains.add(name)
    except Exception:
        pass
    return sorted(list(subdomains))

def check_robots_metadata(url):
    """Inspects configuration pathways exposed in robots.txt metadata."""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    target = urllib.parse.urljoin(url, "/robots.txt")
    paths = []
    try:
        res = requests.get(target, timeout=10)
        if res.status_code == 200:
            for line in res.text.splitlines():
                if line.strip().lower().startswith(("disallow:", "allow:")):
                    parts = line.split(":", 1)
                    if len(parts) > 1 and parts[1].strip() != "/":
                        paths.append(parts[1].strip())
    except Exception:
        pass
    return sorted(list(set(paths)))
