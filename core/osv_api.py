import requests

OSV_API_URL = "https://api.osv.dev/v1/query"

def determine_ecosystem(tech_name):
    """Maps fingerprints to their standard software database ecosystem."""
    name = tech_name.lower()
    if "laravel" in name or "php" in name:
        return "Packagist"
    if "django" in name or "python" in name or "flask" in name:
        return "PyPI"
    return "PyPI"

def look_up_remediation(tech_name, version):
    """
    Queries the CVE database and extracts strict remediation rules:
    Updates to target versions or alternative architectural recommendations.
    """
    ecosystem = determine_ecosystem(tech_name)
    payload = {
        "version": version,
        "package": {"name": tech_name, "ecosystem": ecosystem}
    }

    remediations = []
    try:
        response = requests.post(OSV_API_URL, json=payload, timeout=10)
        if response.status_code == 200:
            vulns = response.json().get("vulns", [])
            for v in vulns:
                cve_id = ", ".join(v.get("aliases", ["No CVE ID"]))
                summary = v.get("summary", "No public summary provided.")

                # Extract the official fixed/patched version string safely
                fixed_version = "No official patch version specified."
                for affected in v.get("affected", []):
                    for ranges in affected.get("ranges", []):
                        for event in ranges.get("events", []):
                            if "fixed" in event:
                                fixed_version = f"Upgrade to version {event['fixed']} or higher immediately."
                                break

                remediations.append({
                    "id": v["id"],
                    "cve": cve_id,
                    "summary": summary,
                    "fix": fixed_version
                })
    except requests.RequestException:
        pass

    return remediations
