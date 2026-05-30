import requests

def discover_seclist_paths(base_url, depth_choice):
    """
    Automated target discovery routing engine using dynamic SecLists tiers.
    Flags exposed files and directory structures left behind by developers.
    """
    if not base_url.startswith("http://") and not base_url.startswith("https://"):
        base_url = "https://" + base_url

    # Map depth configurations to raw SecLists vectors on GitHub
    wordlists = {
        "1": ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt", 150),
        "2": ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt", 4500),
        "3": ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt", 25000)
    }

    selected_list, limit = wordlists.get(depth_choice, wordlists["1"])
    discovered_urls = [base_url]
    
    print(f" \033[94m├── [SECLISTS] Streaming remote directory definitions from target repository...\033[0m")
    
    try:
        res = requests.get(selected_list, timeout=7)
        if res.status_code == 200:
            all_paths = [line.strip() for line in res.text.splitlines() if line.strip() and not line.startswith("#")]
            target_paths = all_paths[:limit]
            print(f" \033[94m├── [FUZZENG] Fuzzing engine active. Scanning {len(target_paths)} system path structures...\033[0m")
        else:
            raise requests.RequestException
    except requests.RequestException:
        print(f" \033[93m├── [WARN] Connection problem fetching list. Using high-priority fallback vectors...\033[0m")
        target_paths = [
            "login", "admin", "test", "dev", "backup", "backup.zip", ".git/HEAD", 
            "config.php", "wp-config.php", "api", "dashboard", "upload", ".env"
        ]

    # Explicit sensitive targets to evaluate disclosure thresholds
    for path in target_paths:
        full_target = f"{base_url.rstrip('/')}/{path}"
        try:
            response = requests.head(full_target, timeout=2, allow_redirects=False)
            
            # Treat 200 (Exposed) or 301/302 (Hidden Portals) as responsive nodes
            if response.status_code in [200, 301, 302]:
                print(f" \033[92m│    └── [FOUND DIRECTION] Surface identified: {full_target} (Status: {response.status_code})\033[0m")
                discovered_urls.append(full_target)
        except requests.RequestException:
            continue

    return list(set(discovered_urls))
