import requests
from bs4 import BeautifulSoup
import urllib.parse

def audit_web_surfaces(url_list):
    """
    Loops through all verified responsive SecList paths and deeply parses 
    internal form layouts for configuration oversights.
    """
    audit_data = {
        "login_forms_found": [],
        "upload_forms_found": [],
        "missing_security_headers": []
    }
    
    headers_checked = False

    # Process every working endpoint located by the SecList pass
    for url in url_list:
        try:
            print(f" \033[94m├── [PARSE ENGINE] Scraping target path: {url}\033[0m")
            response = requests.get(url, timeout=5, headers={"User-Agent": "KASCVE-Defensive-Auditor"})
            
            # Check headers once on the main response landing zone
            if not headers_checked:
                for header in ["Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"]:
                    if header not in response.headers:
                        audit_data["missing_security_headers"].append(header)
                headers_checked = True
                    
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")
            
            if forms:
                print(f" \033[92m│    └── Located {len(forms)} HTML form arrays on path. Verifying entry fields...\033[0m")

            for index, form in enumerate(forms, 1):
                form_action = form.get("action", "")
                form_method = form.get("method", "get").lower()
                absolute_action = urllib.parse.urljoin(url, form_action)
                
                inputs = form.find_all("input")
                password_inputs = form.find_all("input", attrs={"type": "password"})
                file_inputs = form.find_all("input", attrs={"type": "file"})
                
                form_profile = {
                    "id": form.get("id", f"Form #{index}"),
                    "action_url": absolute_action,
                    "method": form_method,
                    "has_csrf": False,
                    "missing_accept": False
                }

                # Scan fields for cryptographic tokens
                csrf_keywords = ["_token", "csrf", "xsrf"]
                for inp in inputs:
                    name_attr = str(inp.get("name", "")).lower()
                    id_attr = str(inp.get("id", "")).lower()
                    if any(kw in name_attr or kw in id_attr for kw in csrf_keywords):
                        form_profile["has_csrf"] = True
                        break

                has_auth_hints = any(k in absolute_action.lower() for k in ["login", "auth", "signup", "register"])
                if password_inputs or has_auth_hints:
                    form_profile["field_name"] = password_inputs[0].get("name", "unnamed_password") if password_inputs else "auth_submit"
                    audit_data["login_forms_found"].append(form_profile)

                if file_inputs:
                    if not any(inp.get("accept") for inp in file_inputs):
                        form_profile["missing_accept"] = True
                    audit_data["upload_forms_found"].append(form_profile)
                   
        except requests.RequestException:
            continue
            
    return audit_data
