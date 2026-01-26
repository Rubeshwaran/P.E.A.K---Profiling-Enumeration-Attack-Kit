import requests
import logging
import urllib3

# Disable SSL warnings for cleaner logs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def analyze_tech_stack(target_url):
    """
    Analyzes the target URL for headers, tech stack, and exposed paths.
    Returns a dictionary compatible with the Auto-Pilot module.
    """
    logger.info(f"Profiling target: {target_url}")
    
    results = {
        "target": target_url,
        "tech_stack": [],
        "exposed_paths": [],
        "headers": {}
    }

    try:
        # 1. Basic Request to get Headers
        try:
            # timeout=10 to prevent hanging, verify=False to ignore SSL errors on targets
            response = requests.get(target_url, timeout=10, verify=False)
            results["headers"] = dict(response.headers)
        except requests.exceptions.RequestException as e:
            logger.error(f"Connection failed: {e}")
            return results

        # 2. Analyze Headers for Tech Info
        server = response.headers.get("Server")
        x_powered_by = response.headers.get("X-Powered-By")
        
        if server:
            results["tech_stack"].append(f"Server: {server}")
        if x_powered_by:
            results["tech_stack"].append(f"PoweredBy: {x_powered_by}")
            
        # 3. Analyze Body HTML for signatures (Simple Fingerprinting)
        text = response.text.lower()
        
        # CMS Detection
        if "wp-content" in text:
            results["tech_stack"].append("CMS: WordPress")
        elif "drupal" in text:
            results["tech_stack"].append("CMS: Drupal")
        elif "joomla" in text:
            results["tech_stack"].append("CMS: Joomla")
            
        # Framework/Library Detection
        if "laravel" in text:
            results["tech_stack"].append("Framework: Laravel")
        if "django" in text:
            results["tech_stack"].append("Framework: Django")
        if "react" in text or "react-dom" in text:
            results["tech_stack"].append("Frontend: React")
        if "vue.js" in text:
            results["tech_stack"].append("Frontend: Vue.js")
        if "bootstrap" in text:
            results["tech_stack"].append("UI: Bootstrap")

        # 4. Check Exposed Paths (Mini-Probe)
        # Checks for common sensitive files quickly
        common_paths = ["/.git", "/.env", "/robots.txt", "/sitemap.xml", "/admin", "/config.php"]
        
        for path in common_paths:
            probe_url = target_url.rstrip("/") + path
            try:
                res = requests.head(probe_url, timeout=3, verify=False)
                # If we get a 200 OK or 403 Forbidden, it exists
                if res.status_code in [200, 403]:
                    results["exposed_paths"].append(f"{path} ({res.status_code})")
            except:
                pass

        logger.info(f"Profiling complete. Found {len(results['tech_stack'])} technologies.")
        return results

    except Exception as e:
        logger.error(f"Profiler Error: {e}")
        return results