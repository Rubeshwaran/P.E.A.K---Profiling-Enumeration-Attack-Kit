import requests
from bs4 import BeautifulSoup
import logging
import urllib3

# Suppress SSL warnings for active probing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

class PeakProfiler:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PEAK-Scanner/2.0 (Active)'
        }
        # Active paths to probe
        self.interesting_paths = [
            '/.git/HEAD', '/.env', '/.DS_Store', '/config.php.bak', 
            '/wp-login.php', '/robots.txt', '/sitemap.xml', '/actuator/health'
        ]

    def analyze_url(self, url):
        if not url.startswith('http'):
            url = 'http://' + url
        
        # Strip trailing slash for probing
        base_url = url.rstrip('/')
        
        findings = {
            "tech_stack": set(),
            "exposed_paths": [],
            "security_headers_missing": []
        }
        
        try:
            print(f"DEBUG: Active Profiling {url}...")
            
            # 1. Main Page Analysis
            response = requests.get(url, headers=self.headers, timeout=5, verify=False)
            
            # Headers Analysis
            h = response.headers
            if 'Server' in h: findings['tech_stack'].add(f"Server: {h['Server']}")
            if 'X-Powered-By' in h: findings['tech_stack'].add(f"Tech: {h['X-Powered-By']}")
            
            # Missing Security Headers Check
            sec_headers = ['X-Frame-Options', 'Content-Security-Policy', 'Strict-Transport-Security']
            for sh in sec_headers:
                if sh not in h:
                    findings['security_headers_missing'].append(sh)

            # HTML Analysis
            soup = BeautifulSoup(response.text, 'html.parser')
            meta_gen = soup.find('meta', attrs={'name': 'generator'})
            if meta_gen: findings['tech_stack'].add(f"Generator: {meta_gen.get('content')}")

            # Fingerprinting (Simple signatures)
            text = response.text.lower()
            if 'wp-content' in text: findings['tech_stack'].add("CMS: WordPress")
            if 'shopify' in text: findings['tech_stack'].add("Platform: Shopify")
            if 'react' in text: findings['tech_stack'].add("Frontend: React")
            if 'django' in text or 'csrftoken' in response.cookies.get_dict(): findings['tech_stack'].add("Framework: Django")
            
            # 2. ACTIVE RECON (Probing Paths)
            for path in self.interesting_paths:
                probe_url = base_url + path
                try:
                    probe = requests.head(probe_url, headers=self.headers, timeout=2, verify=False)
                    # If we get a 200 OK on a sensitive file, it's a FINDING
                    if probe.status_code == 200:
                        findings['exposed_paths'].append(path)
                        if '.git' in path: findings['tech_stack'].add("Vulnerability: Exposed Git Repo")
                        if '.env' in path: findings['tech_stack'].add("Vulnerability: Exposed Env File")
                        if 'wp-login' in path: findings['tech_stack'].add("Panel: WordPress Admin")
                except:
                    pass

        except Exception as e:
            logger.error(f"Profiling error: {e}")
            return {"status": "error", "message": str(e)}

        return {
            "status": "success",
            "url": url,
            "tech_stack": list(findings['tech_stack']),
            "exposed_paths": findings['exposed_paths'],
            "missing_headers": findings['security_headers_missing']
        }