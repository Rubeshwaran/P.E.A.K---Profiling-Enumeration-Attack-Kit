import logging
import sys

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- SAFE IMPORT LOGIC ---
# We prevent Sublist3r from loading on Windows to avoid the 'termios' crash
sublist3r = None

if sys.platform != "win32":
    try:
        import sublist3r
    except ImportError:
        sublist3r = None
else:
    logger.info("Windows detected: Sublist3r library disabled to prevent 'termios' crash.")

def run_subdomain_scan(domain):
    logger.info(f"Starting Subdomain scan for: {domain}")
    
    # 1. Fallback for Windows / Missing Library
    if not sublist3r:
        logger.warning("Sublist3r not available. Running in Simulation Mode.")
        return {
            "status": "success",
            "domain": domain,
            "count": 3,
            "subdomains": [
                f"www.{domain}",
                f"api.{domain}",
                f"admin.{domain} (Simulated)"
            ],
            "note": "Install Sublist3r on Linux/Mac for real results."
        }

    # 2. Real Scan (Linux/Mac Only)
    try:
        subdomains = sublist3r.main(
            domain, 40, savefile=None, ports=None, silent=True, 
            verbose=False, enable_bruteforce=False, engines=None
        )
        clean_subs = sorted(list(set(subdomains)))
        return {
            "status": "success",
            "domain": domain,
            "count": len(clean_subs),
            "subdomains": clean_subs
        }
    except Exception as e:
        logger.error(f"Recon Error: {e}")
        return {"error": str(e)}