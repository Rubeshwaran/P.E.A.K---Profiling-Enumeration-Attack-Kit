import subprocess
import xml.etree.ElementTree as ET
import logging
import shutil
import os

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# -----------------------------------------------------------
# CONFIGURATION: PATH TO NMAP
# -----------------------------------------------------------
# If you haven't installed Nmap yet, download it: https://nmap.org/download.html
# Then update this path to where you installed it.
MANUAL_NMAP_PATH = r"C:\Program Files (x86)\Nmap\nmap.exe" 
# -----------------------------------------------------------

def run_nmap_scan(target_domain):
    """
    Runs a quick Nmap scan (Top 100 ports) and returns open ports.
    """
    
    # 1. Find Nmap
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        if os.path.exists(MANUAL_NMAP_PATH):
            nmap_path = MANUAL_NMAP_PATH
        else:
            return {"error": "Nmap not found. Please install Nmap and check the path in modules/peak_nmap.py"}

    # Clean domain (remove http/https)
    if "://" in target_domain:
        target_domain = target_domain.split("://")[1].split("/")[0]

    logger.info(f"Starting Nmap scan on {target_domain}...")

    # 2. Construct Command
    # -T4: Fast timing
    # -F: Fast mode (Top 100 ports)
    # -oX -: Output XML to stdout
    command = [nmap_path, "-T4", "-F", "-oX", "-", target_domain]

    try:
        # 3. Run Nmap
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate()

        if not stdout:
            return {"error": f"Nmap failed to generate output. Error: {stderr}"}

        # 4. Parse XML Output
        try:
            root = ET.fromstring(stdout)
        except ET.ParseError:
            return {"error": "Could not parse Nmap XML output."}

        open_ports = []
        for host in root.findall('host'):
            ports = host.find('ports')
            if ports:
                for port in ports.findall('port'):
                    state = port.find('state').get('state')
                    if state == 'open':
                        port_id = port.get('portid')
                        service = port.find('service').get('name', 'unknown')
                        open_ports.append({"port": port_id, "service": service})

        logger.info(f"Nmap complete. Found {len(open_ports)} ports.")
        
        return {
            "status": "success",
            "target": target_domain,
            "count": len(open_ports),
            "ports": open_ports
        }

    except Exception as e:
        logger.error(f"Nmap Error: {e}")
        return {"error": str(e)}