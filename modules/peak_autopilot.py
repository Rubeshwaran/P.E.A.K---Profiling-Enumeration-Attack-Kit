import logging
from modules.peak_profiler import analyze_tech_stack
from modules.peak_nmap import run_nmap_scan
from modules.peak_nuclei import run_nuclei_scan
# from modules.peak_recon import run_subdomain_scan (If you added this)

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run_autopilot(target_url):
    """
    The 'One-Click' function. 
    1. Recon -> 2. Vuln Scan -> 3. Decision -> 4. Report
    """
    report = {
        "target": target_url,
        "steps_taken": [],
        "critical_findings": []
    }

    # --- STEP 1: INITIAL RECON ---
    logger.info(" [1/4] Starting Auto-Pilot Recon...")
    
    # Run Tech Profiler
    tech_data = analyze_tech_stack(target_url)
    report["tech_stack"] = tech_data.get("tech_stack", [])
    report["steps_taken"].append("Tech Stack Analysis")

    # Run Nmap (Extract domain from URL first)
    domain = target_url.split("//")[-1].split("/")[0]
    nmap_data = run_nmap_scan(domain)
    report["open_ports"] = nmap_data.get("ports", [])
    report["steps_taken"].append("Nmap Port Scan")

    # --- STEP 2: DECISION ENGINE (LOGIC BASED) ---
    # Here we decide what to do based on Step 1 results.
    # In a full AI version, we would ask Phi-3 here. For now, we use "Rule-Based AI".
    
    tools_to_run = []
    
    # Rule 1: Always run Nuclei on Web Ports
    if any(p['port'] in ['80', '443', '8080'] for p in report['open_ports']):
        tools_to_run.append("nuclei")

    # Rule 2: If WordPress is detected, suggest WPScan (Future integration)
    if "WordPress" in str(report["tech_stack"]):
        report["steps_taken"].append("Detected WordPress - Flagged for WPScan")

    # --- STEP 3: ATTACK EXECUTION ---
    logger.info(" [3/4] Executing Attack Plan...")
    
    if "nuclei" in tools_to_run:
        nuclei_res = run_nuclei_scan(target_url)
        report["nuclei_findings"] = nuclei_res.get("findings", [])
        report["steps_taken"].append(f"Nuclei Scan ({nuclei_res.get('count', 0)} issues)")

        # Filter for Critical/High to highlight them
        for f in report["nuclei_findings"]:
            if f['severity'] in ['critical', 'high']:
                report["critical_findings"].append(f)

    # --- STEP 4: REPORT GENERATION ---
    logger.info(" [4/4] Mission Complete.")
    
    return report