import subprocess
import json
import shutil
import logging
import os

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run_nuclei_scan(target_url):
    # -----------------------------------------------------------
    # DEBUG CONFIGURATION
    # -----------------------------------------------------------
    # 1. Update this to your EXACT path
    MANUAL_NUCLEI_PATH = r"C:\Users\RubeshwaranChokkalin\PEAK\PEAK\tools\nuclei.exe"
    # -----------------------------------------------------------

    # Check if file exists
    if not os.path.exists(MANUAL_NUCLEI_PATH):
        return {"error": f"CRITICAL: The file does not exist at: {MANUAL_NUCLEI_PATH}"}

    logger.info(f"DEBUG: Attempting to run Nuclei from: {MANUAL_NUCLEI_PATH}")
    logger.info(f"DEBUG: Target: {target_url}")

    # Construct Command (Removed -silent to see errors in logs)
    command = [
        MANUAL_NUCLEI_PATH,
        "-u", target_url,
        "-j",
        "-severity", "critical,high,medium" 
    ]

    try:
        # Run process
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        stdout, stderr = process.communicate()

        # LOG EVERYTHING
        logger.info(f"DEBUG STDOUT (First 100 chars): {stdout[:100]}")
        logger.warning(f"DEBUG STDERR: {stderr}")

        # If stdout is empty, something went wrong. Return the error to UI.
        if not stdout.strip():
            # If stderr is also empty, it might be a path/permission issue
            error_msg = stderr if stderr else "Nuclei ran but returned NO output. Check if templates are installed."
            return {"error": f"NUCLEI FAILURE: {error_msg}"}

        # Parse JSON
        results = []
        for line in stdout.splitlines():
            try:
                if line.strip():
                    data = json.loads(line)
                    finding = {
                        "name": data.get("info", {}).get("name", "Unknown Vuln"),
                        "severity": data.get("info", {}).get("severity", "low"),
                        "type": data.get("type", "unknown"),
                        "matched_at": data.get("matched-at", "")
                    }
                    results.append(finding)
            except json.JSONDecodeError:
                continue
        
        return {
            "status": "success",
            "target": target_url,
            "count": len(results),
            "findings": results
        }

    except Exception as e:
        logger.error(f"Execution Exception: {str(e)}")
        return {"error": f"PYTHON CRASH: {str(e)}"}