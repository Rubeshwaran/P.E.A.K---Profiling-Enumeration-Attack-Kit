import subprocess
import logging
import sys
import os
import re

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- PEAK BRANDING ---
PEAK_BANNER = r"""
    ____  _____    ___    __ __
   / __ \/ ____|  /   |  / //_/
  / /_/ / __/    / /| | / ,<   
 / ____/ /___   / ___ |/ /| |  
/_/   /_____/  /_/  |_/_/ |_|  
      INTELLIGENT AGENT
"""

def clean_and_rebrand_output(raw_text):
    """
    Strips CAI branding and injects PEAK identity.
    """
    if not raw_text: return ""

    # Remove ANSI codes
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    clean_text = ansi_escape.sub('', raw_text)

    # Filter out CAI logs
    lines = clean_text.split('\n')
    filtered_lines = []
    ignore_patterns = ["pyproject.toml", "CAI Framework", "Alias Robotics", "httpx", "Get api_key"]

    for line in lines:
        if any(x in line for x in ignore_patterns): continue
        filtered_lines.append(line)

    return PEAK_BANNER + "\n" + "\n".join(filtered_lines)

def run_peak_agent(agent_name, prompt):
    logger.info(f"PEAK Agent ({agent_name}) requested.")

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    loader_path = os.path.join(base_dir, "cai_loader.py")

    # Command: python cai_loader.py <agent> <prompt>
    command = [sys.executable, loader_path, agent_name, prompt]

    try:
        # Run process
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='ignore',
            cwd=base_dir
        )
        
        # Longer timeout for real scanning (120s)
        stdout, stderr = process.communicate(timeout=120)

        if stderr and "ERROR" in stderr:
            logger.warning(f"Agent Stderr: {stderr}")

        if not stdout.strip():
            # If empty, check stderr for clues
            return {"status": "error", "output": f"Agent returned no data. Logs:\n{stderr}"}

        # Success - Rebrand output
        return {
            "status": "success",
            "agent": agent_name,
            "output": clean_and_rebrand_output(stdout)
        }

    except subprocess.TimeoutExpired:
        process.kill()
        return {"status": "error", "output": "Agent timed out (120s). Target might be slow."}
    except Exception as e:
        return {"status": "error", "output": f"System Error: {str(e)}"}