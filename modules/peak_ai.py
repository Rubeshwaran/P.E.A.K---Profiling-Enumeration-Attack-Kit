import requests
import json
import logging

logger = logging.getLogger(__name__)

class PeakAI:
    def __init__(self):
        self.OLLAMA_API = "http://localhost:11434/api/generate"
        self.MODEL = "phi3" 

    # UPDATE THIS LINE TO ACCEPT 'exposed_paths'
    def generate_attack_plan(self, tech_stack_list, exposed_paths):
        """
        Generates specific attack commands based on the profile.
        """
        stack_str = ", ".join(tech_stack_list)
        paths_str = ", ".join(exposed_paths) if exposed_paths else "None detected"
        
        prompt = f"""
        ACT AS: Elite Red Team Operator.
        TARGET: Tech Stack: [{stack_str}], Exposed Paths: [{paths_str}]
        
        MISSION: Provide 3 specific, executable attack commands to compromise this target.
        
        RULES:
        1. NO generic advice (e.g. "Check for XSS").
        2. ONLY executable commands (e.g. "sqlmap -u...", "wpscan...", "curl...").
        3. If '.git' is exposed, suggest 'git-dumper'.
        4. If 'WordPress' is detected, suggest 'wpscan'.
        
        OUTPUT FORMAT (Markdown):
        ### Vector 1: [Name]
        **Command:** `[Command]`
        **Why:** [Brief reason]
        
        ### Vector 2: [Name]
        **Command:** `[Command]`
        **Why:** [Brief reason]
        
        ### Vector 3: [Name]
        **Command:** `[Command]`
        **Why:** [Brief reason]
        """

        payload = {
            "model": self.MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.3} 
        }

        try:
            logger.info(f"Sending prompt to Ollama ({self.MODEL})...")
            # Increased timeout to prevent crashes on slower PCs
            response = requests.post(self.OLLAMA_API, json=payload, timeout=300)
            result = response.json()
            return result.get("response", "No response.")
        except requests.exceptions.ReadTimeout:
            return "Error: AI generation timed out. Try a smaller model or increase timeout."
        except Exception as e:
            return f"AI Error: {str(e)}"