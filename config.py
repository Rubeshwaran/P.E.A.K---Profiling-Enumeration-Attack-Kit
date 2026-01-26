import os

class Config:
    """Application-wide configuration settings."""
    # Security Secrets
    FLASK_SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'your_super_secret_key_here_change_this_in_production_!!!')
    
    # Paths & Database
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DATABASE_PATH = os.path.join(BASE_DIR, 'data', 'visto.db')
    LOG_DIR = os.path.join(BASE_DIR, 'data', 'logs')
    DATA_DIR = os.path.join(BASE_DIR, 'data') 
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    
    # Tool Paths
    # Note: On Linux/Mac, you might use '/usr/bin/nmap'
    NMAP_PATH = r"C:\Program Files (x86)\Nmap\nmap.exe"

    # --- P.E.A.K AI Configuration (Ollama) ---
    # We use the native Ollama endpoint for the P.E.A.K agent
    LLM_API_URL = os.environ.get('LLM_API_URL', 'http://localhost:11434/api/generate')
    LLM_MODEL_NAME = os.environ.get('LLM_MODEL_NAME', 'phi3')
    LLM_API_KEY = os.environ.get('LLM_API_KEY', 'none') # Local Ollama doesn't typically need a key

    # --- External API Keys ---
    SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '')

    # --- Mobile Security (MobSF) ---
    # Ensure MobSF is running on this URL (default is port 8000)
    MOBSF_URL = os.environ.get('MOBSF_URL', 'http://localhost:8000')
    MOBSF_API_KEY = os.environ.get('MOBSF_API_KEY', 'YOUR_MOBSF_API_KEY_HERE')

    # --- Scanning Control ---
    ALLOW_EXTERNAL_SCANNING = True
    INTERNAL_IP_RANGES = [
        "127.0.0.0/8",      # Loopback
        "10.0.0.0/8",       # Private A
        "172.16.0.0/12",    # Private B
        "192.168.0.0/16"    # Private C
    ]

    # Server Settings
    FLASK_PORT = 5000
    DEBUG_MODE = True