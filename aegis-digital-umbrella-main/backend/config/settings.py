import os
from pathlib import Path
import yaml
import logging

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('debug.log')
    ]
)

# Configuration paths
ROOT_DIR = Path(__file__).parent.parent
CONFIG_PATH = ROOT_DIR / '.emergent'

def load_emergent_config():
    """Load configuration from .emergent YAML file"""
    try:
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH, 'r') as f:
                return yaml.safe_load(f) or {}
        logging.warning(f"Config file not found at {CONFIG_PATH}")
        return {}
    except Exception as e:
        logging.warning(f"Config load error: {str(e)}")
        return {}

# Environment variables
MONGODB_URL = os.environ.get('MONGODB_URL', 'mongodb://localhost:27017')
DB_NAME = os.environ.get('DB_NAME', 'aegis_db')
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')

# CORS settings
CORS_ORIGINS = ["*"]  # Allow all origins for development
CORS_CREDENTIALS = True
CORS_METHODS = ["*"]
CORS_HEADERS = ["*"]

