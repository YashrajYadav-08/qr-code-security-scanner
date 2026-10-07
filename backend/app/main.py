from pathlib import Path
import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

API_TITLE = os.getenv("API_TITLE", "QR Guard API")
API_VERSION = os.getenv("API_VERSION", "0.1.0")
DEBUG = os.getenv("DEBUG", "false").lower() == "true"

THREAT_FEED_API_KEY = os.getenv("THREAT_FEED_API_KEY", "")
BLOCKCHAIN_RPC_URL = os.getenv("BLOCKCHAIN_RPC_URL", "")

ALLOWED_SCHEMES = {"http", "https"}
MAX_URL_LENGTH = 2048

def is_dev() -> bool:
    return DEBUG
