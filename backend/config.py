import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

FALKOR_HOST: str = os.getenv("FALKOR_HOST", "localhost")
FALKOR_PORT: int = int(os.getenv("FALKOR_PORT", "6379"))
# Optional: FalkorDB Cloud / authenticated instances
FALKOR_USERNAME: str = os.getenv("FALKOR_USERNAME", "")
FALKOR_PASSWORD: str = os.getenv("FALKOR_PASSWORD", "")
FALKOR_SSL: bool = os.getenv("FALKOR_SSL", "").lower() in ("1", "true", "yes")
FALKOR_QUERY_TIMEOUT_MS: int = int(os.getenv("FALKOR_QUERY_TIMEOUT_MS", "20000"))
if FALKOR_QUERY_TIMEOUT_MS < 1:
    raise ValueError("FALKOR_QUERY_TIMEOUT_MS must be a positive integer")

GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
# Model names change often: override with GEMINI_MODEL if the default is not available on your key.
GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

GRAPH_NAME: str = os.getenv("GRAPH_NAME", "blast")
API_PORT: int = int(os.getenv("API_PORT", "8001"))

BASE_DIR: Path = Path(__file__).resolve().parent
CACHE_DIR: Path = BASE_DIR / "cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
GRAPH_BACKEND: str = os.getenv("GRAPH_BACKEND", "sqlite").lower()
if GRAPH_BACKEND not in {"sqlite", "falkordb"}:
    raise ValueError("GRAPH_BACKEND must be either 'sqlite' or 'falkordb'")
SQLITE_DB_PATH: Path = Path(
    os.getenv("BLAST_RADIUS_SQLITE_PATH", str(CACHE_DIR / "blast_radius.sqlite3"))
).expanduser()
