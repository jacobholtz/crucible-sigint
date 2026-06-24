"""
Crucible SIGINT — uvicorn entry point.

Modules live under src/. Adding that directory to sys.path keeps the bare
imports inside src/ (e.g. `import cache_store`, `import cluster_fingerprint`)
working without rewriting them as `from src.cache_store import ...`.

Run the dev server with:
    venv/bin/uvicorn main:app --reload

Tests can do the same setup with:
    import sys, pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "src"))
"""
import sys
from pathlib import Path

_SRC = Path(__file__).parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from crucible_app import app  # noqa: E402  (sys.path setup must precede the import)

__all__ = ["app"]
