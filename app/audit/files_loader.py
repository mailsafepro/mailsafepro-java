# app/audit/files_loader.py
import os
from typing import Dict, List, Tuple

DEFAULT_EXTENSIONS = (".py", ".md", ".txt")

def load_project_files(base_path: str, extensions: Tuple[str, ...] = DEFAULT_EXTENSIONS,
                       exclude_dirs: List[str] = None) -> Dict[str, str]:
    """
    Recorre base_path y devuelve {ruta_relativa: contenido} filtrando por extensiones.
    No incluye archivos binarios ni .pyc ni .egg-info ni __pycache__.
    """
    if exclude_dirs is None:
        exclude_dirs = ["__pycache__", ".git", "venv", "env", "node_modules", "toni.egg-info", "dist", "build"]

    project_files = {}
    for root, dirs, files in os.walk(base_path):
        # filtrar dirs in-place para no entrar en ellos
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for fname in files:
            if fname.endswith((".pyc", ".pyo")):
                continue
            if fname.startswith("."):
                continue
            if not any(fname.endswith(ext) for ext in extensions):
                continue
            full = os.path.join(root, fname)
            rel = os.path.relpath(full, base_path)
            try:
                with open(full, "r", encoding="utf-8") as f:
                    project_files[rel] = f.read()
            except Exception:
                # skip archivos que no se puedan leer por cualquier motivo
                continue
    return project_files
