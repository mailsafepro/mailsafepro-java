# app/audit/routes.py
from fastapi import APIRouter, Header, HTTPException
import os
from .service import audit_project

router = APIRouter()

# proteger endpoint con token simple en header X-Audit-Token (configura en env: AUDIT_SECRET)
AUDIT_SECRET = os.getenv("AUDIT_SECRET")  # obliga a config

@router.post("/audit_project")
async def run_audit(path: str = ".", x_audit_token: str | None = Header(None)):
    """
    Lanza auditoría en path (ruta absoluta o relativa a la raíz del proyecto).
    Header obligatorio: X-Audit-Token: <AUDIT_SECRET>
    """
    if not AUDIT_SECRET:
        raise HTTPException(500, "AUDIT_SECRET no definido en el entorno; configuración de seguridad requerida")
    if not x_audit_token or x_audit_token != AUDIT_SECRET:
        raise HTTPException(403, "X-Audit-Token inválido")

    # Normalizar path relativo a root (ejecutar desde la raíz)
    base_path = os.path.abspath(path)
    result = await audit_project(base_path)
    return result
