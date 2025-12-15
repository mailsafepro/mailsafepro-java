# app/audit/service.py
import json
import math
from typing import Dict, List
from .files_loader import load_project_files
from .gemini_client import generate_text

# Control de tamaño: caracteres por lote (ajusta según pruebas; tokens ≈ 4 chars)
DEFAULT_CHUNK_CHARS = 12000  # prudente para no llegar al límite del modelo

def chunk_files_by_chars(files: Dict[str, str], max_chars: int = DEFAULT_CHUNK_CHARS) -> List[Dict[str, str]]:
    """
    Agrupa ficheros en lotes de <= max_chars (suma de longitudes).
    Devuelve lista de dicts {relpath: content}.
    """
    batches = []
    current = {}
    current_len = 0
    for path, content in files.items():
        ln = len(content)
        # si un archivo es enorme, lo partimos internamente por slices
        if ln > max_chars:
            # añadir el trozo actual si existe
            if current:
                batches.append(current); current = {}; current_len = 0
            # trocear archivo en ventanas
            start = 0
            while start < ln:
                end = start + max_chars
                batches.append({f"{path}__part_{start}": content[start:end]})
                start = end
            continue
        if current_len + ln > max_chars:
            batches.append(current)
            current = {path: content}
            current_len = ln
        else:
            current[path] = content
            current_len += ln
    if current:
        batches.append(current)
    return batches

def build_audit_prompt(batch: Dict[str, str]) -> str:
    """
    Genera prompt pidiendo auditoría estructurada en JSON.
    """
    instruct = (
        "Eres un auditor senior de código Python/FastAPI. Para cada archivo que te doy, "
        "devuelve un objeto JSON con campos: filename, summary (breve), issues (lista de strings), "
        "severity (low|medium|high) e recommendations (lista de strings). "
        "Entrega UN JSON válido que sea una lista de objetos. Responde SOLO con JSON.\n\n"
    )
    body = ""
    for path, content in batch.items():
        body += f"### FILE: {path}\n{content}\n\n"
    return instruct + body

async def audit_project(base_path: str) -> Dict[str, object]:
    """
    Ejecuta la auditoría sobre el árbol base_path. Devuelve dict con 'ok' y 'results' (si JSON parseable),
    o 'raw' con el texto si no se pudo parsear.
    """
    files = load_project_files(base_path)
    if not files:
        return {"ok": False, "reason": "no_files_found"}

    batches = chunk_files_by_chars(files)
    aggregated = []
    for i, batch in enumerate(batches, 1):
        prompt = build_audit_prompt(batch)
        resp_json = await generate_text(prompt, temperature=0.0, max_output_tokens=1024)
        # extraer texto generado (dependiendo de respuesta del endpoint)
        text = ""
        # la respuesta del generativelanguage puede tener distintas formas; 
        # tratamos de recuperar donde suele venir el texto
        if isinstance(resp_json, dict):
            # caso típico: candidates -> [ { output: "..."}]
            candidates = resp_json.get("candidates") or resp_json.get("outputs") or []
            if candidates and isinstance(candidates, list):
                first = candidates[0]
                text = first.get("output") or first.get("content") or json.dumps(first)
            else:
                text = json.dumps(resp_json)
        else:
            text = str(resp_json)

        # Intentar parsear JSON estrictamente; si falla, guardamos raw
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                aggregated.extend(parsed)
            else:
                # si no es lista, lo encapsulamos
                aggregated.append({"filename": f"batch_{i}", "raw": parsed})
        except Exception:
            aggregated.append({"filename": f"batch_{i}", "raw_text": text})

    return {"ok": True, "results": aggregated, "files_count": len(files)}
