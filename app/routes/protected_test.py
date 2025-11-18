from fastapi import APIRouter, Security, Depends, status
from fastapi.security import HTTPAuthorizationCredentials
from app.auth import (
    get_current_client, 
    validate_api_key,
    security_scheme
)
from app.models import TokenData, APIKeyResponse
from app.config import settings
from app.logger import logger

router = APIRouter(tags=["Security Tests"])

@router.get(
    "/protected-endpoint",
    response_model=APIKeyResponse,
    responses={
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "Insufficient permissions"}
    },
    summary="Test endpoint for API key authentication",
    description="""Valida el funcionamiento de:
    - Autenticación por API Key
    - Sistema de scopes
    - Respuestas estandarizadas de error"""
)
async def protected_endpoint(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    current_client: TokenData = Security(get_current_client, scopes=["basic"]),
    api_key: str = Depends(validate_api_key)
):
    if settings.debug:
        logger.debug(f"Access granted to {current_client.sub} via API key")
    return {
        "message": "Authorization successful",
        "client_id": current_client.sub[:6],
        "scopes": current_client.scopes,
        "key_type": "api_key",
        "remaining_quota": 999  # Ejemplo de dato adicional para planes premium
    }

@router.get(
    "/protected-route",
    response_model=APIKeyResponse,
    include_in_schema=settings.enable_test_routes,
    summary="Test endpoint for JWT authentication"
)
async def protected_route(
    current_client: TokenData = Security(get_current_client, scopes=["basic"])
):
    if settings.debug:
        logger.debug(f"Access granted to {current_client.sub} via JWT")
    return {
        "message": "JWT authorization successful",
        "client_id": current_client.sub[:6],
        "scopes": current_client.scopes,
        "key_type": "jwt"
    }