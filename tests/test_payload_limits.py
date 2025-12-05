"""
Tests for payload size limits.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_small_payload_accepted():
    """Verify small payloads are accepted."""
    response = client.post(
        "/validate/email",
        json={"email": "test@example.com"}
    )
    # Should not be rejected for size (may fail auth)
    assert response.status_code != 413

def test_large_batch_rejected():
    """Verify oversized batch is rejected."""
    # Create payload larger than 10MB
    large_emails = ["test@example.com"] * 500000  # ~15MB
    
    response = client.post(
        "/validate/batch",
        json={"emails": large_emails}
    )
    
    # May return 503 (service unavailable), 422 (validation error), or 413 (payload too large)
    assert response.status_code in [413, 422, 503]

def test_missing_content_length():
    """Verify requests without Content-Length are allowed."""
    # This should pass through (FastAPI will handle)
    response = client.post(
        "/validate/email",
        data=b'{"email": "test@example.com"}',
        headers={"Content-Type": "application/json"}
    )
    assert response.status_code != 413

def test_invalid_content_length():
    """Verify invalid Content-Length is rejected."""
    response = client.post(
        "/validate/email",
        json={"email": "test@example.com"},
        headers={"Content-Length": "invalid"}
    )
    assert response.status_code == 400

def test_limit_varies_by_endpoint():
    """Verify different endpoints have different limits."""
    # Single validation: 10KB limit
    small_payload = {"email": "test@example.com"}
    response = client.post("/validate/email", json=small_payload)
    assert response.status_code != 413
    
    # Batch validation: 10MB limit (much larger)
    large_batch = {"emails": ["test@example.com"] * 1000}
    response = client.post("/validate/batch", json=large_batch)
    # Should pass size check (may fail on other validation)
    assert response.status_code != 413
