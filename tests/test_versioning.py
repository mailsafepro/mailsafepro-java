"""
Tests for API Versioning & Deprecation
"""

import pytest
from fastapi import FastAPI, Response, Depends
from fastapi.testclient import TestClient
from app.versioning.deprecation import deprecate_endpoint, DeprecationDependency
from datetime import datetime

# Setup dummy app for testing
app = FastAPI()

@app.get("/v1/test")
def v1_endpoint():
    return {"version": "v1"}

@app.get("/deprecated")
def deprecated_endpoint(response: Response):
    deprecate_endpoint(
        response,
        sunset_date=datetime(2025, 12, 31, 23, 59, 59),
        link="https://example.com/migration"
    )
    return {"status": "deprecated"}

@app.get("/deprecated-dependency", dependencies=[Depends(DeprecationDependency(sunset_date=datetime(2030, 1, 1)))])
def deprecated_dependency_endpoint():
    return {"status": "deprecated_dep"}

client = TestClient(app)

def test_deprecation_headers_manual():
    """Test manual deprecation headers."""
    response = client.get("/deprecated")
    assert response.status_code == 200
    assert response.headers["Deprecation"] == "true"
    assert "Sunset" in response.headers
    assert "Link" in response.headers
    assert "Wed, 31 Dec 2025" in response.headers["Sunset"]

def test_deprecation_dependency():
    """Test deprecation via dependency."""
    response = client.get("/deprecated-dependency")
    assert response.status_code == 200
    assert response.headers["Deprecation"] == "true"
    assert "Sunset" in response.headers
    assert "Tue, 01 Jan 2030" in response.headers["Sunset"]
