import json
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app

def extract_openapi():
    print("Extracting OpenAPI schema...")
    openapi_data = app.openapi()
    
    output_path = os.path.join(os.path.dirname(__file__), "..", "openapi.json")
    with open(output_path, "w") as f:
        json.dump(openapi_data, f, indent=2)
    
    print(f"OpenAPI schema saved to {output_path}")

if __name__ == "__main__":
    extract_openapi()
