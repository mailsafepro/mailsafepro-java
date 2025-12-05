#!/bin/bash
set -e

# 1. Extract OpenAPI Schema
echo "Extracting OpenAPI schema..."
python scripts/extract_openapi.py

# 2. Generate Python SDK Models
echo "Generating Python SDK models..."
mkdir -p sdk/python/models
datamodel-code-generator --input openapi.json --output sdk/python/models/models.py --output-model-type pydantic_v2.BaseModel

# 3. Generate TypeScript Client (requires node)
if command -v npx &> /dev/null; then
    echo "Generating TypeScript SDK..."
    mkdir -p sdk/typescript
    npx openapi-typescript-codegen --input openapi.json --output sdk/typescript --client axios --name MailSafeProClient
else
    echo "Node.js/npx not found, skipping TypeScript SDK generation."
fi

echo "SDK generation complete!"
