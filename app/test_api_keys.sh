#!/bin/bash

BASE_URL="http://localhost:8000"
MASTER_API_KEY="fb78f9abe3ff499fa09c6c7f7cb26dcc"
PLAN="FREE"

echo "🔐 1. Creando nueva API Key para el plan '$PLAN'..."
API_KEY_RESPONSE=$(curl -s -X POST "$BASE_URL/api-keys" \
  -H "X-API-Key: $MASTER_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"plan\":\"$PLAN\"}")

NEW_API_KEY=$(echo "$API_KEY_RESPONSE" | jq -r '.api_key')
echo "➡️  Nueva API Key: $NEW_API_KEY"

echo ""
echo "📊 2. Consultando /usage con la clave maestra..."
curl -s -X GET "$BASE_URL/usage" -H "X-API-Key: $MASTER_API_KEY" | jq
echo ""

echo "📋 3. Listando claves del cliente..."
LIST_RESPONSE=$(curl -s -X GET "$BASE_URL/api-keys" \
  -H "X-API-Key: $MASTER_API_KEY")

echo "$LIST_RESPONSE" | jq

KEY_HASH=$(echo "$LIST_RESPONSE" | jq -r '.keys[-1].key_hash')
echo "🔎 Último key_hash detectado: $KEY_HASH"

echo ""
echo "❌ 4. Revocando la clave $KEY_HASH..."
curl -s -o /dev/null -w "Código HTTP: %{http_code}\n" -X DELETE "$BASE_URL/api-keys/$KEY_HASH" \
  -H "X-API-Key: $MASTER_API_KEY"

echo ""
echo "✅ 5. Verificando que la clave esté revocada..."
curl -s -X GET "$BASE_URL/api-keys" \
  -H "X-API-Key: $MASTER_API_KEY" | jq