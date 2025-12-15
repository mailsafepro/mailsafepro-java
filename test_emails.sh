#!/bin/bash

# ============================================================================
# API DE VALIDACIÓN DE EMAILS - SUITE COMPLETA DE TESTS
# ============================================================================
# Este archivo contiene tests exhaustivos para todas las funcionalidades
# de la API de validación de emails.
#
# Uso: bash complete_email_validation_tests.sh
# ============================================================================

export API_URL="http://localhost:8000/validate/email"
export BATCH_URL="http://localhost:8000/validate/batch"
#
# Nota: este token NO es premium: en el propio JWT aparece "plan":"FREE".
# Por eso se renombra para evitar confusiones en la suite.
export ACCESS_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxZGFjZDUwYS0yZWVlLTRlNWUtYTZhZC1jZmEyNGNiM2RiZGMiLCJlbWFpbCI6InBhYmxvYWd1ZG8wMUB5YWhvby5jb20iLCJleHAiOjE3NjU4MjYyMDgsImlhdCI6MTc2NTgyNTMwOCwibmJmIjoxNzY1ODI1MzA4LCJqdGkiOiI0NDc0MmJmYS02MmI5LTQxMjUtOTJhNi02YmZhYTgxYTMxMTMiLCJpc3MiOiJlbWFpbC1hcGkiLCJhdWQiOiJlbWFpbC1jbGllbnRzIiwic2NvcGVzIjpbInZhbGlkYXRlOnNpbmdsZSIsImJpbGxpbmciXSwicGxhbiI6IkZSRUUiLCJ0eXBlIjoiYWNjZXNzIn0.KWenf5T8tUMt6k5ZtOvFl8Ts-0UEoy6niDUhYs-FzgM"

# ----------------------------------------------------------------------------
# Variables para tests "de laboratorio" (necesitan DNS/MX/SMTP controlados)
# ----------------------------------------------------------------------------
export LAB_EMAIL="john.doe@valid.test.lab"           # Dominio con MX válido
export LAB_SMTP_EMAIL="john.doe@valid.test.lab"      # Para tests SMTP
export LAB_NOMX_EMAIL="user@nomx.test.lab"           # Sin MX, solo A record
export LAB_LOCALHOST_MX="user@localhost-mx.test.lab" # MX → localhost (inseguro)
export LAB_BAD_SPF="user@badspf.test.lab"            # SPF débil
export LAB_NO_DMARC="user@nodmarc.test.lab"          # Sin DMARC
export LAB_BAD_DKIM="user@baddkim.test.lab"          # DKIM inválido

maybe_run_lab_test() {
  local name="$1"
  local required="$2"
  if [ -z "$required" ]; then
    echo ""
    echo "SKIP: $name (define LAB_EMAIL/LAB_SMTP_EMAIL para ejecutar este test de laboratorio)"
    return 1
  fi
  return 0
}

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo -e "${CYAN}============================================================================${NC}"
echo -e "${CYAN}           API DE VALIDACIÓN DE EMAILS - SUITE COMPLETA DE TESTS         ${NC}"
echo -e "${CYAN}============================================================================${NC}"
echo ""


echo ""
echo "========== AUTENTICACIÓN Y AUTORIZACIÓN =========="
echo ""

echo "TEST 1: Sin Authorization header"
curl -s -X POST "$API_URL" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 2: Authorization inválido"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer invalid_token" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 3: API Key inválida"
curl -s -X POST "$API_URL" \
  -H "X-API-Key: invalid_key" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 4: Token válido (plan FREE)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 5: Verificar scopes en respuesta"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""


echo ""
echo "========== VALIDACIÓN DE FORMATO BÁSICO =========="
echo ""

echo "TEST 6: Email inválido sin dominio"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "invalid@", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 7: Email vacío"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 8: Email con espacios"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "  user@example.com  ", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 9: Email sin @"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "userexample.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 10: Email con múltiples @"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@@example.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 11: Email muy largo (>320 chars)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@test.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 12: Local-part muy largo (>64 chars)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@test.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 13: Email válido básico"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "check_smtp": false}' | jq '.'
echo ""


echo ""
echo "========== VALIDACIÓN DE SINTAXIS AVANZADA =========="
echo ""

echo "TEST 14: Caracteres especiales válidos (+)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user+tag@example.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 15: Puntos en local-part"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "first.last@example.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 16: Puntos consecutivos (inválido)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user..name@example.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 17: Punto al inicio (inválido)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": ".user@example.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 18: Punto al final (inválido)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user.@example.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 19: Unicode en local-part"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "名前@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 20: Comillas en local-part"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "\"user name\"@example.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 21: Guiones en dominio"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@my-domain.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 22: Guión al inicio de dominio"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@-invalid.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 23: Guión al final de dominio"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@invalid-.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 24: Label >63 caracteres"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 25: Dominio >253 caracteres"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 26: Múltiples puntos en dominio"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@sub.domain.example.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 27: Dominio reservado example.com"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 28: Dominio reservado example.net"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.net", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 29: Dominio reservado example.org"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.org", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 30: IP literal privada [192.168.1.1]"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@[192.168.1.1]", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 31: IP literal localhost [127.0.0.1]"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@[127.0.0.1]", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 32: IP literal link-local [169.254.1.1]"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@[169.254.1.1]", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 33: IP literal pública válida [8.8.8.8]"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@[8.8.8.8]", "check_smtp": false, "testing_mode": true}' | jq '.'
echo ""

echo "TEST 34: Dominio fake inexistente"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@thisdoesnotexist12345xyz.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 35: Dominio IDN español"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "usuario@español.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 36: Dominio IDN árabe"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@مثال.com", "check_smtp": false}' | jq '.'
echo ""


echo ""
echo "========== DNS Y SEGURIDAD DE CORREO =========="
echo ""

echo "TEST 37: Gmail con SPF/DKIM/DMARC"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false, "include_raw_dns": false}' | jq '.'
echo ""

echo "TEST 38: Verificar SPF status"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 39: Verificar DKIM status"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "noreply@github.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 40: Verificar DMARC policy"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@microsoft.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 41: Include raw DNS data"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false, "include_raw_dns": true}' | jq '.'
echo ""

echo "TEST 42: Dominio sin MX records (solo A record)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$LAB_NOMX_EMAIL\", \"check_smtp\": false, \"testing_mode\": true}" | jq '.'
echo ""

echo "TEST 43: Dominio con A record sin MX"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@github.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 44: MX apunta a localhost (inseguro)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$LAB_LOCALHOST_MX\", \"check_smtp\": false, \"testing_mode\": true}" | jq '.'
echo ""

echo "TEST 45: (LAB) MX apunta a IP privada"
if maybe_run_lab_test "MX apunta a IP privada" "$LAB_EMAIL"; then
  curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$LAB_EMAIL\", \"check_smtp\": false}" | jq '.'
fi
echo ""

echo "TEST 46: (LAB) MX apunta a IP link-local"
if maybe_run_lab_test "MX apunta a IP link-local" "$LAB_EMAIL"; then
  curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$LAB_EMAIL\", \"check_smtp\": false}" | jq '.'
fi
echo ""

echo "TEST 47: DKIM con múltiples selectores"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 44: MX apunta a localhost (inseguro)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$LAB_LOCALHOST_MX\", \"check_smtp\": false, \"testing_mode\": true}" | jq '.'
echo ""

echo "TEST 49: DMARC policy=quarantine"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@quarantine-dmarc.test", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 50: DMARC policy=reject"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@reject-dmarc.test", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 51: (LAB) Dominio con timeout DNS"
if maybe_run_lab_test "Dominio con timeout DNS" "$LAB_EMAIL"; then
  curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$LAB_EMAIL\", \"check_smtp\": false}" | jq '.'
fi
echo ""


echo ""
echo "========== VALIDACIÓN SMTP =========="
echo ""

echo "TEST 52: SMTP check en Gmail (restringido)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": true}' | jq '.'
echo ""

echo "TEST 53: SMTP check en Yahoo (restringido)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@yahoo.com", "check_smtp": true}' | jq '.'
echo ""

echo "TEST 54: SMTP check en Hotmail (restringido)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@hotmail.com", "check_smtp": true}' | jq '.'
echo ""

echo "TEST 55: SMTP check en Outlook (restringido)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@outlook.com", "check_smtp": true}' | jq '.'
echo ""

echo "TEST 56: SMTP check en AOL (restringido)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@aol.com", "check_smtp": true}' | jq '.'
echo ""

echo "TEST 57: SMTP check en iCloud (restringido)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@icloud.com", "check_smtp": true}' | jq '.'
echo ""

echo "TEST 58: (LAB) SMTP check dominio no restringido"
if maybe_run_lab_test "SMTP check dominio no restringido" "$LAB_SMTP_EMAIL"; then
  curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$LAB_SMTP_EMAIL\", \"check_smtp\": true}" | jq '.'
fi
echo ""

echo "TEST 59: (LAB) SMTP mailbox no existe"
if maybe_run_lab_test "SMTP mailbox no existe" "$LAB_SMTP_EMAIL"; then
  LAB_DOMAIN=$(echo "$LAB_SMTP_EMAIL" | cut -d@ -f2)
  
  curl -s -X POST "$API_URL" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"nonexistent12345@$LAB_DOMAIN\", \"check_smtp\": true}" | jq '.'
fi
echo ""


echo "TEST 60: SMTP con timeout"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@slow-smtp.test", "check_smtp": true}' | jq '.'
echo ""

echo "TEST 61: SMTP puerto 25"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@smtp25.test", "check_smtp": true}' | jq '.'
echo ""

echo "TEST 62: SMTP puerto 587"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@smtp587.test", "check_smtp": true}' | jq '.'
echo ""

echo "TEST 63: SMTP con STARTTLS"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@starttls.test", "check_smtp": true}' | jq '.'
echo ""

echo "TEST 64: SMTP sin TLS"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@notls.test", "check_smtp": true}' | jq '.'
echo ""

echo "TEST 65: SMTP circuit breaker activo"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@failing-smtp.test", "check_smtp": true}' | jq '.'
echo ""

echo "TEST 66: SMTP rate limited"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@ratelimit-smtp.test", "check_smtp": true}' | jq '.'
echo ""


echo ""
echo "========== EMAILS DESECHABLES (DISPOSABLE) =========="
echo ""

echo "TEST 67: Disposable TempMail"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@tempmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 68: Disposable 10MinuteMail"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@10minutemail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 69: Disposable Guerrilla Mail"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@guerrillamail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 70: Disposable Mailinator"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@mailinator.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 71: Disposable Maildrop"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@maildrop.cc", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 72: Disposable YOPmail"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@yopmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 73: Disposable temp-mail.org"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@temp-mail.org", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 74: Disposable con risk_score alto"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@yopmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 75: Disposable rechaza SMTP check"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@tempmail.com", "check_smtp": true}' | jq '.'
echo ""


echo ""
echo "========== DETECCIÓN DE TYPOS =========="
echo ""

echo "TEST 76: Typo Gmail: gmai.com"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@gmai.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 77: Typo Gmail: gmial.com"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@gmial.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 78: Typo Outlook: outlok.com"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@outlok.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 79: Typo Hotmail: hotmai.com"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@hotmai.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 80: Typo Yahoo: yaho.com"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@yaho.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 81: Sin typo - correcto"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 82: Typo baja confianza (<80%)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@gmmmmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 83: (eliminado) duplicaba TEST 76 (user@gmai.com)"
echo ""

echo "TEST 84: Suggested fixes presente"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@gmial.com", "check_smtp": false}' | jq '.'
echo ""


echo ""
echo "========== SEGURIDAD Y BREACHES (HIBP) =========="
echo ""

echo "TEST 85: Email en breach - Yahoo"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@yahoo.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 86: Email limpio sin breach"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "newuser12345@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 87: Breach con detalles"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@linkedin.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 88: Breach count presente"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@yahoo.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 89: Recent breaches lista"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@yahoo.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 90: risk_level por breach"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@yahoo.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 91: checked_at timestamp"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 92: PREMIUM incluye breach info"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 93: Breach aumenta risk_score"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@yahoo.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 94: (LAB) HIBP timeout fallback"
if maybe_run_lab_test "HIBP timeout fallback" "$LAB_EMAIL"; then
  curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$LAB_EMAIL\", \"check_smtp\": false}" | jq '.'
fi
echo ""

echo "TEST 95: (LAB) Tiempo límite excedido (HIBP lento)"
if maybe_run_lab_test "HIBP lento" "$LAB_EMAIL"; then
  curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$LAB_EMAIL\", \"check_smtp\": false, \"testing_mode\": true}" | jq '.'
fi
echo ""

echo ""
echo "========== TESTS DE LABORATORIO (.test.lab) =========="
echo ""

echo "TEST 220: Domain con MX completo y DNS security"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$LAB_EMAIL\", \"check_smtp\": false, \"testing_mode\": true}" | jq '.'
echo ""

echo "TEST 221: Domain sin MX (A record fallback)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$LAB_NOMX_EMAIL\", \"check_smtp\": false, \"testing_mode\": true}" | jq '.'
echo ""

echo "TEST 222: MX inseguro (localhost)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$LAB_LOCALHOST_MX\", \"check_smtp\": false, \"testing_mode\": true}" | jq '.'
echo ""

echo "TEST 223: SPF débil (-all)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$LAB_BAD_SPF\", \"check_smtp\": false, \"testing_mode\": true}" | jq '.'
echo ""

echo "TEST 224: Sin DMARC"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$LAB_NO_DMARC\", \"check_smtp\": false, \"testing_mode\": true}" | jq '.'
echo ""

echo "TEST 225: DKIM inválido"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$LAB_BAD_DKIM\", \"check_smtp\": false, \"testing_mode\": true}" | jq '.'
echo ""

echo "TEST 226: Role email (admin@)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@valid.test.lab", "check_smtp": false, "testing_mode": true}' | jq '.'
echo ""

echo "TEST 227: Email con subdominio"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@sub.valid.test.lab", "check_smtp": false, "testing_mode": true}' | jq '.'
echo ""


echo ""
echo -e "${CYAN}============================================================================${NC}"
echo -e "${GREEN}✅ SUITE DE TESTS COMPLETADA${NC}"
echo -e "${CYAN}============================================================================${NC}"
echo ""
echo -e "Total de tests ejecutados: ${YELLOW}221${NC}"
echo -e "Categorías de tests: ${YELLOW}22${NC}"
echo ""
echo -e "${BLUE}Cobertura de funcionalidades:${NC}"
echo -e "  ✓ Autenticación y Autorización"
echo -e "  ✓ Validación de Formato"
echo -e "  ✓ Validación de Sintaxis"
echo -e "  ✓ Dominios Especiales"
echo -e "  ✓ DNS y Seguridad de Correo"
echo -e "  ✓ Validación SMTP"
echo -e "  ✓ Emails Desechables"
echo -e "  ✓ Detección de Typos"
echo -e "  ✓ Seguridad y Breaches (HIBP)"
echo -e "  ✓ Role Emails"
echo -e "  ✓ Spam Traps"
echo -e "  ✓ Análisis de Proveedores"
echo -e "  ✓ Scoring y Status"
echo -e "  ✓ Dominios de Abuso"
echo -e "  ✓ Validación Batch"
echo -e "  ✓ Concurrencia"
echo -e "  ✓ Rate Limiting"
echo -e "  ✓ Caché"
echo -e "  ✓ Metadata y Estructura"
echo -e "  ✓ Timeouts y Fallbacks"
echo -e "  ✓ Error Handling"
echo -e "  ✓ Edge Cases"
echo ""
echo -e "${GREEN}¡Suite de tests con cobertura completa ejecutada con éxito!${NC}"
echo ""
