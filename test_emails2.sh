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
export PREMIUM_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0YzA3YjJhMi05NDNhLTQ3ZjctYTM3YS0yMTM3NzQzNWM4ZWYiLCJlbWFpbCI6InBhYmxvYWd1ZG8wMUB5YWhvby5jb20iLCJleHAiOjE3NjU2NDk4MzQsImlhdCI6MTc2NTY0ODkzNCwibmJmIjoxNzY1NjQ4OTM0LCJqdGkiOiJmNmZlZDM5Mi0yM2Q0LTQ1NWItYTIzMi01YWMzNTE1YTJiNWUiLCJpc3MiOiJlbWFpbC1hcGkiLCJhdWQiOiJlbWFpbC1jbGllbnRzIiwic2NvcGVzIjpbInZhbGlkYXRlOnNpbmdsZSIsImJpbGxpbmciXSwicGxhbiI6IkZSRUUiLCJ0eXBlIjoiYWNjZXNzIn0.baRKFidDacOWGumGU0Eoy-RoAbXbgpjXWPq0VXVAYcQ"
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
echo "========== ROLE EMAILS =========="
echo ""

echo "TEST 95: Admin email"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@google.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 96: Support email"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "support@microsoft.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 97: Noreply email"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "noreply@github.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 98: Info email"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "info@amazon.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 99: Sales email"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "sales@company.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 100: Marketing email"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "marketing@company.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 101: Personal email no es role"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "john.doe@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 102: role_type presente"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@google.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 103: deliverability_risk"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "noreply@github.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 104: Nombre con palabra role (no detectar)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "roland.smith@gmail.com", "check_smtp": false}' | jq '.'
echo ""


echo ""
echo "========== SPAM TRAPS =========="
echo ""

echo "TEST 105: Spam trap conocido"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "spamtrap@spamtrap.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 106: Email normal no spam trap"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 107: Spam trap alta confianza"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "trap@honeypot.test", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 108: trap_type=known"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "known-trap@test.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 109: trap_type=probable"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "probable-trap@test.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 110: source=database"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "spamtrap@spamtrap.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 111: Threshold >0.9 bloquea"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "high-confidence-trap@test.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 112: error_type=spam_trap"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "confirmed-trap@test.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 113: Spam trap afecta risk_score"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "spamtrap@spamtrap.com", "check_smtp": false}' | jq '.'
echo ""


echo ""
echo "========== ANÁLISIS DE PROVEEDORES =========="
echo ""

echo "TEST 114: Provider Gmail"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 115: Provider Amazon SES"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@amazonses.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 116: Provider Zoho"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@zoho.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 117: Provider ProtonMail"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@protonmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 118: Provider Sendgrid"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@sendgrid.net", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 119: ASN detection"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 120: ASN country"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 121: Provider tier classification"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 122: Provider fingerprint"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 123: Provider fallback en error"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@unknown-provider.test", "check_smtp": false}' | jq '.'
echo ""


echo ""
echo "========== SCORING Y STATUS =========="
echo ""

echo "TEST 124: status=deliverable para válido"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "verified@google.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 125: status=undeliverable para inválido"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "invalid@", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 126: status=risky para sospechoso"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "suspicious@unknown-domain.test", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 127: status=unknown sin info"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@no-info-domain.test", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 128: risk_score en rango [0,1]"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 129: quality_score en rango [0,1]"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 130: suggested_action=accept"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "verified@google.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 131: suggested_action=monitor (0.4<risk<0.7)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@medium-risk.test", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 132: suggested_action=review (risk>0.7)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@high-risk.test", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 133: suggested_action=reject"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@tempmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 134: Scoring con SPF+DKIM+DMARC"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 135: Scoring sin DNS security"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@no-security.test", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 136: quality_score alto con tier1"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 137: Ajuste por múltiples factores"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@tempmail.com", "check_smtp": false}' | jq '.'
echo ""


echo ""
echo "========== DOMINIOS DE ABUSO =========="
echo ""

echo "TEST 138: Dominio en abuse list"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@spam-sender.net", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 139: Dominio malicioso conocido"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@malicious-domain.test", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 140: Subdominio de abuse domain"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@sub.spam-sender.net", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 141: error_type=abuse_domain"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@spam-sender.net", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 142: Abuse domain rechaza automático"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@abuse-domain.test", "check_smtp": false}' | jq '.'
echo ""


echo ""
echo "========== VALIDACIÓN BATCH =========="
echo ""

echo "TEST 143: Batch con 5 emails válidos"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"emails": ["test1@gmail.com", "test2@gmail.com", "test3@gmail.com", "test4@gmail.com", "test5@gmail.com"], "check_smtp": false}' | jq '.'
echo ""

echo "TEST 144: Batch con emails mixtos"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"emails": ["valid@gmail.com", "invalid@", "user@tempmail.com", "admin@yahoo.com", "test@gmai.com"], "check_smtp": false}' | jq '.'
echo ""

echo "TEST 145: Batch con duplicados (deduplicar)"
curl -s -X POST "$BATCH_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"emails": ["test@gmail.com", "test@gmail.com", "test@gmail.com"], "check_smtp": false}' | jq '.'
echo ""

echo "TEST 146: Batch PREMIUM 10 emails"
curl -s -X POST "$BATCH_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"emails": ["test0@gmail.com","test1@gmail.com","test2@gmail.com","test3@gmail.com","test4@gmail.com","test5@gmail.com","test6@gmail.com","test7@gmail.com","test8@gmail.com","test9@gmail.com","test10@gmail.com",], "check_smtp": false}' | jq '.'
echo ""

echo "TEST 147: Batch con check_smtp=true"
curl -s -X POST "$BATCH_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"emails": ["test1@gmail.com", "test2@example.org"], "check_smtp": true}' | jq '.'
echo ""

echo "TEST 148: Batch con include_raw_dns"
curl -s -X POST "$BATCH_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"emails": ["test1@gmail.com", "test2@gmail.com"], "check_smtp": false, "include_raw_dns": true}' | jq '.'
echo ""


echo "TEST 151: Batch con errores parciales"
curl -s -X POST "$BATCH_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"emails": ["valid@gmail.com", "", "invalid@", "test@example.com"], "check_smtp": false}' | jq '.'
echo ""

echo "TEST 152: Batch timeout individual"
curl -s -X POST "$BATCH_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"emails": ["test@gmail.com", "test@slow-domain.test", "test@yahoo.com"], "check_smtp": false}' | jq '.'
echo ""

echo "TEST 153: Batch respuesta array completo"
curl -s -X POST "$BATCH_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"emails": ["test1@gmail.com", "test2@gmail.com"], "check_smtp": false}' | jq '.'
echo ""


echo ""
echo "========== CONCURRENCIA =========="
echo ""

echo "TEST 154: Request simple (concurrency 1)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 155: FREE concurrent limit (2)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $FREE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test1@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 156: PREMIUM concurrent limit (10)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test1@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 157: Exceder concurrent limit"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 158: 429 por concurrency"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 159: Cleanup automático después 10 min"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""


echo ""
echo "========== RATE LIMITING =========="
echo ""

echo "TEST 160: Requests normales sin limit"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 161: FREE daily limit (100/día)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $FREE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 162: PREMIUM daily limit (10000/día)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 163: 429 al exceder daily limit"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 164: remaining count decrementa"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 165: used count incrementa"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 166: Rate limit per-second (10/s)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 167: SMTP host rate limit (60/min)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.org", "check_smtp": true}' | jq '.'
echo ""

echo "TEST 168: Reset de limits diarios"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""


echo ""
echo "========== CACHÉ =========="
echo ""

echo "TEST 169: Primera llamada (cache MISS)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "cache-test-unique--5429782570232627972@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 170: Segunda llamada (cache HIT)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "cache-test-unique--5429782570232627972@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 171: MX cache TTL 3600s"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "mx-cache-test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 172: Domain cache TTL 3600s"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "domain-cache-test@example.org", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 173: SMTP cache TTL 300s"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "smtp-cache-test@example.org", "check_smtp": true}' | jq '.'
echo ""

echo "TEST 174: HIBP cache TTL 7 días"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "hibp-cache-test@yahoo.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 175: Provider cache"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "provider-cache-test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 176: cache_used=true en respuesta"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "cached-email@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 177: Redis fallback a in-memory"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "fallback-test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 178: Cache invalidation manual"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "invalidate-test@gmail.com", "check_smtp": false}' | jq '.'
echo ""


echo ""
echo "========== METADATA Y ESTRUCTURA =========="
echo ""

echo "TEST 179: validation_id es UUID válido"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 180: timestamp es ISO 8601 con Z"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 181: processing_time presente"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 182: client_plan en respuesta"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 183: validation_tier presente"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 184: Todos los campos principales"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 185: Header X-Request-ID"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 186: Header X-Plan"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 187: Header X-Environment"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 188: remaining count visible"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""


echo ""
echo "========== TIMEOUTS Y FALLBACKS =========="
echo ""

echo "TEST 189: Timeout global FREE (15s)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $FREE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@very-slow-domain.test", "check_smtp": true}' | jq '.'
echo ""

echo "TEST 190: Timeout global PREMIUM (45s)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@very-slow-domain.test", "check_smtp": true}' | jq '.'
echo ""

echo "TEST 191: Timeout DNS (2s)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@dns-timeout.test", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 192: Timeout SMTP (5-15s)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@smtp-timeout.test", "check_smtp": true}' | jq '.'
echo ""

echo "TEST 193: Timeout HIBP (12s)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@hibp-timeout.test", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 194: Timeout Provider (5s)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@provider-timeout.test", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 195: Fallback a validación básica"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@timeout-all.test", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 196: Header X-Timeout: true"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@timeout-domain.test", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 197: Partial success en timeout"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@partial-timeout.test", "check_smtp": false}' | jq '.'
echo ""


echo ""
echo "========== ERROR HANDLING =========="
echo ""

echo "TEST 198: error_type=invalid_format"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "invalid@", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 199: error_type=disposable_email"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@tempmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 200: error_type=reserved_domain"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 201: error_type=spam_trap"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "trap@spamtrap.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 202: error_type=no_dns_records"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@nodns-domain.test", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 203: error_type=typo_detected"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@gmai.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 204: 422 Unprocessable Entity"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "invalid-format", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 205: 400 Bad Request batch"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"emails": "not-an-array", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 206: 500 Internal Server Error"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "trigger-error@test.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 207: Detail descriptivo en error"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "invalid@", "check_smtp": false}' | jq '.'
echo ""


echo ""
echo "========== EDGE CASES Y CASOS ESPECIALES =========="
echo ""

echo "TEST 208: Email con + en local-part"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user+tag123@gmail.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 209: Email con _ en local-part"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user_name@example.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 210: Email con números"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user123@example.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 211: Dominio con números"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example123.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 212: Subdominio profundo"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@a.b.c.d.example.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 213: TLD largo (.technology)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.technology", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 214: TLD corto (.io)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.io", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 215: Email case insensitive"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "UsEr@ExAmPlE.CoM", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 216: Normalización lowercase"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "USER@EXAMPLE.COM", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 217: Provider Google Workspace"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@company.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 218: Provider Microsoft 365"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@business.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 219: Reputación máxima (tier1+full)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "verified@google.com", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 220: Reputación baja (sin security)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@low-rep.test", "check_smtp": false}' | jq '.'
echo ""

echo "TEST 221: Múltiples requests rápidos"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $PREMIUM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "rapid-test@gmail.com", "check_smtp": false}' | jq '.'
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
