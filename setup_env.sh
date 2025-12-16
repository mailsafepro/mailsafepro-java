#!/bin/bash

# ================================================================
# SETUP DE ENTORNO - EMAIL VALIDATION API
# Compatible con macOS y Linux
# ================================================================

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Credenciales
USER_EMAIL="pabloagudo01@yahoo.com"
USER_PASSWORD="DiePabl9.-"
RENDER_BASE_URL="https://email-validation-api-jlra.onrender.com"

# ================================================================
# FUNCIONES
# ================================================================

print_header() {
    echo -e "\n${CYAN}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════${NC}\n"
}

print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }

# ================================================================
# 1. DETECTAR ENTORNO
# ================================================================

print_header "DETECCIÓN DE ENTORNO"

if docker ps &>/dev/null && docker ps --format '{{.Names}}' | grep -q "api"; then
    ENVIRONMENT="docker"
    BASE_URL="http://localhost:8000"
    print_success "Docker local activo"
else
    ENVIRONMENT="render"
    BASE_URL="$RENDER_BASE_URL"
    print_warning "Usando Render Cloud"
fi

export ENVIRONMENT BASE_URL
export API_URL="${BASE_URL}/validate/email"
export BATCH_URL="${BASE_URL}/validate/batch"
export AUTH_URL="${BASE_URL}/auth/login"
export REGISTER_URL="${BASE_URL}/auth/register"
export HEALTH_URL="${BASE_URL}/health"

print_success "URLs configuradas"
echo -e "   ${CYAN}Entorno:${NC}  $ENVIRONMENT"
echo -e "   ${CYAN}Base URL:${NC} $BASE_URL"

# ================================================================
# 2. HEALTH CHECK
# ================================================================

print_header "HEALTH CHECK"

HEALTH=$(curl -s "$HEALTH_URL" 2>/dev/null || echo '{"status":"error"}')
STATUS=$(echo "$HEALTH" | jq -r '.status // "error"')

if [ "$STATUS" == "healthy" ] || [ "$STATUS" == "running" ]; then
    print_success "API respondiendo correctamente"
else
    print_error "API no responde"
    exit 1
fi

# ================================================================
# 3. AUTENTICACIÓN
# ================================================================

print_header "AUTENTICACIÓN"

print_info "Intentando login..."

LOGIN_RESP=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$AUTH_URL" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$USER_EMAIL\",\"password\":\"$USER_PASSWORD\"}" 2>/dev/null)

LOGIN_CODE=$(echo "$LOGIN_RESP" | grep "HTTP_CODE:" | cut -d':' -f2)
LOGIN_BODY=$(echo "$LOGIN_RESP" | sed '/HTTP_CODE:/d')

if [ "$LOGIN_CODE" == "200" ]; then
    print_success "Login exitoso"
    ACCESS_TOKEN=$(echo "$LOGIN_BODY" | jq -r '.access_token // .token')
    
elif [ "$LOGIN_CODE" == "401" ]; then
    print_warning "Usuario no existe, registrando..."
    
    REG_RESP=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$REGISTER_URL" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$USER_EMAIL\",\"password\":\"$USER_PASSWORD\"}" 2>/dev/null)
    
    REG_CODE=$(echo "$REG_RESP" | grep "HTTP_CODE:" | cut -d':' -f2)
    REG_BODY=$(echo "$REG_RESP" | sed '/HTTP_CODE:/d')
    
    if [ "$REG_CODE" == "201" ] || [ "$REG_CODE" == "200" ]; then
        print_success "Usuario registrado"
        
        sleep 1
        
        LOGIN_RESP=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$AUTH_URL" \
            -H "Content-Type: application/json" \
            -d "{\"email\":\"$USER_EMAIL\",\"password\":\"$USER_PASSWORD\"}" 2>/dev/null)
        
        LOGIN_CODE=$(echo "$LOGIN_RESP" | grep "HTTP_CODE:" | cut -d':' -f2)
        LOGIN_BODY=$(echo "$LOGIN_RESP" | sed '/HTTP_CODE:/d')
        
        if [ "$LOGIN_CODE" == "200" ]; then
            print_success "Login exitoso"
            ACCESS_TOKEN=$(echo "$LOGIN_BODY" | jq -r '.access_token // .token')
        else
            print_error "Login falló después del registro"
            exit 1
        fi
    else
        print_error "Registro falló (HTTP $REG_CODE)"
        echo "$REG_BODY" | jq '.'
        exit 1
    fi
else
    print_error "Login falló (HTTP $LOGIN_CODE)"
    echo "$LOGIN_BODY" | jq '.'
    exit 1
fi

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" == "null" ]; then
    print_error "No se pudo obtener token"
    exit 1
fi

export ACCESS_TOKEN

print_success "Token: ${ACCESS_TOKEN:0:30}..."

# ================================================================
# 4. INFO DEL TOKEN
# ================================================================

print_header "INFORMACIÓN DEL TOKEN"

TOKEN_PAYLOAD=$(echo "$ACCESS_TOKEN" | cut -d'.' -f2)
while [ $((${#TOKEN_PAYLOAD} % 4)) -ne 0 ]; do
    TOKEN_PAYLOAD="${TOKEN_PAYLOAD}="
done

TOKEN_INFO=$(echo "$TOKEN_PAYLOAD" | base64 -d 2>/dev/null)

if [ -n "$TOKEN_INFO" ]; then
    EMAIL=$(echo "$TOKEN_INFO" | jq -r '.email // "N/A"')
    PLAN=$(echo "$TOKEN_INFO" | jq -r '.plan // "FREE"')
    EXP=$(echo "$TOKEN_INFO" | jq -r '.exp // 0')
    
    echo -e "   ${CYAN}Email:${NC} $EMAIL"
    echo -e "   ${CYAN}Plan:${NC}  $PLAN"
    
    if [ "$EXP" != "0" ] && [ "$EXP" != "null" ]; then
        NOW=$(date +%s)
        TIME_LEFT=$((EXP - NOW))
        
        if [ $TIME_LEFT -lt 0 ]; then
            print_error "Token EXPIRADO"
            exit 1
        else
            MINUTES=$((TIME_LEFT / 60))
            print_success "Token válido por $MINUTES minutos"
        fi
    fi
fi

# ================================================================
# 5. TEST DE VALIDACIÓN
# ================================================================

print_header "TEST DE VALIDACIÓN"

print_info "Validando: test@gmail.com"

TEST_RESP=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$API_URL" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"email": "test@gmail.com", "check_smtp": false}' 2>/dev/null)

TEST_CODE=$(echo "$TEST_RESP" | grep "HTTP_CODE:" | cut -d':' -f2)
TEST_BODY=$(echo "$TEST_RESP" | sed '/HTTP_CODE:/d')

if [ "$TEST_CODE" == "200" ]; then
    print_success "Validación exitosa"
    
    STATUS=$(echo "$TEST_BODY" | jq -r '.status // "unknown"')
    VALID=$(echo "$TEST_BODY" | jq -r '.valid // false')
    TIME=$(echo "$TEST_BODY" | jq -r '.processing_time // 0')
    SPF=$(echo "$TEST_BODY" | jq -r '.dns_security.spf.status // "not_found"')
    DMARC=$(echo "$TEST_BODY" | jq -r '.dns_security.dmarc.status // "not_found"')
    RISK=$(echo "$TEST_BODY" | jq -r '.risk_score // 0')
    
    echo -e "\n   ${CYAN}Resultados:${NC}"
    echo -e "   ├─ Status:  $STATUS"
    echo -e "   ├─ Valid:   $VALID"
    echo -e "   ├─ Time:    ${TIME}s"
    echo -e "   ├─ SPF:     $SPF"
    echo -e "   ├─ DMARC:   $DMARC"
    echo -e "   └─ Risk:    $RISK"
    
    if [ "$STATUS" == "deliverable" ] && [ "$SPF" == "valid" ]; then
        print_success "✨ ¡Todo funciona perfectamente!"
    elif [ "$STATUS" == "deliverable" ]; then
        print_success "Validación básica OK"
    else
        print_warning "Status: $STATUS"
    fi
else
    print_error "Validación falló (HTTP $TEST_CODE)"
    echo "$TEST_BODY" | jq '.'
fi

# ================================================================
# 6. RESUMEN
# ================================================================

print_header "RESUMEN"

print_success "Configuración completa"
echo ""
print_info "Variables exportadas:"
echo "  • ENVIRONMENT:  $ENVIRONMENT"
echo "  • BASE_URL:     $BASE_URL"
echo "  • API_URL:      $API_URL"
echo "  • ACCESS_TOKEN: ${ACCESS_TOKEN:0:20}..."
echo ""
print_warning "Test rápido:"
echo '  curl -s -X POST "$API_URL" \'
echo '    -H "Authorization: Bearer $ACCESS_TOKEN" \'
echo '    -H "Content-Type: application/json" \'
echo '    -d '"'"'{"email": "user@example.com"}'"'"' | jq '"'"'.'"'"
echo ""
print_success "Listo para tests 🚀"
echo ""

