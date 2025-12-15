#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

API_URL="http://localhost:8000/validate/email"
JWT_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxZGFjZDUwYS0yZWVlLTRlNWUtYTZhZC1jZmEyNGNiM2RiZGMiLCJlbWFpbCI6InBhYmxvYWd1ZG8wMUB5YWhvby5jb20iLCJleHAiOjE3NjU4MjM3NDksImlhdCI6MTc2NTgyMjg0OSwibmJmIjoxNzY1ODIyODQ5LCJqdGkiOiI4ZjVmNzgwZS1hYzA1LTRkNTgtODllOS1iMjBiY2FmNmZjYWMiLCJpc3MiOiJlbWFpbC1hcGkiLCJhdWQiOiJlbWFpbC1jbGllbnRzIiwic2NvcGVzIjpbInZhbGlkYXRlOnNpbmdsZSIsImJpbGxpbmciXSwicGxhbiI6IkZSRUUiLCJ0eXBlIjoiYWNjZXNzIn0.apS3oF-GcfP5Uj7JYPKaYtoouo1sCixxDiUBC4hIbJY"

PASSED=0
FAILED=0

test_email() {
    local email=$1
    local expected_status=$2
    local expected_status_field=$3
    local expected_error_type=$4
    local description=$5
    
    echo -n "Testing $description ($email): "
    
    full_response=$(curl -s -w "\n%{http_code}" \
        -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $JWT_TOKEN" \
        -d "{\"email\":\"$email\", \"testing_mode\": true}" \
        "$API_URL")
    
    http_status=$(echo "$full_response" | tail -n1)
    json_body=$(echo "$full_response" | sed '$d')
    
    if [ "$http_status" -ne "$expected_status" ]; then
        echo -e "${RED}✗ FAIL${NC} (HTTP: expected $expected_status, got $http_status)"
        echo -e "${YELLOW}Response:${NC} $json_body"
        FAILED=$((FAILED + 1))
        return 1
    fi
    
    local validation_passed=true
    local validation_error=""
    
    if [ -n "$expected_status_field" ]; then
        local actual_status=$(echo "$json_body" | jq -r '.status // ""')
        if [ "$actual_status" != "$expected_status_field" ]; then
            validation_passed=false
            validation_error+="status: expected '$expected_status_field', got '$actual_status' | "
        fi
    fi
    
    if [ -n "$expected_error_type" ]; then
        local actual_error_type=$(echo "$json_body" | jq -r '.error_type // ""')
        if [ "$actual_error_type" != "$expected_error_type" ]; then
            validation_passed=false
            validation_error+="error_type: expected '$expected_error_type', got '$actual_error_type' | "
        fi
    fi
    
    if [ "$validation_passed" = true ]; then
        echo -e "${GREEN}✓ PASS${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}✗ FAIL${NC} (${validation_error% | })"
        echo -e "${YELLOW}Response:${NC} $json_body"
        FAILED=$((FAILED + 1))
    fi
}

echo "Waiting for API to be ready..."
max_attempts=30
attempt=0
until curl -s -f -X GET "http://localhost:8000/health" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ $attempt -ge $max_attempts ]; then
        echo -e "${RED}API did not become ready in time!${NC}"
        exit 1
    fi
    sleep 2
done
echo -e "${GREEN}API is ready!${NC}\n"

echo "========================================"
echo "Email Validation Tests (Final)"
echo "========================================"
echo ""

# ✅ Tests con expectativas corregidas

# Test 1: Email con usuario no-role (john.doe@ no es role)
test_email "john.doe@valid.test.lab" 200 "deliverable" "" "Valid domain with MX, SPF, DKIM, DMARC (non-role user)"

# Test 2: Sin MX pero con A record (error_type esperado)
test_email "john.doe@nomx.test.lab" 200 "risky" "no_mx_has_a" "Domain without MX (A record fallback)"

# Test 3: MX apunta a localhost (error_type esperado)
test_email "john.doe@localhost-mx.test.lab" 200 "undeliverable" "unsafe_mx_host" "MX pointing to localhost"

# Test 4-7: DNS security débil (NO son error_types)
test_email "john.doe@badspf.test.lab" 200 "deliverable" "" "Domain with weak SPF (affects quality)"
test_email "john.doe@nodmarc.test.lab" 200 "deliverable" "" "Domain without DMARC (affects quality)"
test_email "john.doe@baddkim.test.lab" 200 "deliverable" "" "Domain with bad DKIM (affects quality)"
test_email "john.doe@dmarcreport.test.lab" 200 "deliverable" "" "Domain with DMARC policy=none"

# Test 8: Role email admin@ (status=risky es correcto)
test_email "admin@valid.test.lab" 200 "risky" "" "Role email (admin@) - status risky expected"

# Test 9: Role email test@ (status=risky es correcto)
test_email "test@valid.test.lab" 200 "risky" "" "Role email (test@) - status risky expected"

# Test 10: Formato inválido (422)
test_email "not-an-email" 422 "" "" "Invalid email format"

echo ""
echo "========================================"
echo "Tests completed!"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo "========================================"

if [ $FAILED -gt 0 ]; then
    exit 1
fi
exit 0
