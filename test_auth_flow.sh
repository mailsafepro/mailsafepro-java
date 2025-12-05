#!/bin/bash

BASE_URL="http://localhost:8000/auth"
EMAIL="pabloagudo01@yahoo.com"
PASSWORD="DiePabl9.-"

echo "---------------------------------------------------"
echo "🚀 Starting Authentication Flow Test"
echo "---------------------------------------------------"

# 1. Register
echo -e "\n1️⃣  Registering user..."
REGISTER_RESPONSE=$(curl -s -X POST "$BASE_URL/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$EMAIL\", \"password\": \"$PASSWORD\", \"plan\": \"FREE\"}")

echo "Response: $REGISTER_RESPONSE"

# Check if registration was successful or user already exists
if echo "$REGISTER_RESPONSE" | grep -q "User already exists"; then
  echo "⚠️  User already exists, proceeding to login..."
elif echo "$REGISTER_RESPONSE" | grep -q "access_token"; then
  echo "✅ Registration successful!"
else
  echo "❌ Registration failed!"
  exit 1
fi

# 2. Login
echo -e "\n2️⃣  Logging in..."
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$EMAIL\", \"password\": \"$PASSWORD\"}")

echo "Response: $LOGIN_RESPONSE"

ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token')
REFRESH_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.refresh_token')

if [ "$ACCESS_TOKEN" == "null" ]; then
  echo "❌ Login failed! No access token received."
  exit 1
fi

echo "✅ Login successful!"
echo "🔑 Access Token: ${ACCESS_TOKEN:0:20}..."

# 3. Get User Profile (Me)
echo -e "\n3️⃣  Getting User Profile (/me)..."
ME_RESPONSE=$(curl -s -X GET "$BASE_URL/me" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

echo "Response: $ME_RESPONSE"

if echo "$ME_RESPONSE" | grep -q "$EMAIL"; then
  echo "✅ /me endpoint verified!"
else
  echo "❌ /me endpoint failed!"
  exit 1
fi

# 4. Refresh Token
echo -e "\n4️⃣  Refreshing Token..."
REFRESH_RESPONSE=$(curl -s -X POST "$BASE_URL/refresh" \
  -H "Authorization: Bearer $REFRESH_TOKEN")

echo "Response: $REFRESH_RESPONSE"

NEW_ACCESS_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.access_token')

if [ "$NEW_ACCESS_TOKEN" != "null" ]; then
  echo "✅ Token refresh successful!"
  echo "🔑 New Access Token: ${NEW_ACCESS_TOKEN:0:20}..."
else
  echo "❌ Token refresh failed!"
  exit 1
fi

# 5. Logout
echo -e "\n5️⃣  Logging out..."
LOGOUT_RESPONSE=$(curl -s -X POST "$BASE_URL/logout" \
  -H "Authorization: Bearer $NEW_ACCESS_TOKEN")

echo "Response: $LOGOUT_RESPONSE"

if echo "$LOGOUT_RESPONSE" | grep -q "Successfully logged out"; then
  echo "✅ Logout successful!"
else
  echo "❌ Logout failed!"
  exit 1
fi

echo -e "\n---------------------------------------------------"
echo "🎉 All Authentication Tests Passed!"
echo "---------------------------------------------------"
