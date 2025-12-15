export API_URL="http://localhost:8000/validate/email"
export BATCH_URL="http://localhost:8000/validate/batch"
#
# Nota: este token NO es premium: en el propio JWT aparece "plan":"FREE".
# Por eso se renombra para evitar confusiones en la suite.
export ACCESS_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxZGFjZDUwYS0yZWVlLTRlNWUtYTZhZC1jZmEyNGNiM2RiZGMiLCJlbWFpbCI6InBhYmxvYWd1ZG8wMUB5YWhvby5jb20iLCJleHAiOjE3NjU4MjYyMDgsImlhdCI6MTc2NTgyNTMwOCwibmJmIjoxNzY1ODI1MzA4LCJqdGkiOiI0NDc0MmJmYS02MmI5LTQxMjUtOTJhNi02YmZhYTgxYTMxMTMiLCJpc3MiOiJlbWFpbC1hcGkiLCJhdWQiOiJlbWFpbC1jbGllbnRzIiwic2NvcGVzIjpbInZhbGlkYXRlOnNpbmdsZSIsImJpbGxpbmciXSwicGxhbiI6IkZSRUUiLCJ0eXBlIjoiYWNjZXNzIn0.KWenf5T8tUMt6k5ZtOvFl8Ts-0UEoy6niDUhYs-FzgM"

echo "TEST 4: Token válido (plan FREE)"
curl -s -X POST "$API_URL" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@gmail.com", "check_smtp": false}' | jq '.'
echo ""