SERVER="http://192.168.192.1:12321"
API_KEY="changeme"

ACCESS="eyJhbG....."
REFRESH="eyJhbG....."


curl -X POST "${SERVER}/set_tokens" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -d "{ \"access\": \"${ACCESS}\", \"refresh\": \"${REFRESH}\" }"
