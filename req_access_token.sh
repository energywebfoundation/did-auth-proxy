#!/usr/bin/bash

curl "http://localhost:3000/auth/login" \
  -Ssf \
  -X POST --header 'Content-Type: application/json' \
  -d "{\"identityToken\": \"$IDENTITY_TOKEN\"}" \
  | jq