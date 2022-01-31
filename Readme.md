## Prerequisites
- nodejs
- yarn
- docker
- docker compose
- jq (https://stedolan.github.io/jq/download/)

## Installation
```shell
yarn install
```

## Start
```shell
docker-compose up --build
```

## Test

```shell
export IDENTITY_TOKEN=$(node generate-identity-cli/index.js -p $PRIVATE_KEY -b 999999999999)
```

```shell
export ACCESS_TOKEN=$(curl "http://localhost:8080/login" \
  -Ssf \
  -X POST --header 'Content-Type: application/json' \
  -d "{\"identityToken\": \"$IDENTITY_TOKEN\"}" \
  | jq -r .accessToken) 
```
Request an endpoint with valid token:
```shell
curl -v http://127.0.0.1:8080/ -H "Authorization: Bearer $ACCESS_TOKEN"
```
You should see token validated successfully by auth-server and then request forwarded to the backend:
```text
nginx-auth-poc-auth-server-1  | {"url":"/token-introspection","headers":{"authorization":"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkaWQiOiJkaWQ6ZXRocjoweDgyRmNCMzEzODVFYUJlMjYxRTRlNjAwM2I5RjJDYjJhZjM0ZTI2NTQiLCJ2ZXJpZmllZFJvbGVzIjpbeyJuYW1lIjoicm9sZTEiLCJuYW1lc3BhY2UiOiJyb2xlMS5yb2xlcy5hcHAtdGVzdDIuYXBwcy5hcnR1ci5pYW0uZXdjIn1dLCJpYXQiOjE2NDMyMzM4MjB9.lyKwCib128oOFA8aVsqZ-sOm9gXZTKK9zn4xHHdT8N8","host":"auth-server","connection":"close","user-agent":"curl/7.81.0","accept":"*/*"},"method":"GET","body":{}}
nginx-auth-poc-backend-1      | {"url":"/","headers":{"host":"backend","connection":"close","user-agent":"curl/7.81.0","accept":"*/*","authorization":"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkaWQiOiJkaWQ6ZXRocjoweDgyRmNCMzEzODVFYUJlMjYxRTRlNjAwM2I5RjJDYjJhZjM0ZTI2NTQiLCJ2ZXJpZmllZFJvbGVzIjpbeyJuYW1lIjoicm9sZTEiLCJuYW1lc3BhY2UiOiJyb2xlMS5yb2xlcy5hcHAtdGVzdDIuYXBwcy5hcnR1ci5pYW0uZXdjIn1dLCJpYXQiOjE2NDMyMzM4MjB9.lyKwCib128oOFA8aVsqZ-sOm9gXZTKK9zn4xHHdT8N8"},"method":"GET","body":{}}
nginx-auth-poc-webserver-1    | 172.25.0.1 - - [26/Jan/2022:22:16:16 +0000] "GET / HTTP/1.1" 200 69 "-" "curl/7.81.0" "-"
nginx-auth-poc-webserver-1    | 2022/01/26 22:16:16 [info] 25#25: *18 client 172.25.0.1 closed keepalive connection
```
Request an endpoint with invalid token:
```shell
curl -v http://127.0.0.1:8080/ -H "Authorization: Bearer invalid-token"
```
You should see token rejected by auth-server and request not forwarded to the backend:
```text
nginx-auth-poc-auth-server-1  | {"url":"/token-introspection","headers":{"authorization":"Bearer invalid-token","host":"auth-server","connection":"close","user-agent":"curl/7.81.0","accept":"*/*"},"method":"GET","body":{}}
nginx-auth-poc-webserver-1    | 172.25.0.1 - - [26/Jan/2022:22:16:52 +0000] "GET / HTTP/1.1" 401 179 "-" "curl/7.81.0" "-"
nginx-auth-poc-webserver-1    | 2022/01/26 22:16:52 [info] 25#25: *21 client 172.25.0.1 closed keepalive connection
```
