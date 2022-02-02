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
export ACCESS_TOKEN=$(curl "http://localhost:8080/auth/login" \
  -Ssf \
  -X POST --header 'Content-Type: application/json' \
  -d "{\"identityToken\": \"$IDENTITY_TOKEN\"}" \
  | jq -r .access_token) 
```

You should see in docker logs request forwarded to the autorization service and access token generated:

```text
did-auth-proxy-poc-auth-server-1  | [Nest] 1  - 02/02/2022, 7:11:03 PM   DEBUG [webserver] connection from ::ffff:192.168.0.4:55342 +92812ms
did-auth-proxy-poc-auth-server-1  | [Nest] 1  - 02/02/2022, 7:11:07 PM   DEBUG [AuthController] user has been logged in +3872ms
did-auth-proxy-poc-auth-server-1  | [Nest] 1  - 02/02/2022, 7:11:07 PM   DEBUG [AuthController] identity token received: eyJhbGciOiJFUzI1NiIs**********************************************************************************************************************************************************************************************************************************************************************************************************************MjczYzVlMmRiMzE3ODFj +0ms
did-auth-proxy-poc-auth-server-1  | [Nest] 1  - 02/02/2022, 7:11:07 PM   DEBUG [AuthController] identity token content: {"iss":"did:ethr:0x82FcB31385EaBe261E4e6003b9F2Cb2af34e2654","claimData":{"blockNumber":999999999999}} +1ms
did-auth-proxy-poc-auth-server-1  | [Nest] 1  - 02/02/2022, 7:11:07 PM   DEBUG [AuthController] access token generated: eyJhbGciOiJIUzI1NiIs*************************************************************************************************************************************************************************************************************************************************************************faU7sFfMl3HSLAD8UsqE +1ms
did-auth-proxy-poc-auth-server-1  | [Nest] 1  - 02/02/2022, 7:11:07 PM   DEBUG [AuthController] access token content: {"did":"did:ethr:0x82FcB31385EaBe261E4e6003b9F2Cb2af34e2654","verifiedRoles":[{"name":"role1","namespace":"role1.roles.app-test2.apps.artur.iam.ewc"}],"iat":1643829307} +1ms
did-auth-proxy-poc-webserver-1    | 192.168.0.1 - - [02/Feb/2022:19:15:07 +0000] "POST /auth/login HTTP/1.1" 201 379 "-" "curl/7.81.0" "-"
did-auth-proxy-poc-auth-server-1  | [Nest] 1  - 02/02/2022, 7:11:07 PM     LOG [HttpLoggerMiddleware] 201 | [POST] /auth/login - 3876ms +2ms
did-auth-proxy-poc-webserver-1    | 2022/02/02 19:15:07 [info] 24#24: *20 client 192.168.0.1 closed keepalive connection
did-auth-proxy-poc-auth-server-1  | [Nest] 1  - 02/02/2022, 7:11:07 PM   DEBUG [webserver] connection from ::ffff:192.168.0.4:55342 closed, 529 bytes read, 593 bytes written, 3879ms elapsed +2ms
```

Request an endpoint with valid token:
```shell
curl -v http://127.0.0.1:8080/ -H "Authorization: Bearer $ACCESS_TOKEN"
```
You should see token validated successfully by auth-server and then request forwarded to the backend:
```text
did-auth-proxy-poc-auth-server-1  | [Nest] 1  - 02/02/2022, 7:12:38 PM   DEBUG [webserver] connection from ::ffff:192.168.0.4:55332 +18195ms
did-auth-proxy-poc-auth-server-1  | [Nest] 1  - 02/02/2022, 7:12:38 PM   DEBUG [AuthController] successful access token introspection: {"did":"did:ethr:0x82FcB31385EaBe261E4e6003b9F2Cb2af34e2654","verifiedRoles":[{"name":"role1","namespace":"role1.roles.app-test2.apps.artur.iam.ewc"}],"iat":1643825467} +2ms
did-auth-proxy-poc-auth-server-1  | [Nest] 1  - 02/02/2022, 7:12:38 PM     LOG [HttpLoggerMiddleware] 200 | [GET] /auth/token-introspection - 2ms +1ms
did-auth-proxy-poc-backend-1      | incoming request: {"url":"/","headers":{"host":"backend","connection":"close","user-agent":"curl/7.81.0","accept":"*/*","authorization":"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkaWQiOiJkaWQ6ZXRocjoweDgyRmNCMzEzODVFYUJlMjYxRTRlNjAwM2I5RjJDYjJhZjM0ZTI2NTQiLCJ2ZXJpZmllZFJvbGVzIjpbeyJuYW1lIjoicm9sZTEiLCJuYW1lc3BhY2UiOiJyb2xlMS5yb2xlcy5hcHAtdGVzdDIuYXBwcy5hcnR1ci5pYW0uZXdjIn1dLCJpYXQiOjE2NDM4MjkxMTF9.WR1Vnq8MrLmWs_6sXP6iOg-Pv3UgXq425R64FBirnyE"},"method":"GET","body":{}}
did-auth-proxy-poc-webserver-1    | 192.168.0.1 - - [02/Feb/2022:19:12:38 +0000] "GET / HTTP/1.1" 200 69 "-" "curl/7.81.0" "-"
did-auth-proxy-poc-webserver-1    | 2022/02/02 19:12:38 [info] 24#24: *15 client 192.168.0.1 closed keepalive connection
did-auth-proxy-poc-auth-server-1  | [Nest] 1  - 02/02/2022, 7:12:38 PM   DEBUG [webserver] connection from ::ffff:192.168.0.4:55332 closed, 447 bytes read, 98 bytes written, 7ms elapsed +5ms
```
Request an endpoint with invalid token:
```shell
curl -v http://127.0.0.1:8080/ -H "Authorization: Bearer invalid-token"
```
You should see token rejected by auth-server and request not forwarded to the backend:
```text
did-auth-proxy-poc-auth-server-1  | [Nest] 1  - 02/02/2022, 7:13:31 PM   DEBUG [webserver] connection from ::ffff:192.168.0.4:55338 +52916ms
did-auth-proxy-poc-webserver-1    | 192.168.0.1 - - [02/Feb/2022:19:13:31 +0000] "GET / HTTP/1.1" 401 179 "-" "curl/7.81.0" "-"
did-auth-proxy-poc-auth-server-1  | [Nest] 1  - 02/02/2022, 7:13:31 PM    WARN [HttpLoggerMiddleware] 401 | [GET] /auth/token-introspection - 2ms +3ms
did-auth-proxy-poc-auth-server-1  | [Nest] 1  - 02/02/2022, 7:13:31 PM   DEBUG [webserver] connection from ::ffff:192.168.0.4:55338 closed, 155 bytes read, 260 bytes written, 3ms elapsed +1ms
did-auth-proxy-poc-webserver-1    | 2022/02/02 19:13:31 [info] 24#24: *18 client 192.168.0.1 closed keepalive connection
```
