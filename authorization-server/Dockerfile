FROM node:16-alpine as build

RUN apk add python3 make g++

WORKDIR /app
COPY ["package.json", "yarn.lock", "./"]

RUN yarn

FROM node:16-alpine

WORKDIR /app

COPY --from=build /app/node_modules ./node_modules

COPY . .

CMD index.js
