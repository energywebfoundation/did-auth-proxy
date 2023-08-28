FROM node:18.17.1-alpine@sha256:3482a20c97e401b56ac50ba8920cc7b5b2022bfc6aa7d4e4c231755770cf892f as dependencies
WORKDIR /app

COPY ["./package.json", "./yarn.lock", "./"]

RUN yarn install

FROM node:16-alpine as final
WORKDIR /app

COPY --from=dependencies /app/node_modules ./node_modules
COPY . .

EXPOSE 80

CMD ["index.js"]
