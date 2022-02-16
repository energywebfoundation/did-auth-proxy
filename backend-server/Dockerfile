FROM node:16-alpine as dependencies
WORKDIR /app

COPY ["./package.json", "./yarn.lock", "./"]

RUN yarn install

FROM node:16-alpine as final
WORKDIR /app

COPY --from=dependencies /app/node_modules ./node_modules
COPY . .

EXPOSE 80

CMD ["index.js"]
