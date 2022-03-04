#### TRANSPILATION STAGE
FROM node:16-alpine as build
WORKDIR /app
RUN apk add python3 make g++

COPY ["./package.json", "yarn.lock", "./"]
RUN yarn

COPY . .
RUN yarn build

#### PRODUCTION DEPENDENCIES INSTALLATION STAGE
FROM node:16-alpine as dependencies-prod
WORKDIR /app
RUN apk add python3 make g++

COPY --from=build /usr/local/share/.cache/yarn/v6 /usr/local/share/.cache/yarn/v6
COPY ["./package.json", "yarn.lock", "./"]
RUN yarn install --production=true

#### FINAL IMAGE CREATION STAGE
FROM node:16-alpine as final
WORKDIR /app

ENV NODE_ENV=production
ENV BIND=0.0.0.0

COPY --from=dependencies-prod /app/node_modules ./node_modules
COPY --from=build /app/dist ./

EXPOSE 3000

CMD ["node", "main.js"]
