FROM node:16-alpine as base
#FROM --platform=linux/amd64 node:16-alpine as base
#FROM --platform=linux/arm64 node:16-alpine as base

WORKDIR /app

#### TRANSPILATION STAGE
FROM base as build

RUN apk add python3 make g++

COPY ["./package.json", "yarn.lock", "./"]
RUN yarn

COPY . .
RUN yarn build

#### PRODUCTION DEPENDENCIES INSTALLATION STAGE
FROM base as dependencies-prod

RUN apk add python3 make g++

COPY --from=build /usr/local/share/.cache/yarn/v6 /usr/local/share/.cache/yarn/v6
COPY ["./package.json", "yarn.lock", "./"]
RUN yarn install --production=true

#### FINAL IMAGE CREATION STAGE
FROM base as final

ENV NODE_ENV=production
ENV BIND=0.0.0.0

COPY --from=dependencies-prod /app/node_modules ./node_modules
COPY --from=build /app/dist ./

EXPOSE 3000

CMD ["node", "main.js"]
