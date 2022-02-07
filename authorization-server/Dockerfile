#### PRODUCTION DEPENDENCIES INSTALLATION STAGE
FROM node:16-alpine as dependencies
WORKDIR /app
RUN apk add python3 make g++

ENV NODE_ENV=production

COPY ["./package.json", "yarn.lock", "./"]
RUN yarn install --production=true

#### TRANSPILATION STAGE
FROM node:16-alpine as build

WORKDIR /app
RUN apk add python3 make g++

COPY --from=dependencies /app/node_modules /app/node_modules

COPY --from=dependencies /app/package.json /app/
COPY --from=dependencies /app/yarn.lock /app/
RUN yarn

COPY . .
RUN yarn build

#### FINAL IMAGE CREATION STAGE
FROM node:16-alpine as final
WORKDIR /app

ENV NODE_ENV=production
ENV BIND=0.0.0.0

COPY --from=dependencies /app/node_modules ./node_modules
COPY --from=build /app/dist ./

EXPOSE 3000

CMD ["node", "main.js"]
