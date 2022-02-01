#### PRODUCTION DEPENDENCIES INSTALLATION STAGE
FROM node:lts-alpine as dependencies
WORKDIR /app

ENV NODE_ENV=production

COPY ["./package.json", "yarn.lock", "./"]
RUN yarn install --production=true

#### TRANSPILATION STAGE
FROM node:lts-alpine as build

WORKDIR /app

COPY --from=dependencies /app/node_modules /app/node_modules

COPY --from=dependencies /app/package.json /app/
COPY --from=dependencies /app/yarn.lock /app/
RUN yarn

COPY . .
RUN yarn build

#### FINAL IMAGE CREATION STAGE
FROM node:lts-alpine as final
WORKDIR /app

ENV NODE_ENV=production
ENV BIND=0.0.0.0

COPY --from=dependencies /app/node_modules ./node_modules
COPY --from=build /app/dist ./

EXPOSE 3000

CMD ["node", "main.js"]
