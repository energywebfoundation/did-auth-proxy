FROM node:24.21.0-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 as base

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

ARG GIT_SHA

ENV NODE_ENV=production
ENV BIND=0.0.0.0
ENV LOG_LEVEL=info

COPY --from=dependencies-prod /app/node_modules ./authorisation-server/node_modules
COPY --from=build /app/dist ./authorisation-server/

RUN echo "{\"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\", \"gitSha\": \"$GIT_SHA\"}" > build.json
COPY package.json .
EXPOSE 3000

CMD ["node", "authorisation-server/main.js"]
