FROM node:24.21.0-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 as dependencies
WORKDIR /app

COPY ["./package.json", "./yarn.lock", "./"]

RUN yarn install

FROM node:24.21.0-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 as final
WORKDIR /app

COPY --from=dependencies /app/node_modules ./node_modules
COPY . .

EXPOSE 80

CMD ["index.js"]
