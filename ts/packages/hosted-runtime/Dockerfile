# syntax=docker/dockerfile:1.7

# AgentCore Runtime requires Linux ARM64 images.
ARG TARGETPLATFORM=linux/arm64
FROM --platform=${TARGETPLATFORM} node:22-bookworm-slim AS build

WORKDIR /opt/threatforest/ts

COPY ts/package.json ts/package-lock.json ts/tsconfig.base.json ./
COPY ts/packages/types/package.json packages/types/package.json
COPY ts/packages/control-plane/package.json packages/control-plane/package.json
COPY ts/packages/engine/package.json packages/engine/package.json
COPY ts/packages/hosted-runtime/package.json packages/hosted-runtime/package.json

RUN npm ci --ignore-scripts

COPY ts/packages/types packages/types
COPY ts/packages/control-plane packages/control-plane
COPY ts/packages/engine packages/engine
COPY ts/packages/hosted-runtime packages/hosted-runtime

RUN mkdir -p node_modules/@threatforest \
    && ln -sfn ../../packages/types node_modules/@threatforest/types \
    && ln -sfn ../../packages/control-plane node_modules/@threatforest/control-plane \
    && ln -sfn ../../packages/engine node_modules/@threatforest/engine \
    && ln -sfn ../../packages/hosted-runtime node_modules/@threatforest/hosted-runtime \
    && ./node_modules/.bin/tsc -b --force packages/types \
    && ./node_modules/.bin/tsc -b --force packages/control-plane packages/engine packages/hosted-runtime \
    && ./node_modules/.bin/esbuild packages/hosted-runtime/src/entrypoint.ts \
      --bundle \
      --external:@opentelemetry/api \
      --format=cjs \
      --outfile=packages/hosted-runtime/dist/runtime.cjs \
      --platform=node \
      --sourcemap \
      --target=node22 \
    && npm prune --omit=dev \
    && test -e packages/hosted-runtime/dist/runtime.cjs \
    && test -e node_modules/@threatforest/types/dist/index.js \
    && test -e node_modules/@threatforest/control-plane/dist/src/index.js \
    && test -e node_modules/@threatforest/engine/dist/index.js

FROM --platform=${TARGETPLATFORM} node:22-bookworm-slim AS runtime

ENV NODE_ENV=production \
    NODE_OPTIONS=--enable-source-maps \
    HOST=0.0.0.0 \
    PORT=8080 \
    THREATFOREST_WORKSPACE_ROOT=/tmp/threatforest

WORKDIR /opt/threatforest/ts
COPY --from=build --chown=node:node /opt/threatforest/ts ./

RUN mkdir -p /tmp/threatforest && chown node:node /tmp/threatforest

USER node
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8080/ping').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]

CMD ["node", "--require", "@aws/aws-distro-opentelemetry-node-autoinstrumentation/register", "packages/hosted-runtime/dist/runtime.cjs"]
