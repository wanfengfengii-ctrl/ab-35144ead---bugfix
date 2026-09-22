# Production image for the telemetry service. One image is used for the API
# instances, the background worker and the one-shot `verify` service; the
# process role is selected with the container command.

FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
# Only runtime dependencies (the devDependency embedded-postgres is used by the
# host-side test suite and must never ship in the image).
RUN npm ci --omit=dev --no-audit --no-fund

FROM node:22-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app
RUN apk add --no-cache wget \
  && addgroup -S app && adduser -S app -G app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./package.json
COPY migrations ./migrations
COPY src ./src
COPY verify ./verify
COPY examples ./examples
USER app
EXPOSE 8080
CMD ["node", "src/bin/api.js"]
