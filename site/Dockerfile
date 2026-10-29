# Production image of the website: build with Node, serve the static files with nginx.
#
#   docker build --build-arg SITE_URL=https://www.meine-domain.de -t funkenschlag ./site
#   docker run --rm -p 8080:8080 funkenschlag
#
# CHECK_LIVE=1 (set by the CI for the release image) makes placeholders such as
# [Vorname Nachname] or example.org a build error, so an incomplete Impressum never ships.

FROM node:26.13-alpine AS build
WORKDIR /app
# No Git hooks inside the image.
ENV LEFTHOOK=0
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
ARG SITE_URL
ARG BASE_PATH=/
ARG CHECK_LIVE=0
ENV SITE_URL=$SITE_URL BASE_PATH=$BASE_PATH CHECK_LIVE=$CHECK_LIVE
RUN npx astro build && node scripts/check-site.mjs

FROM nginxinc/nginx-unprivileged:1.30-alpine-slim
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
