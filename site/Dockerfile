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

# Official nginx image: it gets security releases promptly (nginx-unprivileged was not
# rebuilt for weeks, see #33). Run it like nginx-unprivileged does: as user nginx (101),
# port 8080 (docker/nginx.conf), pid and temp files in /tmp so the root filesystem can
# stay read-only. apk upgrade picks up Alpine fixes published after the base image.
FROM nginx:1.30-alpine-slim
RUN apk upgrade --no-cache \
 && sed -i -e '/^user /d' -e 's,^pid .*,pid /tmp/nginx.pid;,' /etc/nginx/nginx.conf \
 && sed -i '/^http {/a\    client_body_temp_path /tmp/client_temp;\n    proxy_temp_path /tmp/proxy_temp;\n    fastcgi_temp_path /tmp/fastcgi_temp;\n    uwsgi_temp_path /tmp/uwsgi_temp;\n    scgi_temp_path /tmp/scgi_temp;' /etc/nginx/nginx.conf
USER 101
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
