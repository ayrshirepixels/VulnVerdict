# The TLS proxy for the Compose stack and the appliance: Caddy built from source by the current Go release with its
# dependencies raised to their latest releases, on plain Alpine. The official Caddy image can lag behind Go and
# dependency security releases (in September 2026 it carried one critical and fourteen high findings).
ARG CADDY_VERSION=v2.11.4
FROM golang:1.26-alpine AS build
ARG CADDY_VERSION
COPY caddy-build.sh /usr/local/bin/caddy-build
RUN sh /usr/local/bin/caddy-build "${CADDY_VERSION}" /caddy

FROM alpine:3
RUN apk add --no-cache ca-certificates mailcap \
    && mkdir -p /config/caddy /data/caddy /etc/caddy /srv
COPY --from=build /caddy /usr/bin/caddy
ENV XDG_CONFIG_HOME=/config XDG_DATA_HOME=/data
VOLUME /config /data
EXPOSE 80 443 443/udp
WORKDIR /srv
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
LABEL org.opencontainers.image.description="VulnVerdict TLS proxy: Caddy built with the current Go release and dependencies"
