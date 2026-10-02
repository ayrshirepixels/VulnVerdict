# VulnVerdict: single image, runs as "web", "worker" or "all" depending on the Role setting.
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY VulnVerdict.slnx ./
COPY src/VulnVerdict.Core/VulnVerdict.Core.csproj src/VulnVerdict.Core/
COPY src/VulnVerdict.Web/VulnVerdict.Web.csproj src/VulnVerdict.Web/
RUN dotnet restore src/VulnVerdict.Web/VulnVerdict.Web.csproj
COPY src/ src/
# Publish restores again on purpose: the SDK only adds the package carrying _framework/blazor.web.js when it
# can see the .razor files, which the csproj-only restore above cannot. Without it the console is not interactive.
RUN dotnet publish src/VulnVerdict.Web/VulnVerdict.Web.csproj -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
# pg_dump and pg_restore for the worker's nightly backup. The client's major version must be the database image's
# (deploy/images/db.Dockerfile): an older pg_dump refuses a newer server, and a newer one writes dumps the database
# container's own pg_restore cannot read back. Raise both together.
ARG PG_MAJOR=16
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata curl postgresql-client-${PG_MAJOR} && rm -rf /var/lib/apt/lists/* \
    # /data/backups exists in the image so a volume mounted there starts out owned by the console's user
    && useradd --system --uid 10001 --create-home vulnverdict && mkdir -p /data/backups && chown vulnverdict /data /data/backups
COPY --from=build /app .
# this release's Compose file, Caddyfile and scripts: update.sh takes them from the image it moves to (deploy/update.sh)
COPY deploy/docker-compose.yml deploy/Caddyfile deploy/update.sh deploy/rollback.sh deploy/restore.sh deploy/.env.example /app/deploy/
RUN sed -i "/^    build: \.\.$/d" /app/deploy/docker-compose.yml && ! grep -q "build:" /app/deploy/docker-compose.yml
ENV ASPNETCORE_URLS=http://0.0.0.0:8080 \
    ASPNETCORE_FORWARDEDHEADERS_ENABLED=true \
    Worker__DataDir=/data \
    DOTNET_gcServer=0
USER vulnverdict
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD curl -fsS http://localhost:8080/healthz || exit 1
# the release pipeline passes the tag; the console shows it and puts it in reports and issue links
ARG VV_VERSION=dev
ENV VV_VERSION=${VV_VERSION}
ENTRYPOINT ["dotnet", "VulnVerdict.Web.dll"]
