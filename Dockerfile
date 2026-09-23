# VulnVerdict: single image, runs as "web", "worker" or "all" depending on the Role setting.
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY VulnVerdict.slnx ./
COPY src/VulnVerdict.Core/VulnVerdict.Core.csproj src/VulnVerdict.Core/
COPY src/VulnVerdict.Web/VulnVerdict.Web.csproj src/VulnVerdict.Web/
RUN dotnet restore src/VulnVerdict.Web/VulnVerdict.Web.csproj
COPY src/ src/
RUN dotnet publish src/VulnVerdict.Web/VulnVerdict.Web.csproj -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata curl && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home vulnverdict && mkdir -p /data && chown vulnverdict /data
COPY --from=build /app .
ENV ASPNETCORE_URLS=http://0.0.0.0:8080 \
    ASPNETCORE_FORWARDEDHEADERS_ENABLED=true \
    Worker__DataDir=/data \
    DOTNET_gcServer=0
USER vulnverdict
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD curl -fsS http://localhost:8080/healthz || exit 1
ENTRYPOINT ["dotnet", "VulnVerdict.Web.dll"]
