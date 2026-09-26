# The database for the Compose stack and the appliance: the official Postgres image without gosu, running as the
# postgres user from the start. gosu only drops root privileges at start-up, which running as postgres makes
# unnecessary; its old Go build was the image's only critical and high findings. The cleaned filesystem is copied into
# a fresh image so the removed file does not linger in a lower layer (scanners read every layer). Data directories
# created by the official image are already owned by postgres, so existing installs start unchanged.
FROM postgres:16-alpine AS base
RUN rm -f /usr/local/bin/gosu

FROM scratch
COPY --from=base / /
# the official image's settings, which a copied filesystem does not carry
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=en_US.utf8 \
    PGDATA=/var/lib/postgresql/data
USER postgres
VOLUME /var/lib/postgresql/data
EXPOSE 5432
STOPSIGNAL SIGINT
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["postgres"]
LABEL org.opencontainers.image.description="VulnVerdict database: Postgres 16 without gosu, running as postgres"
