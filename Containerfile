# share_service image. Reuses two sibling packages, so build with the *parent*
# (monorepo) directory as context:
#
#   podman build -f share_service/Containerfile -t share-service ..
#   podman run --rm -p 8101:8101 --env-file share_service/.env share-service
#
FROM python:3.12-slim

WORKDIR /app

# Reused packages FIRST (they change rarely -> better layer caching), then this
# service. The .env (credentials) is never copied.
#
# python_interface is the FileEngine gRPC client: every core call is delegated
# through it as the link creator (spec §4.1).
#
# audit_service is NOT optional here, unlike in the other services that import
# it opportunistically. The core attributes delegated activity to the creator,
# so the audit chain is the only record that an access was external (spec §4.3)
# -- with no publisher this service refuses to mint or redeem anything and
# /readyz stays red. Installing it is what makes the image functional at all.
# (Note ldap_manager's image does NOT install it and simply runs unaudited;
# that is safe for its emitter's semantics and would be a dead container here.)
COPY python_interface/ /app/python_interface/
COPY audit_service/ /app/audit_service/
COPY share_service/pyproject.toml share_service/README.md /app/share_service/
COPY share_service/src/ /app/share_service/src/

RUN pip install --no-cache-dir /app/python_interface && \
    pip install --no-cache-dir /app/audit_service && \
    pip install --no-cache-dir /app/share_service

# Bind all interfaces INSIDE the container for the API; the host still fronts it.
# Monitoring stays on loopback *within the container* per the platform
# convention -- scrapers reach it by exec/sidecar, not across the network,
# because /healthz /readyz /poolz /metrics carry no authentication.
ENV SHARE_API_HOST=0.0.0.0 \
    SHARE_API_PORT=8101 \
    SHARE_MONITORING_HOST=127.0.0.1 \
    SHARE_MONITORING_PORT=8102
EXPOSE 8101

CMD ["share-service"]
