#!/bin/bash

set -euo pipefail

IMAGE_NAME="shaw:latest"
CONTAINER_NAME="shaw-dev"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

docker build --pull --no-cache -f "${REPO_ROOT}/Dockerfile" -t "${IMAGE_NAME}" "${REPO_ROOT}"

docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

docker run -d --rm --name "${CONTAINER_NAME}" -p "${SHAW_SERVICE_PORT: -4}":"${SHAW_SERVICE_PORT: -4}" \
    -e SHAW_SERVICE_CLIENT_ID \
    -e SHAW_SERVICE_PORT \
    -e SHAW_CA_CERT \
    -e SHAW_SERVER_CERT \
    -e SHAW_SERVER_KEY \
    -e SHAW_CLIENT_CERT \
    -e SHAW_CLIENT_KEY \
    -e SHAW_S2S_AUTH_URL \
    -e SHAW_S2S_AUTH_CLIENT_ID \
    -e SHAW_S2S_AUTH_CLIENT_SECRET \
    -e SHAW_DB_CA_CERT \
    -e SHAW_DB_CLIENT_CERT \
    -e SHAW_DB_CLIENT_KEY \
    -e SHAW_DATABASE_URL \
    -e SHAW_DATABASE_NAME \
    -e SHAW_DATABASE_USERNAME \
    -e SHAW_DATABASE_PASSWORD \
    -e SHAW_DATABASE_HMAC_INDEX_SECRET \
    -e SHAW_FIELD_LEVEL_AES_GCM_SECRET \
    -e SHAW_S2S_JWT_VERIFYING_KEY \
    -e SHAW_USER_JWT_SIGNING_KEY \
    -e SHAW_USER_JWT_VERIFYING_KEY \
    "${IMAGE_NAME}"
