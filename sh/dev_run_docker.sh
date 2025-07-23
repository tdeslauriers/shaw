#!/bin/bash

docker build -t shaw .

docker run -d --rm -p $(op read "op://world_site/shaw_service_container_dev/port"):$(op read "op://world_site/shaw_service_container_dev/port") \
    -e SHAW_SERVICE_CLIENT_ID=$(op read "op://world_site/shaw_service_container_dev/client_id") \
    -e SHAW_SERVICE_PORT=":$(op read "op://world_site/shaw_service_container_dev/port")" \
    -e SHAW_CA_CERT="$(op document get "service_ca_dev_cert" --vault world_site | base64 -w 0)" \
    -e SHAW_SERVER_CERT="$(op document get "shaw_service_server_dev_cert" --vault world_site | base64 -w 0)" \
    -e SHAW_SERVER_KEY="$(op document get "shaw_service_server_dev_key" --vault world_site | base64 -w 0)" \
    -e SHAW_CLIENT_CERT="$(op document get "shaw_service_client_dev_cert" --vault world_site | base64 -w 0)" \
    -e SHAW_CLIENT_KEY="$(op document get "shaw_service_client_dev_key" --vault world_site | base64 -w 0)" \
    -e SHAW_S2S_AUTH_URL="$(op read "op://world_site/ran_service_container_dev/url"):$(op read "op://world_site/ran_service_container_dev/port")" \
    -e SHAW_S2S_AUTH_CLIENT_ID="$(op read "op://world_site/shaw_s2s_login_dev/username")" \
    -e SHAW_S2S_AUTH_CLIENT_SECRET="$(op read "op://world_site/shaw_s2s_login_dev/password")" \
    -e SHAW_DB_CA_CERT="$(op document get "db_ca_dev_cert" --vault world_site | base64 -w 0)" \
    -e SHAW_DB_CLIENT_CERT="$(op document get "shaw_db_client_dev_cert" --vault world_site | base64 -w 0)" \
    -e SHAW_DB_CLIENT_KEY="$(op document get "shaw_db_client_dev_key" --vault world_site | base64 -w 0)" \
    -e SHAW_DATABASE_URL="$(op read "op://world_site/shaw_db_dev/server"):$(op read "op://world_site/shaw_db_dev/port")" \
    -e SHAW_DATABASE_NAME="$(op read "op://world_site/shaw_db_dev/database")" \
    -e SHAW_DATABASE_USERNAME="$(op read "op://world_site/shaw_db_dev/username")" \
    -e SHAW_DATABASE_PASSWORD="$(op read "op://world_site/shaw_db_dev/password")" \
    -e SHAW_DATABASE_HMAC_INDEX_SECRET="$(op read "op://world_site/shaw_hmac_index_secret_dev/secret")" \
    -e SHAW_FIELD_LEVEL_AES_GCM_SECRET="$(op read "op://world_site/shaw_aes_gcm_secret_dev/secret")" \
    -e SHAW_S2S_JWT_VERIFYING_KEY="$(op read "op://world_site/ran_jwt_key_pair_dev/verifying_key")" \
    -e SHAW_USER_JWT_SIGNING_KEY="$(op read "op://world_site/shaw_jwt_key_pair_dev/signing_key")" \
    -e SHAW_USER_JWT_VERIFYING_KEY="$(op read "op://world_site/shaw_jwt_key_pair_dev/verifying_key")" \
    shaw:latest
