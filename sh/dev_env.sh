#!/bin/bash

# Service client id and port
export SHAW_SERVICE_CLIENT_ID=$(op read "op://world_site/shaw_service_app_local/client_id")
export SHAW_SERVICE_PORT=":$(op read "op://world_site/shaw_service_app_local/port")"

# certs
export SHAW_CA_CERT=$(op document get "service_ca_dev_cert" --vault world_site | base64 -w 0)

export SHAW_SERVER_CERT=$(op document get "shaw_service_server_dev_cert" --vault world_site | base64 -w 0)
export SHAW_SERVER_KEY=$(op document get "shaw_service_server_dev_key" --vault world_site | base64 -w 0)

export SHAW_CLIENT_CERT=$(op document get "shaw_service_client_dev_cert" --vault world_site | base64 -w 0)
export SHAW_CLIENT_KEY=$(op document get "shaw_service_client_dev_key" --vault world_site | base64 -w 0)

export SHAW_DB_CA_CERT=$(op document get "db_ca_dev_cert" --vault world_site | base64 -w 0)

export SHAW_DB_CLIENT_CERT=$(op document get "shaw_db_client_dev_cert" --vault world_site | base64 -w 0)
export SHAW_DB_CLIENT_KEY=$(op document get "shaw_db_client_dev_key" --vault world_site | base64 -w 0)

# Database connection details + creds
export SHAW_DATABASE_URL=$(op read "op://world_site/shaw_db_dev/server"):$(op read "op://world_site/shaw_db_dev/port")
export SHAW_DATABASE_NAME=$(op read "op://world_site/shaw_db_dev/database")
export SHAW_DATABASE_USERNAME=$(op read "op://world_site/shaw_db_dev/username")
export SHAW_DATABASE_PASSWORD=$(op read "op://world_site/shaw_db_dev/password")

# HMAC key for blind index fields in database
export SHAW_DATABASE_HMAC_INDEX_SECRET=$(op read "op://world_site/shaw_hmac_index_secret_dev/secret")

# Field level encryption key for database fields
export SHAW_FIELD_LEVEL_AES_GCM_SECRET=$(op read "op://world_site/shaw_aes_gcm_secret_dev/secret")

# User JWT signing key --> sign the jwt and provide verifying key to validate the jwt to client services
export SHAW_USER_JWT_SIGNING_KEY=$(op read "op://world_site/shaw_jwt_key_pair_dev/signing_key")
export SHAW_USER_JWT_VERIFYING_KEY=$(op read "op://world_site/shaw_jwt_key_pair_dev/verifying_key")

# S2S JWT verifying key --> validate the s2s jwt
export SHAW_S2S_JWT_VERIFYING_KEY=$(op read "op://world_site/ran_jwt_key_pair_dev/verifying_key")

# S2S Auth creds
export SHAW_S2S_AUTH_URL=$(op read "op://world_site/shaw_s2s_login_dev/url")
export SHAW_S2S_AUTH_CLIENT_ID=$(op read "op://world_site/shaw_s2s_login_dev/username")
export SHAW_S2S_AUTH_CLIENT_SECRET=$(op read "op://world_site/shaw_s2s_login_dev/password")