#!/bin/bash

# namespace and ConfigMap name
NAMESPACE="world"
CONFIG_MAP_NAME="cm-identity-service"

# get url from 1password
IDENTITY_URL=$(op read "op://world_site/shaw_service_container_prod/url")
IDENTITY_PORT=$(op read "op://world_site/shaw_service_container_prod/port")
IDENTITY_CLIENT_ID=$(op read "op://world_site/shaw_service_container_prod/client_id")

# validate value is not empty
if [[ -z "$IDENTITY_URL" || -z "$IDENTITY_PORT" || -z "$IDENTITY_CLIENT_ID" ]]; then
  echo "Error: failed to get identity config vars from 1Password."
  exit 1
fi

echo "Identity URL: $IDENTITY_URL:$IDENTITY_PORT"

# apply cm
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: $CONFIG_MAP_NAME
  namespace: $NAMESPACE
data:
  identity-url: "$IDENTITY_URL:$IDENTITY_PORT"
  identity-port: ":$IDENTITY_PORT"
  identity-client-id: "$IDENTITY_CLIENT_ID"
EOF
