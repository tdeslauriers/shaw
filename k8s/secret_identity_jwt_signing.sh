#!/bin/bash

# variables
NAMESPACE="world"
SECRET_NAME="secret-identity-jwt-signing"

# get key pair from 1Password
JWT_SIGNING_KEY=$(op read "op://world_site/shaw_jwt_key_pair_prod/signing_key")
JWT_VERIFYING_KEY=$(op read "op://world_site/shaw_jwt_key_pair_prod/verifying_key")

# check if values are retrieved successfully
if [[ -z "$JWT_SIGNING_KEY" || -z "$JWT_VERIFYING_KEY"  ]]; then
  echo "Error: failed to get identity service's jwt signing keys from 1Password."
  exit 1
fi

# create the key pair secret
kubectl create secret generic $SECRET_NAME \
  --namespace $NAMESPACE \
  --from-literal=jwt-signing-key="$JWT_SIGNING_KEY" \
  --from-literal=jwt-verifying-key="$JWT_VERIFYING_KEY" \
  --dry-run=client -o yaml | kubectl apply -f -
