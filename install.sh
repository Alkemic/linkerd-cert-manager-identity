#!/bin/bash -eu

kind create cluster --name linkerd

kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.11.0/cert-manager.yaml

kubectl create ns linkerd

kubectl apply -n linkerd -f issuer.yaml

kubectl  wait --namespace linkerd  --for condition=ready --timeout 60s issuer linkerd-identity

linkerd install --crds | kubectl apply -f -

# root CA
kubectl -n linkerd create configmap linkerd-identity-trust-roots \
  --from-literal=ca-bundle.crt="$(kubectl -n linkerd get secrets root-secret -o json | jq -r '.data["ca.crt"]' | base64 -d -)" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -f role.yaml

linkerd install --identity-external-issuer --set "identity.externalCA=true" \
  --set "identity.controllerImage=alkemic/linekrd-identity-cert-manager" \
  --set "identity.linkerdVersion=v0.0.1.8" \
  | kubectl apply -f -

#linkerd install \
#  --identity-trust-anchors-file <(kubectl -n linkerd get secrets root-secret -o json | jq -r '.data["ca.crt"]' | base64 -d) \
#  | kubectl apply -f -