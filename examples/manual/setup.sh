#!/bin/bash -eu

cert_manger_version=v1.13.3

kind delete cluster --name linkerd || true
kind create cluster --name linkerd

# install cert-manager
kubectl apply --wait -f "https://github.com/cert-manager/cert-manager/releases/download/${cert_manger_version}/cert-manager.yaml"
kubectl wait --namespace cert-manager --for condition=Available=True --timeout 120s \
  deployment cert-manager-webhook

# create issuer in LinkerD's namespace used for identity certificates,
# secret with CA is required for next step
kubectl create ns linkerd
kubectl apply -n linkerd --wait -f issuer.yaml
kubectl wait --namespace linkerd --for condition=ready --timeout 60s issuer linkerd

linkerd install --crds | kubectl apply --wait -f -

# create external trust root, with CA derived from self signed issuer
# in more complex scenario, this can be your root CA that is stored in
# Vault's PKI engine, that "linkerd" issuer used to sign requests
ca_bundle=$(kubectl -n linkerd get secrets root-secret -o json | jq -r '.data["ca.crt"]' | base64 -d -)
kubectl -n linkerd create configmap linkerd-identity-trust-roots \
  --from-literal=ca-bundle.crt="${ca_bundle}" \
  --dry-run=client -o yaml | kubectl apply -f -

# for less permissive environments, allow our service account to manage certificate requests
# and create events
kubectl apply -f role.yaml

# generate LinkerD's resources and patch identity deployment
linkerd install --identity-external-issuer --set "identity.externalCA=true" > input.yaml
kubectl kustomize | kubectl apply -f -
rm input.yaml
