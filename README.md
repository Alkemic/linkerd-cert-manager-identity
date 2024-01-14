# LinkerD cert-manager identity

This project is designed as a drop in replacement for default identity provider, that issues certificates from local
cert-manager installation.

With a few changes to parameters, to take `Issuer` configuration into account.

## Pre-requirements

A cert-manager must be installed, and `Issuer` must be configured and working beforehand.

*Note*: service account related to this identity controller requires `Role`/`RoleBinding`s that allow this service to
create new `CertificateRequests` and `Event`s. See [role.yaml](./examples/manual/role.yaml) for details.

## Usages

### Self-signed

A basic example can be found in [examples/manual](./examples/manual), where first we create and `ClusterIssuer` and
`Certificate` authority, which will be used as a trust anchor.

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: selfsigned
spec:
  selfSigned: {}
---
# root CA - trust anchor
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: selfsigned
  namespace: linkerd
spec:
  isCA: true
  commonName: my-selfsigned-ca
  secretName: root-secret
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: selfsigned
    kind: ClusterIssuer
    group: cert-manager.io
```

Now we can configure `Issuer` that we'll use for issuing identity certificates. The `linkerd-identity-issuer`
intermediate certificate is used for validation reason, since `linkerd` cli check if it's valid.

```yaml
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: linkerd
  namespace: linkerd
spec:
  ca:
    secretName: root-secret
---
# issuer cert - intermediate
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: linkerd-identity-issuer
  namespace: linkerd
spec:
  secretName: linkerd-identity-issuer
  duration: 48h
  renewBefore: 25h
  issuerRef:
    name: linkerd
    kind: Issuer
  commonName: identity.linkerd.cluster.local
  dnsNames:
    - identity.linkerd.cluster.local
  isCA: true
  privateKey:
    algorithm: ECDSA
  usages:
    - cert sign
    - crl sign
    - server auth
    - client auth
```

Trust anchor must be extracted from secrets (`root-secret` in this case) and stored in configmap 
`linkerd-identity-trust-roots` under `ca-bundle.crt` key, in LinkerD's namespace, then during installation you must
inform that you are using external certificate authority. Last step is to patch identity controller `Deployment` to use 
[alkemic/linkerd-cert-manager-identity](https://hub.docker.com/r/alkemic/linkerd-cert-manager-identity) image
and add argument `--issuer-name=linkerd` to specify which `Issuer` should be used.

### Vault

A certificate authority that is stored in Vault's PKI engine is our trust anchor, and you need a copy of it. Below is a
basic snippet taken from [Vault's documentation](https://cert-manager.io/docs/configuration/vault/).

```yaml
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: vault-issuer
  namespace: sandbox
spec:
  vault:
    path: pki_int/sign/example-dot-com
    server: https://vault.local
    caBundle: <base64 encoded CA Bundle PEM file>
    auth:
      ...
```

Rest is similar to [self-signed](#self-signed) approach, create `linkerd-identity-issuer` `Certificate`

```yaml
---
# issuer cert - intermediate
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: linkerd-identity-issuer
  namespace: linkerd
spec:
  secretName: linkerd-identity-issuer
  duration: 48h
  renewBefore: 25h
  issuerRef:
    name: vault-issuer
    kind: Issuer
  commonName: identity.linkerd.cluster.local
  dnsNames:
    - identity.linkerd.cluster.local
  isCA: true
  privateKey:
    algorithm: ECDSA
  usages:
    - cert sign
    - crl sign
    - server auth
    - client auth
```

Create configmap `linkerd-identity-trust-roots` with `ca-bundle.crt` key with certificate authority mentioned before.

## Arguments

Old (working in original identity controller):
* `addr` - address to serve on (default ":8080")
* `admin-addr` - address of HTTP admin server (default ":9990")
* `controller-namespace` - namespace in which Linkerd is installed
* `enable-pprof` - Enable pprof endpoints on the admin server
* `identity-scheme` - scheme used for the identity issuer secret format
* `identity-trust-domain` - configures the name suffix used for identities
* `kubeconfig` - path to kube config
* `log-level` - log level, must be one of: panic, fatal, error, warn, info, debug (default "info")
* `trace-collector` - Enables OC Tracing with the specified endpoint as collector

Ignored:
* `log-format` - log format, must be one of: plain, json (default "plain")
* `identity-clock-skew-allowance` - the amount of time to allow for clock skew within a Linkerd cluster
* `identity-issuance-lifetime` - the amount of time for which the Identity issuer should certify identity
* `version` - print version and exit

New options:
* `issuer-kind` - issuer kind, can be Issuer or ClusterIssuer (default "Issuer")
* `issuer-name` - name of issuer (default "linkerd")
* `preserve-csr-requests` - Do not remove CertificateRequests after csr is created

## Versioning

Versions in this project are set up to indicate which mainland version of LinkerD they support, e.g. 2.14.1 is fully
compatabile with LinkerD v2.14.x. The patch version

## Compatability

At this moment it was tested (and used on production) with LinkerD version 2.13.x and 2.14.x, cert-manager 1.11.x
and 1.13.x and K8S 1.23 and 1.27.

## Note

This project is based upon [LinkerD's identity controller](https://github.com/linkerd/linkerd2) and idea from 
[istio-csr](https://github.com/cert-manager/istio-csr/).
