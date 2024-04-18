# GCP KMS Issuer

[![Build Status](https://github.com/drzzlio/kms-issuer/actions/workflows/test-build.yml/badge.svg?branch=main)](https://github.com/drzzlio/kms-issuer/actions)
[![CodeQL Status](https://github.com/drzzlio/kms-issuer/actions/workflows/code-quality.yml/badge.svg?branch=main)](https://github.com/drzzlio/kms-issuer/actions)
[![E2E Tests](https://github.com/drzzlio/kms-issuer/actions/workflows/e2e.yaml/badge.svg?branch=main)](https://github.com/drzzlio/kms-issuer/actions)

GCP KMS issuer is a [cert-manager](https://cert-manager.io/) Issuer controller that uses [GCP KMS](https://cloud.google.com/security/products/security-key-management) to sign certificate requests.

Forked, with much gratitude, from Skyscanner's original AWS-targeted codebase.

## Getting started

In this guide, we assume that you have a [Kubernetes](https://kubernetes.io/) environment with a cert-manager version supporting CertificateRequest issuers, cert-manager v1.13.0 or higher.

For any details on Cert-Manager, check the [official documentation](https://cert-manager.io/docs/usage/).

## Install

The easiest way to install gcp-ksm-issuer in a cluster is to base a
kustomization on the resources built from `config/default`. It's usually best
practice to copy the result into your own repo, especially if you're doing
gitops, so that you don't have a deploy-time github network dependency.

We prerendered this in a build pipeline and attach it to releases as
`gcp-kms-issuer-installer.yaml`.

You can mutate these resources using our own kustomization, or you can
reference any elements under `config` directly if you need to more deeply
change things. You should still prerender this and include the result in your
repo.

### Usage

1. Install [cert-manager](https://cert-manager.io/docs/installation/). The operator has been tested with version v1.13.5

```bash
kubectl apply --validate=false -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.5/cert-manager.yaml
```

Optionally [install kubernetes config connector](https://cloud.google.com/config-connector/docs/concepts/installation-types) to manage your gcp kms keys with k8s

2. Install and run the kms-issuer

Install the kms-issuer as described in the previous section.

3. Create a KMS KeyRing and CryptoKey

You need a valid KMS asymetric key that as the ability to do ASYMMETRIC_SIGN
with an RSA PSS SHA256 algorithm.
Since this controller is optimally  meant to be used with config connector,
create a `KMSKeyRing` and `KMSCryptoKey` with the appropriate settings.

It _can_ be used without config connector if, for example, your keys are being
managed by an external IaC tool like terraform. In this case the `external`
property of the `KMSIssuer.KeyRef` should be the link to the key in the GCP KMS
API like `projects/gptops-playground/locations/us-central1/keyRings/kmsissuer-test/cryptoKeys/kmsissuer-test`.

```yaml
cat << EOF | kubectl apply -f -
apiVersion: kms.cnrm.cloud.google.com/v1beta1
kind: KMSKeyRing
metadata:
  name: cakeys
  annotations:
    cnrm.cloud.google.com/deletion-policy: "abandon"
spec:
  location: us-central1
---
apiVersion: kms.cnrm.cloud.google.com/v1beta1
kind: KMSCryptoKey
metadata:
  name: caroot
spec:
  keyRingRef:
    name: cakeys
  purpose: ASYMMETRIC_SIGN
  versionTemplate:
    algorithm: RSA_SIGN_PSS_2048_SHA256
    protectionLevel: HSM
  importOnly: false
EOF
```

4. Create a KMS Issuer Referencing the Key

```yaml
cat << EOF | kubectl apply -f -
---
apiVersion: cert-manager.drzzl.io/v1alpha1
kind: KMSIssuer
metadata:
  name: kms-issuer
  namespace: default
spec:
  keyRef: 
    name: caroot
  commonName: My Root CA # The common name for the root certificate
  duration: 87600h # 10 years
EOF
```

At this point, the operator geneates a public root certificate signed using the provided KMS key. You can inspect it with the following command:

```bash
kubectl get kmsissuer kms-issuer -o json | jq -r ".status.certificate" |  base64 --decode  | openssl x509 -noout -text
```

6. Finally, create a Certificate request that will be signed by our KMS issuer.

```yaml
cat << EOF | kubectl apply -f -
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-com
  namespace: default
spec:
  # Secret names are always required.
  secretName: example-com-tls
  duration: 8760h # 1 year
  renewBefore: 360h # 15d
  subject:
    organizations:
      - skyscanner
  # The use of the common name field has been deprecated since 2000 and is
  # discouraged from being used.
  commonName: example.com
  isCA: false
  privateKey:
    algorithm: RSA
    encoding: PKCS1
    size: 2048
  usages:
    - server auth
    - client auth
  # At least one of a DNS Name, URI, or IP address is required.
  dnsNames:
    - example.com
    - www.example.com
  uris:
    - spiffe://cluster.local/ns/sandbox/sa/example
  ipAddresses:
    - 192.168.0.5
  # Issuer references are always required.
  issuerRef:
    name: kms-issuer
    # We can reference ClusterIssuers by changing the kind here.
    # The default value is Issuer (i.e. a locally namespaced Issuer)
    kind: KMSIssuer
    # This is optional since cert-manager will default to this value however
    # if you are using an external issuer, change this to that issuer group.
    group: cert-manager.drzzl.io
EOF
```

You now have a key pair signed by KMS

```bash
kubectl get secret example-com-tls
```

## API Reference

### KMSIssuer

A KMSIssuer resource configures a new [Cert-Manager external issuer](https://cert-manager.io/docs/configuration/external).

| Field              | Type     | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ------------------ | -------- | -----------                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `apiVersion`       | string   | `cert-manager.drzzl.io/v1alpha1`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `kind`             | string   | `KMSIssuer`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `metadata`         | object   | Refer to the Kubernetes API [documentation][kubernetes-meta] for `metadata` fields.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `spec`             | object   | Desired state of the KMSIssuer resource.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `spec.keyRef`        | string   | A reference to the GCP KMS key used to sign certs.
| `spec.keyRef.name`   | string   | The name of the `KMSCryptoKey` resource to use if managed by KCC.
| `spec.keyRef.namespace` | string   | The namespace of the `KMSCryptoKey` recource to use - defaults to same as the KMSIssuer.
| `spec.keyRef.external` | string   | A self-link to the GCP KMS key to use if not managed by KCC (mutually-exclusive with name/namespace).
| `spec.commonName`  | string   | The common name to be used on the Certificate.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `spec.duration`    | duration | Certificate default Duration. (optional, default=26280h aka 3 years)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `spec.renewBefore` | duration | The amount of time before the certificate’s notAfter time that the issuer will begin to attempt to renew the certificate. If this value is greater than the total duration of the certificate (i.e. notAfter - notBefore), it will be automatically renewed 2/3rds of the way through the certificate’s duration. <br> <br> The `NotBefore` field on the certificate is set to the current time rounded down by the renewal interval. For example, if the certificate is renewed every hour, the `NotBefore` field is set to the beggining of the hour. If the certificate is renewed every day, the `NotBefore` field is set to the beggining of the day. This allows the generation of consistent certificates regardless of when it has been generated during the renewal period, or recreate the same certificate after a backup/restore of your kubernetes cluster. For more details on the computation, check the [time.Truncate](https://golang.org/pkg/time/#Time.Truncate) function. |

[kubernetes-meta]: https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.19/#objectmeta-v1-meta

## Disable Approval Check

The KMS Issuer will wait for CertificateRequests to have an [approved condition set](https://cert-manager.io/docs/concepts/certificaterequest/#approval) before
signing. If using an older version of cert-manager (pre v1.3), you can disable
this check by supplying the command line flag `-enable-approved-check=false` to
the Issuer Deployment.

## Contributing

Kms-Issuer is built using the [Kubebuilder](https://book.kubebuilder.io/) framework. See the [official documentation](https://book.kubebuilder.io/quick-start.html) to get started and
check [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

## Security

Check [SECURITY.md](SECURITY.md).
