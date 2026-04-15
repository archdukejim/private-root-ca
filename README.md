# Private Root CA

> Offline, standalone Public Key Infrastructure (PKI) management for home labs.

This repository provides scripts to initialize a self-contained Root CA, sign intermediate CAs, and generate/sign standalone offline leaf certificates. 

It uses a pre-built Docker image (`private-root-ca:latest` — Alpine + OpenSSL) to generate key material securely, but will fall back to local `openssl` if Docker is unavailable.

---

## 1. Initialize the PKI

The root CA and intermediate CA must be generated **offline**. 

```bash
./root-ca.sh init
```

Identity fields are read from `pki-vars.yaml`; any missing fields are collected interactively. The intermediate CA key type, key param, and digest are **always prompted** (current values shown as defaults) so the algorithm is confirmed explicitly on every run.

This writes four files to `./output/` (gitignored):

| File | Purpose |
|------|---------|
| `root_ca.key` | Root CA private key — **keep offline or destroy** |
| `root_ca.crt` | Root CA certificate (trust anchor) |
| `intermediate_ca.key` | Intermediate CA private key |
| `intermediate_ca.crt` | Intermediate CA certificate |

**Key generation options** — CLI flags override `pki-vars.yaml` settings:

```bash
./root-ca.sh init --key-type ec --key-param P-384   # use EC P-384 instead of RSA 4096
./root-ca.sh init --key /path/to/existing.key       # bring your own root CA key
./root-ca.sh init --ca-name "Acme Lab CA" --country US --org "Acme" --outpath /tmp/pki
```

After `init`, verify the chain:

```bash
./root-ca.sh verify
```

---

## 2. Generate Standalone Leaf Certificates

While the `intermediate_ca` is typically supplied to an automated provisioner (like Step-CA), you can use these scripts to manually generate and sign standalone certificates locally.

```bash
# 1. Generate a leaf key + CSR (prompted interactively for missing fields)
./gen-csr.sh --cn myservice.home --san "DNS:myservice.home,IP:10.0.1.5"
# → output/myservice.home.key
# → output/myservice.home.csr

# 2. Sign the CSR with the root CA
./root-ca.sh --sign-certs output/myservice.home.csr
# → myservice.home.crt  (written to script directory by default)

# Write the signed cert to a specific location
./root-ca.sh --sign-certs myservice.home.csr --outpath /srv/certs/
```

Both scripts display a **pre-issuance confirmation review** — a summary of all resolved settings — before generating any key material. The prompt accepts `Y` (proceed), `n` (abort), or `edit` (re-enter individual fields interactively).
