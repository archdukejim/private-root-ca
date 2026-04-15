# Private Root CA

> Offline, standalone Public Key Infrastructure (PKI) management for home labs inside a FIPS-compliant, self-contained Docker ecosystem.

This repository provides scripts packaged within a Red Hat UBI minimal container to initialize a self-contained Root CA, sign intermediate CAs, and generate/sign standalone offline leaf certificates. 

The container enforces FIPS-compliant algorithms (via `openssl`) and strictly contains all execution within the Docker environment, interacting with the host exclusively via volume mounts.

It is built for multi-arch execution (e.g., AMD64 and ARM64/Raspberry Pi) leveraging the official multi-architecture `ubi-minimal` base images.

---

## Architecture & Configuration

All execution happens exclusively in the container. The scripts (`root-ca` and `gen-csr`) evaluate operations in the container's `/ca/output/` directory, which routes to a volume on the host. An optional explicit root key can be mounted at `/key/root_ca.key`.

### Running the Container

The container provides two modes of operation: **Long-Running/Background** and **Transient**.

#### Option 1: Long-Running (docker-compose)

This mounts your directories and starts a sleeping container in the background.

```bash
docker-compose up -d
```

You can then run commands inside the container whenever you need to mint certificates:

```bash
# As standard root in container
docker exec -it private-root-ca root-ca init

# As a specific host user (so the generated files sync host permissions perfectly)
docker exec -it --user "1000:1000" private-root-ca root-ca init
```

#### Option 2: Transient Execution (docker run)

Spin up the container instantly, run one command, and tear down:

```bash
docker run --rm -it \
  --user "$(id -u):$(id -g)" \
  -v "$(pwd)/output:/ca/output" \
  private-root-ca:latest root-ca init
```

---

## 1. Initialize the PKI

The root CA and intermediate CA must be generated **offline**. Utilizing either the transient or background execution above:

```bash
# Using an existing compose setup
docker exec -it private-root-ca root-ca init
```

Identity fields are read from `pki-vars.yaml` inside the container (`/ca/pki-vars.yaml` if mounted, or `/etc/pki/pki-vars.yaml` by default). Any missing fields are collected interactively. The intermediate CA key type, key param, and digest are **always prompted**.

This writes four files to the `/ca/output/` volume (which appears on your host):

| File | Purpose |
|------|---------|
| `root_ca.key` | Root CA private key — **keep offline or destroy** |
| `root_ca.crt` | Root CA certificate (trust anchor) |
| `intermediate_ca.key` | Intermediate CA private key |
| `intermediate_ca.crt` | Intermediate CA certificate |

**Key generation options:**

```bash
docker exec -it private-root-ca root-ca init --key-type ec --key-param P-384
```

*Note: If you have an external root key you want to supply, mount it to `/key/root_ca.key` and it will securely adopt it.*

After `init`, verify the chain:

```bash
docker exec -it private-root-ca root-ca verify
```

---

## 2. Generate Standalone Leaf Certificates

While the `intermediate_ca` is typically supplied to an automated provisioner (like Step-CA), you can manually generate and sign standalone certificates using `gen-csr`.

```bash
# 1. Generate a leaf key + CSR
docker exec -it private-root-ca gen-csr --cn myservice.home --san "DNS:myservice.home,IP:10.0.1.5"

# 2. Sign the CSR with the root CA
docker exec -it private-root-ca root-ca --sign-certs /ca/output/myservice.home.csr
```

*Certs and keys are output directly to `/ca/output/` on the container, syncing instantly to your host volume mount without altering file permissions recursively across the whole system, securely preserving ownership to the running `--user`.*
