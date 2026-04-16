# Private Root CA

> Offline, standalone Public Key Infrastructure (PKI) management for home labs inside a FIPS-compliant, self-contained Docker ecosystem.

This repository provides modular scripts packaged within a Red Hat UBI minimal container to initialize a self-contained Root CA, sign intermediate CAs, batch process your own custom intermediate keys, and generate leaf certificates securely. 

This environment natively enforces industry best practices (e.g. default 10+ year CA lifespans natively inherited through defaults) while allowing explicitly defined logic to override all metrics via `.json` configs.

## Architecture & Configuration

The container operates dynamically by scanning explicitly mapped volume mounts.
- `/ca/output`: Main output directory.
- `/ca/int-keys`: Explicit volume for dropping in your own `.key` files to batch sign.
- `/root.key`: Optional explicit mount for your Root CA key.

### `pki-config.json`

You can optionally mount an explicit configuration file to `/ca/pki-config.json` to alter certificate generation dynamically. This inherently solves "complex functions", for example, setting time limits individually per key:

```json
{
  "root": {
    "ca_name": "Acme Global CA",
    "days": 7300,
    "country": "US"
  },
  "intermediates": {
    "prod_inter": {
      "ca_name": "Acme Production Intermediate CA",
      "days": 365
    },
    "dev_inter": {
      "ca_name": "Acme Development Sandbox CA",
      "days": 30
    }
  },
  "leaf": {
    "days": 180,
    "inter": "prod_inter"
  }
}
```

## Usage

Start the container securely in the background:
```bash
docker-compose up -d
```

### 1. Initialize the Root CA
Generate or mount your root and initiate self-signing.
```bash
docker exec -it private-root-ca pki-init-root
```

### 2. Intermediate CAs (Batch "Bring Your Own Key")
Drop your `.key` files (e.g., `prod_inter.key`, `dev_inter.key`) into your mounted `./int-keys` directory.

Run the batch processing tool:
```bash
docker exec -it private-root-ca pki-batch
```
The logic iterates your folder. It deduplicates and skips any keys that already have generated certificates, while referencing `pki-config.json` for specific individual key execution overrides (like the exact days and CNs established for `prod_inter` against `dev_inter` above in the custom fields). 

*Note: You can also generate ad-hoc/new intermediates directly using `docker exec -it private-root-ca pki-inter --name my_new_int` without needing an input key first.*

### 3. Generate Standalone Leaf Certificates
Generate local leaves interactively or purely through arguments seamlessly.

```bash
docker run -it --rm -v $(pwd)/output:/ca/output private-root-ca:latest pki-leaf --cn myservice.home --san "DNS:myservice.home"
```
*Note: A `PKI_PROD_MODE=true` docker environmental variable natively enforces robust constraints, explicitly denying testing or arbitrary leaf generation without concrete identifiers.*
