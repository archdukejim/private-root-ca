FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

# Install openssl and python3 (required for parsing YAML config)
RUN microdnf install -y \
    openssl \
    python3 \
    && microdnf clean all

# Create the standard mount points and provide open permissions so that
# any user defined by `docker run --user` can write to them.
RUN mkdir -p /ca /key && chmod 777 /ca /key

# Copy the default variables configuration
COPY pki-vars.yaml /etc/pki/pki-vars.yaml

# Copy scripts and make them universally accessible
COPY root-ca.sh /usr/local/bin/root-ca
COPY gen-csr.sh /usr/local/bin/gen-csr
RUN chmod +x /usr/local/bin/root-ca /usr/local/bin/gen-csr

WORKDIR /ca

# By default, run sleep infinity so the container stays alive for `docker exec`
# Alternatively, commands can be passed directly to `docker run`
CMD ["sleep", "infinity"]
