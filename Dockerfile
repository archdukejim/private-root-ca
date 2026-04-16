FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

# Install openssl and python3 (required for parsing JSON config)
RUN microdnf install -y \
    openssl \
    python3 \
    && microdnf clean all

# Create the standard mount points and provide open permissions so that
# any user defined by `docker run --user` can write to them.
RUN mkdir -p /ca/output /ca/int-keys /key && chmod -R 777 /ca /key

# Copy modular scripts and make them universally accessible
COPY pki-core.sh /usr/local/bin/pki-core
COPY pki-init-root.sh /usr/local/bin/pki-init-root
COPY pki-inter.sh /usr/local/bin/pki-inter
COPY pki-batch.sh /usr/local/bin/pki-batch
COPY pki-leaf.sh /usr/local/bin/pki-leaf

RUN chmod +x /usr/local/bin/pki-*

WORKDIR /ca

# Generate an empty default JSON if none is provided via volumes
RUN echo "{}" > /etc/pki-config.json

# By default, run sleep infinity so the container stays alive for `docker exec`
# Alternatively, commands can be passed directly to `docker run`
CMD ["sleep", "infinity"]
