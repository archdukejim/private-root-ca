#!/bin/bash
# pki-batch - Batch iterate injected intermediate keys

source /usr/local/bin/pki-core

echo ""
info "Beginning batch evaluation of ${INT_KEYS_DIR}..."

if [ ! -d "$INT_KEYS_DIR" ]; then
    warn "Volume ${INT_KEYS_DIR} does not exist. Skipping."
    exit 0
fi

shopt -s nullglob
keys=("$INT_KEYS_DIR"/*.key)
shopt -u nullglob

if [ ${#keys[@]} -eq 0 ]; then
    warn "No .key files found in ${INT_KEYS_DIR}"
    exit 0
fi

for keypath in "${keys[@]}"; do
    name=$(basename "$keypath" .key)
    
    # If the certificate already exists, the pki-inter script inherently safely skips it,
    # but we will just pass it directly along to rely on its duplicate logic.
    info "Initiating processing sequence for key: ${name}"
    
    # Because config defaults exist inside pki-inter, we can safely just pass name and key.
    /usr/local/bin/pki-inter --name "$name" --key "$keypath" || warn "Failed processing $name"
    
done

ok "Batch intermediate processing complete."
echo ""
