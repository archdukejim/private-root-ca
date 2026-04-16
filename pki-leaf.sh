#!/bin/bash
# pki-leaf - Generates a leaf key/CSR and signs it with an intermediate CA

source /usr/local/bin/pki-core

FLAG_CN=""
FLAG_SAN=""
FLAG_DAYS=""
FLAG_INTER=""
FLAG_KEY_TYPE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --cn)        FLAG_CN="$2"; shift 2 ;;
        --san)       FLAG_SAN="$2"; shift 2 ;;
        --days)      FLAG_DAYS="$2"; shift 2 ;;
        --inter)     FLAG_INTER="$2"; shift 2 ;;
        --key-type)  FLAG_KEY_TYPE="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: pki-leaf --cn <domain> [options]"
            echo "  --san <san>       Subject Alternative Names"
            echo "  --days <n>        Validity period"
            echo "  --inter <name>    Intermediate CA to sign with (default: intermediate_ca)"
            exit 0
            ;;
        *) die "Unknown argument: $1" ;;
    esac
done

echo ""
echo -e "  ${BOLD}PKI — Leaf Certificate Generation${NC}"

if [ "${PKI_PROD_MODE,,}" = "true" ] && [ -z "$FLAG_CN" ]; then
    die "PROD MODE ENFORCED: --cn is explicitly required to prevent generic test artifacts."
fi

CN="$(_prompt "$FLAG_CN" "Common Name (e.g. myservice.home)" "test.home")"
SAN="$(_prompt "$FLAG_SAN" "SANs (DNS:...,IP:...) [Optional]" "")"
INTER_NAME="${FLAG_INTER:-$(_cfg default_inter "intermediate_ca")}"
DAYS="${FLAG_DAYS:-$(_cfg leaf.days "$DEF_LEAF_DAYS")}"
KEY_TYPE="${FLAG_KEY_TYPE:-$(_cfg leaf.key_type "$DEF_KEY_TYPE")}"
KEY_PARAM="$(_cfg leaf.key_param "$DEF_LEAF_KEY_PARAM")"
DIGEST="$(_cfg leaf.digest "$DEF_DIGEST")"

CN_SAFE="${CN//[^a-zA-Z0-9.-]/_}"

leaf_key="${OUT_DIR}/${CN_SAFE}.key"
leaf_csr="${OUT_DIR}/${CN_SAFE}.csr"
leaf_crt="${OUT_DIR}/${CN_SAFE}.crt"

int_key="${OUT_DIR}/${INTER_NAME}.key"
int_crt="${OUT_DIR}/${INTER_NAME}.crt"

[ -f "$int_crt" ] || die "Intermediate CA Cert missing: ${int_crt}"
[ -f "$int_key" ] || die "Intermediate CA Key missing: ${int_key}"

if [ -f "$leaf_crt" ]; then
    ok "Terminal Certificate ${leaf_crt} exists. Skipping."
    exit 0
fi

if [ ! -f "$leaf_key" ]; then
    info "Generating leaf key (${KEY_TYPE} ${KEY_PARAM})..."
    case "${KEY_TYPE,,}" in
        rsa) openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:${KEY_PARAM}" -out "$leaf_key" 2>/dev/null ;;
        ec) openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:${KEY_PARAM}" -out "$leaf_key" 2>/dev/null ;;
        ed25519) openssl genpkey -algorithm ed25519 -out "$leaf_key" 2>/dev/null ;;
    esac
    chmod 600 "$leaf_key"
fi

local_cnf="${OUT_DIR}/_csr_${CN_SAFE}.cnf"
cat > "$local_cnf" <<CNFEOF
[req]
prompt = no
distinguished_name = dn
req_extensions = leaf_ext

[dn]
CN = ${CN}

[leaf_ext]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth,clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
CNFEOF

if [ -n "$SAN" ]; then
    echo "subjectAltName = ${SAN}" >> "$local_cnf"
fi

info "Generating CSR..."
openssl req -new -key "$leaf_key" -out "$leaf_csr" -"${DIGEST}" -config "$local_cnf" 2>/dev/null
ok "CSR generated: $leaf_csr"

info "Signing leaf certificate with ${INTER_NAME} (${DAYS} days)..."
openssl x509 -req -in "$leaf_csr" -CA "$int_crt" -CAkey "$int_key" -CAcreateserial \
    -out "$leaf_crt" -days "$DAYS" -"${DIGEST}" -extfile "$local_cnf" -extensions leaf_ext 2>/dev/null

rm -f "$local_cnf"
chmod 644 "$leaf_crt"

openssl verify -CAfile "${OUT_DIR}/root_ca.crt" -untrusted "$int_crt" "$leaf_crt" >/dev/null 2>&1 \
    && ok "Leaf chain verified successfully" \
    || warn "Chain verification explicitly against ${INTER_NAME} failed!"

ok "Finished writing ${leaf_crt}"
echo ""
