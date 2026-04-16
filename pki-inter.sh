#!/bin/bash
# pki-inter - Sub-CA generation and signing.

source /usr/local/bin/pki-core

NAME=""
FLAG_KEY=""
FLAG_CA_NAME=""
FLAG_DAYS=""
FLAG_DIGEST=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --name)      NAME="$2"; shift 2 ;;
        --key)       FLAG_KEY="$2"; shift 2 ;;
        --ca-name)   FLAG_CA_NAME="$2"; shift 2 ;;
        --days)      FLAG_DAYS="$2"; shift 2 ;;
        --digest)    FLAG_DIGEST="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: pki-inter --name <file-prefix> [options]"
            echo "  --key <path>        Use explicit/mounted private key"
            echo "  --ca-name <name>    Common Name for the cert"
            exit 0
            ;;
        *) die "Unknown argument: $1" ;;
    esac
done

echo ""
echo -e "  ${BOLD}PKI — Intermediate CA ($NAME)${NC}"

NAME="$(_prompt "$NAME" "Intermediate CA File Prefix (e.g., prod_inter)" "intermediate_ca")"

root_crt="${OUT_DIR}/root_ca.crt"
root_key="/root.key"
[ -f "$root_key" ] || root_key="${OUT_DIR}/root_ca.key"

[ -f "$root_crt" ] || die "Root CA missing: ${root_crt}"
[ -f "$root_key" ] || die "Root Key missing: ${root_key}"

int_key="${OUT_DIR}/${NAME}.key"
int_csr="${OUT_DIR}/${NAME}.csr"
int_crt="${OUT_DIR}/${NAME}.crt"

if [ -f "$int_crt" ]; then
    ok "Certificate ${int_crt} already exists. Skipping."
    exit 0
fi

if [ -n "$FLAG_KEY" ]; then
    [ -f "$FLAG_KEY" ] || die "Key not found: $FLAG_KEY"
    info "Using provided key: $FLAG_KEY"
    int_key="$FLAG_KEY"
elif [ -f "$int_key" ]; then
    ok "Found existing key: $int_key"
else
    KEY_TYPE="$(_cfg int.key_type "$DEF_KEY_TYPE")"
    KEY_PARAM="$(_cfg int.key_param "$DEF_INT_KEY_PARAM")"
    info "Generating new intermediate key (${KEY_TYPE} ${KEY_PARAM})..."
    case "${KEY_TYPE,,}" in
        rsa) openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:${KEY_PARAM}" -out "$int_key" 2>/dev/null ;;
        ec) openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:${KEY_PARAM}" -out "$int_key" 2>/dev/null ;;
        ed25519) openssl genpkey -algorithm ed25519 -out "$int_key" 2>/dev/null ;;
    esac
    chmod 600 "$int_key"
    ok "Key generated: $int_key"
fi

# Load variables
CA_NAME="$(_prompt "${FLAG_CA_NAME:-$(_cfg intermediates.${NAME}.ca_name "$NAME CA")}" "CA Name" "$NAME CA")"
DAYS="${FLAG_DAYS:-$(_cfg intermediates.${NAME}.days "$DEF_INT_DAYS")}"
DIGEST="${FLAG_DIGEST:-$(_cfg int.digest "$DEF_DIGEST")}"

CERT_COUNTRY="$(_cfg root.country "US")"
CERT_PROVINCE="$(_cfg root.province "DC")"
CERT_CITY="$(_cfg root.city "Washington")"
CERT_ORG="$(_cfg root.org "Internal")"
CERT_OU="$(_cfg root.ou "Private")"

info "Generating CSR..."
int_subj="/C=${CERT_COUNTRY}/ST=${CERT_PROVINCE}/L=${CERT_CITY}/O=${CERT_ORG}/OU=${CERT_OU}/CN=${CA_NAME}"
openssl req -new -key "$int_key" -out "$int_csr" -"${DIGEST}" -subj "$int_subj" 2>/dev/null
ok "CSR generated: $int_csr"

info "Signing Intermediate CA (${DAYS} days)..."
ext_conf="${OUT_DIR}/_int_ext_${NAME}.cnf"
cat > "$ext_conf" <<EXTEOF
[ext]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EXTEOF

openssl x509 -req -in "$int_csr" -CA "$root_crt" -CAkey "$root_key" -CAcreateserial \
    -out "$int_crt" -days "$DAYS" -"${DIGEST}" -extfile "$ext_conf" -extensions ext 2>/dev/null

rm -f "$ext_conf"
chmod 644 "$int_crt"
ok "Intermediate CA generated: $int_crt"
echo ""
