#!/bin/bash
# pki-init-root - Generates or adopts a Root CA private key and self-signs its certificate.

source /usr/local/bin/pki-core

FLAG_CA_NAME=""
FLAG_COUNTRY=""
FLAG_PROVINCE=""
FLAG_CITY=""
FLAG_ORG=""
FLAG_OU=""
FLAG_KEY_TYPE=""
FLAG_KEY_PARAM=""
FLAG_DAYS=""
FLAG_DIGEST=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ca-name)   FLAG_CA_NAME="$2"; shift 2 ;;
        --country)   FLAG_COUNTRY="$2"; shift 2 ;;
        --province)  FLAG_PROVINCE="$2"; shift 2 ;;
        --city)      FLAG_CITY="$2"; shift 2 ;;
        --org)       FLAG_ORG="$2"; shift 2 ;;
        --ou)        FLAG_OU="$2"; shift 2 ;;
        --key-type)  FLAG_KEY_TYPE="$2"; shift 2 ;;
        --key-param) FLAG_KEY_PARAM="$2"; shift 2 ;;
        --days)      FLAG_DAYS="$2"; shift 2 ;;
        --digest)    FLAG_DIGEST="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: pki-init-root [options]"
            echo "  --ca-name <name>    Common Name (e.g., Acme Root CA)"
            echo "  --days <n>          Validity in days (default: $DEF_ROOT_DAYS)"
            exit 0
            ;;
        *) die "Unknown argument: $1" ;;
    esac
done

echo ""
echo -e "  ${BOLD}PKI Initialization — Root CA${NC}"
echo ""

# Load defaults from config or hardcoded defaults
CA_NAME="$(_prompt "${FLAG_CA_NAME:-$(_cfg root.ca_name)}" "CA Name" "Root Certificate Authority")"
CERT_COUNTRY="$(_prompt "${FLAG_COUNTRY:-$(_cfg root.country)}" "Country (2-letter code)" "US")"
CERT_PROVINCE="$(_prompt "${FLAG_PROVINCE:-$(_cfg root.province)}" "State / Province" "DC")"
CERT_CITY="$(_prompt "${FLAG_CITY:-$(_cfg root.city)}" "City / Locality" "Washington")"
CERT_ORG="$(_prompt "${FLAG_ORG:-$(_cfg root.org)}" "Organization" "Internal")"
CERT_OU="$(_prompt "${FLAG_OU:-$(_cfg root.ou)}" "Organizational Unit" "Private")"

KEY_TYPE="${FLAG_KEY_TYPE:-$(_cfg root.key_type "$DEF_KEY_TYPE")}"
KEY_PARAM="${FLAG_KEY_PARAM:-$(_cfg root.key_param "$DEF_ROOT_KEY_PARAM")}"
DAYS="${FLAG_DAYS:-$(_cfg root.days "$DEF_ROOT_DAYS")}"
DIGEST="${FLAG_DIGEST:-$(_cfg root.digest "$DEF_DIGEST")}"

mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

root_key="${OUT_DIR}/root_ca.key"
root_crt="${OUT_DIR}/root_ca.crt"

# Check for custom mounted key
if [ -f "/root.key" ]; then
    info "Adopting explicit mounted Root CA key at /root.key"
    root_key="/root.key"
elif [ -f "$root_key" ]; then
    ok "Existing Root CA key found at output/root_ca.key"
else
    info "Generating new Root CA private key (${KEY_TYPE} ${KEY_PARAM})..."
    case "${KEY_TYPE,,}" in
        rsa) openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:${KEY_PARAM}" -out "$root_key" 2>/dev/null ;;
        ec) openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:${KEY_PARAM}" -out "$root_key" 2>/dev/null ;;
        ed25519) openssl genpkey -algorithm ed25519 -out "$root_key" 2>/dev/null ;;
        *) die "Unknown key type '${KEY_TYPE}'. Supported: rsa, ec, ed25519" ;;
    esac
    chmod 600 "$root_key"
    ok "Root CA key generated: ${root_key}"
fi

if [ -f "$root_crt" ]; then
    ok "Root CA certificate already exists (${root_crt}) — skipping generation."
else
    info "Self-signing Root CA certificate (${DAYS} days)..."
    root_subj="/C=${CERT_COUNTRY}/ST=${CERT_PROVINCE}/L=${CERT_CITY}/O=${CERT_ORG}/OU=${CERT_OU}/CN=${CA_NAME}"
    openssl req -new -x509 \
        -key "$root_key" \
        -out "$root_crt" \
        -days "$DAYS" \
        -"${DIGEST}" \
        -subj "$root_subj" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "subjectKeyIdentifier=hash" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        2>/dev/null
    chmod 644 "$root_crt"
    ok "Root CA certificate generated: ${root_crt}"
fi

echo ""
printf "  ${BOLD}Root CA Fingerprint:${NC} "
openssl x509 -in "$root_crt" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//'
echo ""
