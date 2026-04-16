#!/bin/bash
# pki-init-root - Generates or adopts a Root CA private key and self-signs its certificate.

source /usr/local/bin/pki-core

FLAG_CA_NAME=""
FLAG_KEY_TYPE=""
FLAG_KEY_PARAM=""
FLAG_DAYS=""
FLAG_DIGEST=""

FLAG_C=""
FLAG_ST=""
FLAG_L=""
FLAG_O=""
FLAG_OU=""
FLAG_EMAIL=""
SKIP_DEFAULTS="false"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ca-name)   FLAG_CA_NAME="$2"; shift 2 ;;
        --key-type)  FLAG_KEY_TYPE="$2"; shift 2 ;;
        --key-param) FLAG_KEY_PARAM="$2"; shift 2 ;;
        --days)      FLAG_DAYS="$2"; shift 2 ;;
        --digest)    FLAG_DIGEST="$2"; shift 2 ;;
        --country)   FLAG_C="$2"; shift 2 ;;
        --state)     FLAG_ST="$2"; shift 2 ;;
        --locality)  FLAG_L="$2"; shift 2 ;;
        --org)       FLAG_O="$2"; shift 2 ;;
        --ou)        FLAG_OU="$2"; shift 2 ;;
        --email)     FLAG_EMAIL="$2"; shift 2 ;;
        --no-defaults) SKIP_DEFAULTS="true"; shift 1 ;;
        --help|-h)
            echo "Usage: pki-init-root [options]"
            echo "  --ca-name <name>    Common Name (e.g., Acme Root CA)"
            echo "  --days <n>          Validity in days (default: $DEF_ROOT_DAYS)"
            echo "  --no-defaults       Leaves fields blank unless explicitly passed"
            exit 0
            ;;
        *) die "Unknown argument: $1" ;;
    esac
done

echo ""
echo -e "  ${BOLD}PKI Initialization — Root CA${NC}"
echo ""

CA_NAME="$(_prompt "${FLAG_CA_NAME:-$(_cfg root.ca_name)}" "CA Name" "Root Certificate Authority")"

if [ "$SKIP_DEFAULTS" = "true" ]; then
    C="${FLAG_C}"
    ST="${FLAG_ST}"
    L="${FLAG_L}"
    O="${FLAG_O}"
    OU="${FLAG_OU}"
    EMAIL="${FLAG_EMAIL}"
else
    C="${FLAG_C:-$(_cfg root.country "$DEF_C")}"
    ST="${FLAG_ST:-$(_cfg root.state "$DEF_ST")}"
    L="${FLAG_L:-$(_cfg root.locality "$DEF_L")}"
    O="${FLAG_O:-$(_cfg root.org "$DEF_O")}"
    OU="${FLAG_OU:-$(_cfg root.ou "$DEF_OU")}"
    EMAIL="${FLAG_EMAIL:-$(_cfg root.email "$DEF_EMAIL")}"
fi

KEY_TYPE="${FLAG_KEY_TYPE:-$(_cfg root.key_type "$DEF_KEY_TYPE")}"
KEY_PARAM="${FLAG_KEY_PARAM:-$(_cfg root.key_param "$DEF_ROOT_KEY_PARAM")}"
DAYS="${FLAG_DAYS:-$(_cfg root.days "$DEF_ROOT_DAYS")}"
DIGEST="${FLAG_DIGEST:-$(_cfg root.digest "$DEF_DIGEST")}"

mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

root_key="${OUT_DIR}/root_ca.key"
root_crt="${OUT_DIR}/root_ca.crt"

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

    local_cnf="${OUT_DIR}/_cnf_root.cnf"
    cat > "$local_cnf" <<CNFEOF
[req]
prompt = no
distinguished_name = dn
req_extensions = ext
x509_extensions = ext

[dn]
CN = ${CA_NAME}
CNFEOF

    [ -n "$C" ] && echo "C = ${C}" >> "$local_cnf"
    [ -n "$ST" ] && echo "ST = ${ST}" >> "$local_cnf"
    [ -n "$L" ] && echo "L = ${L}" >> "$local_cnf"
    [ -n "$O" ] && echo "O = ${O}" >> "$local_cnf"
    [ -n "$OU" ] && echo "OU = ${OU}" >> "$local_cnf"
    [ -n "$EMAIL" ] && echo "emailAddress = ${EMAIL}" >> "$local_cnf"

    cat >> "$local_cnf" <<CNFEOF

[ext]
basicConstraints=critical,CA:TRUE
subjectKeyIdentifier=hash
keyUsage=critical,keyCertSign,cRLSign
CNFEOF

    openssl req -new -x509 \
        -key "$root_key" \
        -out "$root_crt" \
        -days "$DAYS" \
        -"${DIGEST}" \
        -config "$local_cnf" \
        2>/dev/null
    
    rm -f "$local_cnf"
    chmod 644 "$root_crt"
    ok "Root CA certificate generated: ${root_crt}"
fi

echo ""
printf "  ${BOLD}Root CA Fingerprint:${NC} "
openssl x509 -in "$root_crt" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//'
echo ""
