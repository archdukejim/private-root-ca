#!/bin/bash
# pki-inter - Sub-CA generation and signing.

source /usr/local/bin/pki-core

NAME=""
FLAG_KEY=""
FLAG_CA_NAME=""
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
        --name)      NAME="$2"; shift 2 ;;
        --key)       FLAG_KEY="$2"; shift 2 ;;
        --ca-name)   FLAG_CA_NAME="$2"; shift 2 ;;
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
            echo "Usage: pki-inter --name <file-prefix> [options]"
            echo "  --key <path>        Use explicit/mounted private key"
            echo "  --ca-name <name>    Common Name for the cert"
            echo "  --no-defaults       Leaves fields blank unless explicitly passed"
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
    KEY_TYPE="$(_cfg intermediates.${NAME}.key_type "$DEF_KEY_TYPE")"
    KEY_PARAM="$(_cfg intermediates.${NAME}.key_param "$DEF_INT_KEY_PARAM")"
    info "Generating new intermediate key (${KEY_TYPE} ${KEY_PARAM})..."
    case "${KEY_TYPE,,}" in
        rsa) openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:${KEY_PARAM}" -out "$int_key" 2>/dev/null ;;
        ec) openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:${KEY_PARAM}" -out "$int_key" 2>/dev/null ;;
        ed25519) openssl genpkey -algorithm ed25519 -out "$int_key" 2>/dev/null ;;
    esac
    chmod 600 "$int_key"
    ok "Key generated: $int_key"
fi

CA_NAME="$(_prompt "${FLAG_CA_NAME:-$(_cfg intermediates.${NAME}.ca_name "$NAME CA")}" "CA Name" "$NAME CA")"
DAYS="${FLAG_DAYS:-$(_cfg intermediates.${NAME}.days "$DEF_INT_DAYS")}"
DIGEST="${FLAG_DIGEST:-$(_cfg intermediates.${NAME}.digest "$DEF_DIGEST")}"

if [ "$SKIP_DEFAULTS" = "true" ]; then
    C="${FLAG_C}"
    ST="${FLAG_ST}"
    L="${FLAG_L}"
    O="${FLAG_O}"
    OU="${FLAG_OU}"
    EMAIL="${FLAG_EMAIL}"
else
    C="${FLAG_C:-$(_cfg intermediates.${NAME}.country "$DEF_C")}"
    ST="${FLAG_ST:-$(_cfg intermediates.${NAME}.state "$DEF_ST")}"
    L="${FLAG_L:-$(_cfg intermediates.${NAME}.locality "$DEF_L")}"
    O="${FLAG_O:-$(_cfg intermediates.${NAME}.org "$DEF_O")}"
    OU="${FLAG_OU:-$(_cfg intermediates.${NAME}.ou "$DEF_OU")}"
    EMAIL="${FLAG_EMAIL:-$(_cfg intermediates.${NAME}.email "$DEF_EMAIL")}"
fi

info "Generating CSR..."
local_cnf="${OUT_DIR}/_csr_inter_${NAME}.cnf"
cat > "$local_cnf" <<CNFEOF
[req]
prompt = no
distinguished_name = dn

[dn]
CN = ${CA_NAME}
CNFEOF

[ -n "$C" ] && echo "C = ${C}" >> "$local_cnf"
[ -n "$ST" ] && echo "ST = ${ST}" >> "$local_cnf"
[ -n "$L" ] && echo "L = ${L}" >> "$local_cnf"
[ -n "$O" ] && echo "O = ${O}" >> "$local_cnf"
[ -n "$OU" ] && echo "OU = ${OU}" >> "$local_cnf"
[ -n "$EMAIL" ] && echo "emailAddress = ${EMAIL}" >> "$local_cnf"

openssl req -new -key "$int_key" -out "$int_csr" -"${DIGEST}" -config "$local_cnf" 2>/dev/null
rm -f "$local_cnf"
ok "CSR generated: $int_csr"

info "Signing Intermediate CA (${DAYS} days)..."
ext_conf="${OUT_DIR}/_ext_inter_${NAME}.cnf"
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
