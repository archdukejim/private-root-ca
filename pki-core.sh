#!/bin/bash
# pki-core - Sourced library for PKI scripting

set -euo pipefail

# -----------------------------------------------------------------------
# Config Paths
# -----------------------------------------------------------------------
OUT_DIR="/ca/output"
CONFIG_FILE="/ca/pki-config.json"
INT_KEYS_DIR="/ca/int-keys"

# "Production mode" limits things like creating leaf certs implicitly 
# without providing adequate parameters.
PKI_PROD_MODE="${PKI_PROD_MODE:-false}"

# Defaults according to best practices
DEF_KEY_TYPE="rsa"
DEF_ROOT_KEY_PARAM="4096"
DEF_INT_KEY_PARAM="4096"
DEF_LEAF_KEY_PARAM="2048"

DEF_ROOT_DAYS="7300"    # 20 years
DEF_INT_DAYS="3650"     # 10 years
DEF_LEAF_DAYS="365"     # 1 year
DEF_DIGEST="sha512"

# -----------------------------------------------------------------------
# Colours & Logging
# -----------------------------------------------------------------------
BOLD='\033[1m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

info()  { echo -e "  ${BOLD}[INFO]${NC}  $*"; }
ok()    { echo -e "  ${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "  ${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "  ${RED}[ERROR]${NC} $*" >&2; }
die()   { err "$*"; exit 1; }

# -----------------------------------------------------------------------
# JSON Parsing (Python3 assumed present via UBI Minimal)
# -----------------------------------------------------------------------
# Usage: _read_json "file.json" "global.cert_param" "default_val"
_read_json() {
    local file="$1" keypath="$2" default="${3:-}"
    [ -f "$file" ] || { echo "$default"; return; }
    python3 -c '
import sys, json
try:
    with open(sys.argv[1]) as f: data = json.load(f)
    keys = sys.argv[2].split(".")
    for k in keys: data = data[k]
    print(data if data is not None else sys.argv[3])
except Exception: print(sys.argv[3])
' "$file" "$keypath" "$default"
}

# Reads dot-path from /ca/pki-config.json
_cfg() {
    local keypath="$1" default="${2:-}"
    _read_json "$CONFIG_FILE" "$keypath" "$default"
}

# -----------------------------------------------------------------------
# Prompts
# -----------------------------------------------------------------------
_prompt() {
    local val="$1" label="$2" dflt="${3:-}"
    if [ -n "$val" ]; then echo "$val"; return; fi
    local input=""
    if [ -n "$dflt" ]; then
        read -rp "  ${label} [${dflt}]: " input
        echo "${input:-$dflt}"
    else
        while [ -z "$input" ]; do
            read -rp "  ${label}: " input
            [ -z "$input" ] && echo -e "  ${RED}This field is required.${NC}" >&2
        done
        echo "$input"
    fi
}

_prompt_forced() {
    local current="$1" label="$2"
    local input=""
    if [ -n "$current" ]; then
        read -rp "  ${label} [${current}]: " input
        echo "${input:-$current}"
    else
        while [ -z "$input" ]; do
            read -rp "  ${label}: " input
            [ -z "$input" ] && echo -e "  ${RED}This field is required.${NC}" >&2
        done
        echo "$input"
    fi
}
