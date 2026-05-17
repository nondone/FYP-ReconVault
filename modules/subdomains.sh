#!/bin/bash
# modules/subdomains.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DICT_DIR="$SCRIPT_DIR/dictionary"

[ -f "$SCRIPT_DIR/utils.sh" ] && source "$SCRIPT_DIR/utils.sh"
if ! command -v log_info &>/dev/null; then
    log_info()    { echo -e "[\e[34mINFO\e[0m] $1"; }
    log_success() { echo -e "[\e[32mSUCCESS\e[0m] $1"; }
    log_warn()    { echo -e "[\e[33mWARN\e[0m] $1"; }
fi

run_subdomains() {
    local SUBFINDER_BIN="/usr/bin/subfinder"
    local AMASS_BIN="/usr/bin/amass"
    local GOBUSTER_BIN="/usr/bin/gobuster"

    local target
    target=$(echo "$1" | tr -d '[:space:]' | tr -cd 'a-zA-Z0-9.-')
    local out=$2
    [[ "$out" != /* ]] && out="$SCRIPT_DIR/../$out"
    local type=$3
    local user_limit=${4:-300}
    local dict_file=${5:-"seclists_top5k.txt"}

    local subfinder_limit="${SUBFINDER_TIMEOUT:-60}"
    local amass_limit="${AMASS_TIMEOUT:-60}"
    local gobuster_limit="${GOBUSTER_TIMEOUT:-300}"

    local raw="$out/temp_subs.txt"
    local raw_passive="$out/temp_subs_passive.txt"
    local raw_bruteforce="$out/temp_subs_bruteforce.txt"
    local all_out="$out/subdomains_all.txt"
    local live_out="$out/subdomains_live.txt"
    local clean_out="$out/subdomains.txt"
    local httpx_input="$out/temp_httpx_targets.txt"

    local wordlist
    if [ -f "$DICT_DIR/$dict_file" ]; then
        wordlist="$DICT_DIR/$dict_file"
    elif [ -f "$SCRIPT_DIR/$dict_file" ]; then
        wordlist="$SCRIPT_DIR/$dict_file"
    else
        log_warn "Dictionary '$dict_file' not found in $DICT_DIR — falling back to seclists_top5k.txt"
        wordlist="$DICT_DIR/seclists_top5k.txt"
    fi

    mkdir -p "$out"
    : > "$raw"
    : > "$raw_passive"
    : > "$raw_bruteforce"
    : > "$all_out"
    : > "$live_out"
    : > "$clean_out"
    : > "$httpx_input"

    log_info "Subdomain Discovery: target=$target | mode=$type | dict=$(basename "$wordlist") | limit=${user_limit}s"
    log_info "Timeouts: subfinder=${SUBFINDER_TIMEOUT}s amass=${AMASS_TIMEOUT}s gobuster=${GOBUSTER_TIMEOUT}s httpx=${HTTPX_TIMEOUT}s nuclei=${NUCLEI_TIMEOUT}s | limit=${user_limit}s"

    if [ "$type" == "passive" ]; then
        log_info "Mode: PASSIVE — running subfinder + amass passive (no brute-force)..."

        if [ -x "$SUBFINDER_BIN" ]; then
            timeout "${subfinder_limit}s" "$SUBFINDER_BIN" -d "$target" -silent >> "$raw_passive" 2>/dev/null || true
        else
            log_warn "subfinder not found."
        fi

        if [ -x "$AMASS_BIN" ]; then
            timeout "${amass_limit}s" "$AMASS_BIN" enum -d "$target" -passive >> "$raw_passive" 2>/dev/null || true
        else
            log_warn "amass not found — passive amass skipped."
        fi
    else
        log_info "Mode: ACTIVE — dictionary brute-force only (gobuster)..."

        : > "$raw_passive"

        if [ -x "$GOBUSTER_BIN" ]; then
            local wl_lines
            wl_lines=$(wc -l < "$wordlist" 2>/dev/null || echo 0)
            log_info "Launching gobuster DNS brute-force (${gobuster_limit}s | wordlist: $(basename "$wordlist") | $wl_lines entries)..."
            timeout "${gobuster_limit}s" "$GOBUSTER_BIN" dns -q \
                --resolver 8.8.8.8 \
                --domain "$target" \
                -w "$wordlist" \
                -t 100 >> "$raw_bruteforce" 2>/dev/null || true
        else
            log_warn "gobuster not found — DNS brute-force skipped."
        fi

        if [[ -s "$raw_bruteforce" ]]; then
            log_info "Active brute-force finished. Deduplicating..."
        else
            log_warn "Gobuster returned no subdomain candidates for $target."
        fi
    fi

    # Wildcard DNS check: if a random subdomain resolves, gobuster output is likely noisy
    local wildcard_probe wildcard_hit
    wildcard_probe="rvwild-$(date +%s)-$RANDOM.$target"
    wildcard_hit=$(dig +short "$wildcard_probe" 2>/dev/null | grep -E '^[0-9.]+' | head -n1)

    if [[ -n "$wildcard_hit" && -s "$raw_bruteforce" ]]; then
        log_warn "Wildcard DNS detected for $target ($wildcard_probe -> $wildcard_hit). Ignoring gobuster brute-force results to reduce false positives."
        : > "$raw_bruteforce"
    fi

    cat "$raw_passive" "$raw_bruteforce" > "$raw"

    # Only keep gobuster brute-force results that actually resolve
    if [[ -s "$raw_bruteforce" ]]; then
        log_info "Validating gobuster brute-force candidates with DNS resolution..."
        : > "$raw"
        while IFS= read -r sub; do
            sub=$(echo "$sub" \
                | sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g' \
                | sed -E 's/Found://Ig' \
                | sed -E 's#^\*\.##' \
                | sed -E 's#^https?://##' \
                | tr -d '\r' \
                | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' \
                | awk '{print $1}' \
                | sed -E 's#/.*$##' \
                | sed -E 's/\.$//' \
                | tr '[:upper:]' '[:lower:]')

            [[ -z "$sub" ]] && continue

            if dig +short "$sub" | grep -qE '^[0-9.]+'; then
                echo "$sub" >> "$raw"
            fi
        done < "$raw_bruteforce"
    fi

    # --- 2. NORMALIZE ALL DISCOVERED SUBDOMAINS ---
    log_info "Raw subdomain lines collected: $(wc -l < "$raw" 2>/dev/null || echo 0)"

    local target_escaped
    target_escaped="${target//./\\.}"

    if [ -s "$raw" ]; then
        cat "$raw" \
            | sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g' \
            | sed -E 's/Found://Ig' \
            | sed -E 's#^\*\.##' \
            | sed -E 's#^https?://##' \
            | tr -d '\r' \
            | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' \
            | awk '{print $1}' \
            | sed -E 's#/.*$##' \
            | sed -E 's/\.$//' \
            | tr '[:upper:]' '[:lower:]' \
            | grep -Ei "^([a-z0-9_-]+\\.)+${target_escaped}$" \
            | sort -u > "$all_out"
    fi

    if [ ! -s "$all_out" ]; then
        echo "$target" >> "$all_out"
    fi

    sort -u "$all_out" -o "$all_out"
    log_info "Normalized subdomains kept: $(wc -l < "$all_out" 2>/dev/null || echo 0)"

    cp "$all_out" "$clean_out"

    # --- 3. FILTER TO LIVE WEB SUBDOMAINS (HTTPX) ---
    log_info "Filtering to live web subdomains only (httpx)..."

    : > "$live_out"

    local total
    total=$(wc -l < "$all_out" 2>/dev/null || echo 0)

    if command -v httpx &>/dev/null; then
        local httpx_limit="${HTTPX_TIMEOUT:-60}"

        # Avoid timing out on absurdly large noisy sets
        if [[ "$total" -gt 2000 ]]; then
            log_warn "Too many discovered subdomains ($total). Sampling 2000 targets randomly for live validation."
            shuf "$all_out" | head -2000 > "$httpx_input"
        else
            cp "$all_out" "$httpx_input"
        fi

        timeout "$((httpx_limit + 60))s" httpx \
            -l "$httpx_input" \
            -silent \
            -threads 100 \
            -random-agent \
            -follow-host-redirects \
            -no-color \
            2>/dev/null \
            | sed 's#https\?://##' \
            | cut -d/ -f1 \
            | tr -d '\r' \
            | sort -u > "$live_out"
    else
        log_warn "httpx not found — falling back to DNS resolution checks (dig)..."
        while IFS= read -r sub; do
            sub=$(echo "$sub" | tr -d '\r' | xargs)
            [[ -z "$sub" ]] && continue
            if dig +short "$sub" | grep -qE '^[0-9.]+'; then
                printf '%s\n' "$sub" >> "$live_out"
            fi
        done < "$all_out"
    fi

    local count_live
    count_live=$(wc -l < "$live_out" 2>/dev/null || echo 0)

    rm -f "$raw" "$raw_passive" "$raw_bruteforce" "$httpx_input"
    log_success "Found $total subdomains, $count_live live — dict: $(basename "$wordlist") — limit=${user_limit}s"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_subdomains "$1" "$2" "$3" "$4" "$5"
fi