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
    local all_out="$out/subdomains_all.txt"
    local live_out="$out/subdomains_live.txt"
    local clean_out="$out/subdomains.txt"

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
    : > "$all_out"
    : > "$live_out"
    : > "$clean_out"

    log_info "Subdomain Discovery: target=$target | mode=$type | dict=$(basename "$wordlist") | limit=${user_limit}s"
    log_info "Timeouts: subfinder=${subfinder_limit}s amass=${amass_limit}s gobuster=${gobuster_limit}s"

    if [ "$type" == "passive" ]; then
        log_info "Mode: PASSIVE — running subfinder + amass passive (no brute-force)..."

        if [ -x "$SUBFINDER_BIN" ]; then
            timeout "${subfinder_limit}s" "$SUBFINDER_BIN" -d "$target" -silent >> "$raw" 2>/dev/null || true
        else
            log_warn "subfinder not found."
        fi

        if [ -x "$AMASS_BIN" ]; then
            timeout "${amass_limit}s" "$AMASS_BIN" enum -d "$target" -passive >> "$raw" 2>/dev/null || true
        else
            log_warn "amass not found — passive amass skipped."
        fi
    else
        log_info "Mode: ACTIVE — subfinder + amass + gobuster in parallel..."

        if [ -x "$SUBFINDER_BIN" ]; then
            log_info "Launching subfinder (${subfinder_limit}s)..."
            timeout "${subfinder_limit}s" "$SUBFINDER_BIN" -d "$target" -silent >> "$raw" 2>/dev/null &
        else
            log_warn "subfinder not found."
        fi

        if [ -x "$AMASS_BIN" ]; then
            log_info "Launching amass passive (${amass_limit}s)..."
            timeout "${amass_limit}s" "$AMASS_BIN" enum -d "$target" -passive >> "$raw" 2>/dev/null &
        else
            log_warn "amass not found — passive amass skipped."
        fi

        if [ -x "$GOBUSTER_BIN" ]; then
            local wl_lines
            wl_lines=$(wc -l < "$wordlist" 2>/dev/null || echo 0)
            log_info "Launching gobuster DNS brute-force (${gobuster_limit}s | wordlist: $(basename "$wordlist") | $wl_lines entries)..."
            timeout "${gobuster_limit}s" "$GOBUSTER_BIN" dns -q \
                --resolver 8.8.8.8 \
                --domain "$target" \
                -w "$wordlist" \
                -t 100 >> "$raw" 2>/dev/null &
        else
            log_warn "gobuster not found — DNS brute-force skipped."
        fi

        wait
        log_info "All discovery jobs finished. Deduplicating..."
    fi

    log_info "Raw subdomain lines collected: $(wc -l < "$raw" 2>/dev/null || echo 0)"

    if [ -s "$raw" ]; then
        sed 's/Found://g' "$raw" \
            | tr -d '\r' \
            | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
            | grep -iE "([a-zA-Z0-9-]+\.)+${target//./\\.}$" \
            | awk '{print $1}' \
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
    if command -v httpx &>/dev/null; then
        local httpx_limit="${HTTPX_TIMEOUT:-60}"

        # httpx returns full URLs; normalize to hostnames for downstream modules
        timeout "${httpx_limit}s" httpx -l "$all_out" -silent 2>/dev/null \
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




    local total count_live
    total=$(wc -l < "$all_out" 2>/dev/null || echo 0)
    count_live=$(wc -l < "$live_out" 2>/dev/null || echo 0)

    [ -f "$raw" ] && rm -f "$raw"
    log_success "Found $total subdomains, $count_live live — dict: $(basename "$wordlist") — limit=${user_limit}s"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_subdomains "$1" "$2" "$3" "$4" "$5"
fi
