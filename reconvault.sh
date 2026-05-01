#!/bin/bash
# Path: /home/kali/ReconVault/reconvault.sh
# PATCH: Added $6 = dictionary file argument
 
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$BASE_DIR/modules"
 
if [ -f "$BASE_DIR/reconvault.cfg" ]; then
    source "$BASE_DIR/reconvault.cfg"
else
    log_info()    { echo -e "[\e[34mINFO\e[0m]    $1"; }
    log_success() { echo -e "[\e[32mSUCCESS\e[0m] $1"; }
    log_warn()    { echo -e "[\e[33mWARN\e[0m]    $1"; }
    log_error()   { echo -e "[\e[31mERROR\e[0m]   $1"; }
    log_section() { echo -e "\e[35m[===]\e[0m $1"; }
    export -f log_info log_success log_warn log_error log_section
fi

: "${SUBFINDER_TIMEOUT:=60}"
: "${AMASS_TIMEOUT:=60}"
: "${GOBUSTER_TIMEOUT:=300}"
: "${HTTPX_TIMEOUT:=60}"
: "${NUCLEI_TIMEOUT:=90}"

log_info "Core tool timeouts:"
log_info "  subfinder=${SUBFINDER_TIMEOUT}s | amass=${AMASS_TIMEOUT}s | gobuster=${GOBUSTER_TIMEOUT}s | httpx=${HTTPX_TIMEOUT}s | nuclei=${NUCLEI_TIMEOUT}s"


# Source modules (Ensure utils.sh is sourced first)
[ -f "$MODULES_DIR/utils.sh"      ] && source "$MODULES_DIR/utils.sh"      || { log_error "utils.sh missing!"; exit 1; }
[ -f "$MODULES_DIR/subdomains.sh" ] && source "$MODULES_DIR/subdomains.sh" || log_warn "subdomains.sh missing."
[ -f "$MODULES_DIR/hosts.sh"      ] && source "$MODULES_DIR/hosts.sh"      || log_warn "hosts.sh missing."
[ -f "$MODULES_DIR/web.sh"        ] && source "$MODULES_DIR/web.sh"        || log_warn "web.sh missing."
[ -f "$MODULES_DIR/vulns.sh"      ] && source "$MODULES_DIR/vulns.sh"      || log_warn "vulns.sh missing."
[ -f "$MODULES_DIR/osint.sh"      ] && source "$MODULES_DIR/osint.sh"      || log_warn "osint.sh missing."
[ -f "$MODULES_DIR/paramining.sh" ] && source "$MODULES_DIR/paramining.sh" || log_warn "paramining.sh missing."


# --- 3. INPUT HANDLING ---
TARGET_RAW=$(echo "$1" | tr -d '\r' | xargs)
MODE=$(echo "$2" | tr -d '\r' | xargs)
MODULES_LIST=$(echo "$3" | tr -d '\r' | xargs)
UNIQUE_FOLDER=$(echo "$4" | tr -d '\r' | xargs)
# --- NEW: Capture Scan Timeout from UI Settings ---
SCAN_LIMIT=$(echo "$5" | tr -d '\r' | xargs)
DICT_FILE=$(echo "$6" | tr -d '\r' | xargs)  # ← ADD THIS LINE

# Automatically strip protocol and www
TARGET=$(echo "$TARGET_RAW" | sed -e 's|^[^/]*//||' -e 's|^www\.||' -e 's|/.*$||')

[ -z "$MODE" ] && MODE="fast"
[ -z "$UNIQUE_FOLDER" ] && UNIQUE_FOLDER="$TARGET"
# Default to 300 if no limit is passed from Python
[ -z "$SCAN_LIMIT" ] && SCAN_LIMIT=300

if [ -z "$TARGET" ]; then
    echo "Usage: bash reconvault.sh <target.com> [fast|full] [modules] [unique_folder] [timeout]"
    exit 1
fi

# --- 4. PREPARE DIRECTORY ---
OUTPUT_DIR="$BASE_DIR/output/$UNIQUE_FOLDER"
mkdir -p "$OUTPUT_DIR"
# --- 5. RESET OUTPUT FILES (prevents stale data across partial module runs) ---
mkdir -p "$OUTPUT_DIR/temp"

for f in subdomains.txt subdomains_all.txt subdomains_live.txt hosts_detail.txt hosts.txt web.txt osint.txt parameters.txt vulns.txt; do
    : > "$OUTPUT_DIR/$f"
done

# --- 6. BANNER ---
log_section "ReconVault Engine Starting"

log_info "Target       : $TARGET"
log_info "Mode         : $MODE"
log_info "Modules      : ${MODULES_LIST:-all}"
log_info "Output dir   : $OUTPUT_DIR"
log_info "Timeout limit: ${SCAN_LIMIT}s"
log_info "Dictionary   : $DICT_FILE"   
check_dependencies
echo ""


# ==========================================
# SCAN LOGIC
# ==========================================

# Fast mode stops after live discovery + summary
if [ "$MODE" == "fast" ]; then
    log_info "FAST PATH: Running lightweight modules: subdomains, web, paramining, vulns."

    export MAX_MINING_TARGETS="${MAX_MINING_TARGETS:-200}"

    run_subdomains "$TARGET" "$OUTPUT_DIR" "passive" "$SCAN_LIMIT"
    run_web "$TARGET" "$OUTPUT_DIR" "fast"
    run_paramining "$TARGET" "$OUTPUT_DIR" "$MODE"
    run_vulns "$TARGET" "$OUTPUT_DIR" "fast"

    echo "Skipped in Fast Scan" > "$OUTPUT_DIR/hosts.txt"
    echo "Skipped in Fast Scan" > "$OUTPUT_DIR/osint.txt"
    echo "Skipped in Fast Scan" > "$OUTPUT_DIR/hosts_detail.txt"




elif [ "$MODE" == "full" ]; then
    log_section "FULL SCAN — Modules: $MODULES_LIST"
 
    # Subdomains
  if [[ "$MODULES_LIST" == *"subdomains"* ]]; then
        log_info "Running subdomains (active) with dict: $DICT_FILE"
        run_subdomains "$TARGET" "$OUTPUT_DIR" "active" "$SCAN_LIMIT" "$DICT_FILE"
  else
      echo "Skipped (Deselected)" > "$OUTPUT_DIR/subdomains.txt"
      echo "Skipped (Deselected)" > "$OUTPUT_DIR/subdomains_all.txt"
      echo "Skipped (Deselected)" > "$OUTPUT_DIR/subdomains_live.txt"
  fi
 
    # Hosts
    if [[ "$MODULES_LIST" == *"hosts"* ]]; then
        log_info "Running host analysis..."
        run_hosts_analysis "$TARGET" "$OUTPUT_DIR"
        # Add API enrichment
        vt_lookup "$TARGET" "$OUTPUT_DIR/hosts_detail.txt"
        TARGET_IP=$(dig +short "$TARGET" | grep -E '^[0-9.]+$' | head -1)
        [ -n "$TARGET_IP" ] && shodan_lookup "$TARGET_IP" "$OUTPUT_DIR/hosts_detail.txt"
    else
        echo "Skipped (Deselected)" > "$OUTPUT_DIR/hosts_detail.txt"
        log_warn "Hosts module skipped."
    fi
 
    # Web
    if [[ "$MODULES_LIST" == *"web"* ]]; then
        log_info "Running web analysis..."
        run_web "$TARGET" "$OUTPUT_DIR"
    else
        echo "Skipped (Deselected)" > "$OUTPUT_DIR/web.txt"
        log_warn "Web module skipped."
    fi
 
    # OSINT
    if [[ "$MODULES_LIST" == *"osint"* ]]; then
        log_info "Running OSINT (full)..."
        run_osint "$TARGET" "$OUTPUT_DIR" "full"
    else
        echo "Skipped (Deselected)" > "$OUTPUT_DIR/osint.txt"
        log_warn "OSINT module skipped."
    fi


    # Parameter Mining
    if [[ "$MODULES_LIST" == *"paramining"* ]]; then
        log_info "Running parameter mining..."
        run_paramining "$TARGET" "$OUTPUT_DIR"
    else
        echo "Skipped (Deselected)" > "$OUTPUT_DIR/parameters.txt"
        log_warn "Paramining module skipped."
    fi
 
    # Vulnerabilities
    if [[ "$MODULES_LIST" == *"vulns"* ]]; then
        log_info "Running vulnerability scan..."
        run_vulns "$TARGET" "$OUTPUT_DIR" "full"
    else
        echo "Skipped (Deselected)" > "$OUTPUT_DIR/vulns.txt"
        log_warn "Vulns module skipped."
    fi
 
else
    log_error "Unknown mode '$MODE'. Use 'fast' or 'full'."
    exit 1
fi
 
# --- 7. FINAL PACKAGING ---
log_section "Packaging all results"
save_json "$OUTPUT_DIR"
 
# Cleanup temp
rm -rf "$OUTPUT_DIR/temp"
 
log_success "[SUCCESS] Scan complete for $TARGET"
log_info "Report saved to: $OUTPUT_DIR/reconvault_report.json"
