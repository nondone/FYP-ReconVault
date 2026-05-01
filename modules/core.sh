#!/bin/bash
# modules/core.sh

log() {
    local color=$1
    local msg=$2
    case $color in
        "info")    echo -e "\033[1;34m[*] $(date +%H:%M:%S) - $msg\033[0m" ;;
        "success") echo -e "\033[1;32m[+] $(date +%H:%M:%S) - $msg\033[0m" ;;
        "error")   echo -e "\033[1;31m[!] $(date +%H:%M:%S) - $msg\033[0m" ;;
        "warn")    echo -e "\033[1;33m[~] $(date +%H:%M:%S) - $msg\033[0m" ;;
        "section") echo -e "\033[1;35m[>] $(date +%H:%M:%S) - === $msg ===\033[0m" ;;
    esac
}

init_recon() {
    local target=$1
    local out_dir=$2

    log "section" "Initializing workspace for $target"
    mkdir -p "$out_dir/temp" "$out_dir/logs" "$out_dir/gowitness"

    # Create all expected output files upfront so downstream reads never fail
    for f in subdomains.txt web.txt vulns.txt osint.txt parameters.txt hosts_detail.txt; do
        touch "$out_dir/$f"
    done

    # Write a scan metadata file for reference
    {
        echo "target=$target"
        echo "start_time=$(date --iso-8601=seconds)"
        echo "out_dir=$out_dir"
    } > "$out_dir/scan_meta.txt"

    log "success" "Workspace ready at $out_dir"
}

cleanup() {
    local out_dir=$1
    log "info" "Cleaning up temporary files..."
    rm -rf "$out_dir/temp"
    rm -f "$out_dir"/*.tmp "$out_dir"/*.bak
    # Record end time into metadata
    echo "end_time=$(date --iso-8601=seconds)" >> "$out_dir/scan_meta.txt"
    log "success" "Cleanup complete."
}

# Checks if a command exists and logs a warning if missing
require_tool() {
    local tool=$1
    if ! command -v "$tool" &>/dev/null; then
        log "warn" "Tool '$tool' not found — skipping that step."
        return 1
    fi
    return 0
}

# Writes a timestamped section header into any output file
section_header() {
    local file=$1
    local title=$2
    echo -e "\n========================================" >> "$file"
    echo "  $title" >> "$file"
    echo "  $(date '+%Y-%m-%d %H:%M:%S')" >> "$file"
    echo -e "========================================\n" >> "$file"
}
