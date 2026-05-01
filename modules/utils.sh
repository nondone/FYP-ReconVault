#!/bin/bash
# modules/utils.sh

log_info()    { echo -e "[\e[34mINFO\e[0m]    $(date +%H:%M:%S) $1"; }
log_success() { echo -e "[\e[32mSUCCESS\e[0m] $(date +%H:%M:%S) $1"; }
log_error()   { echo -e "[\e[31mERROR\e[0m]   $(date +%H:%M:%S) $1"; }
log_warn()    { echo -e "[\e[33mWARN\e[0m]    $(date +%H:%M:%S) $1"; }
log_section() { echo -e "\e[35m[===] $(date +%H:%M:%S) === $1 ===\e[0m"; }

save_json() {
    local out=$1
    log_info "Packaging all results into reconvault_report.json..."

    # Ensure all expected files exist
    for file in subdomains.txt subdomains_all.txt subdomains_live.txt web.txt vulns.txt osint.txt parameters.txt hosts_detail.txt; do
        [[ ! -f "$out/$file" ]] && : > "$out/$file"
    done

    # Prefer all-subdomains for reporting, fall back to legacy file
    local sub_file="$out/subdomains_all.txt"
    [[ ! -s "$sub_file" ]] && sub_file="$out/subdomains.txt"

    # Safe integer counts — default to 0 if empty or command fails
    local sub_count web_count vuln_count osint_count param_count
    sub_count=$(grep -cvE '^\s*$|^Error|^No data|^Skipped' "$sub_file" 2>/dev/null)
    [[ ! "$sub_count" =~ ^[0-9]+$ ]] && sub_count=0

    web_count=$(grep -cvE '^\s*$|^Error|^No data|^Skipped' "$out/web.txt" 2>/dev/null)
    [[ ! "$web_count" =~ ^[0-9]+$ ]] && web_count=0

    vuln_count=$(grep -cE '\[critical\]|\[high\]|\[medium\]|\[low\]' "$out/vulns.txt" 2>/dev/null)
    [[ ! "$vuln_count" =~ ^[0-9]+$ ]] && vuln_count=0

    osint_count=$(grep -cvE '^\s*$|^=|^-|^\[!|^Skipped' "$out/osint.txt" 2>/dev/null)
    [[ ! "$osint_count" =~ ^[0-9]+$ ]] && osint_count=0

    param_count=$(grep -cvE '^\s*$|^=|^-|^Skipped' "$out/parameters.txt" 2>/dev/null)
    [[ ! "$param_count" =~ ^[0-9]+$ ]] && param_count=0

    if ! command -v jq &>/dev/null; then
        log_error "jq not found — cannot package reconvault_report.json"
        return 1
    fi

    # IMPORTANT: Use --rawfile so we don't pass huge file contents via argv (avoids 'Argument list too long').
    jq -n \
        --rawfile sub     "$sub_file" \
        --rawfile sub_all "$out/subdomains_all.txt" \
        --rawfile sub_live "$out/subdomains_live.txt" \
        --rawfile web     "$out/web.txt" \
        --rawfile vuln    "$out/vulns.txt" \
        --rawfile osint   "$out/osint.txt" \
        --rawfile params  "$out/parameters.txt" \
        --rawfile hosts   "$out/hosts_detail.txt" \
        --arg sub_count   "$sub_count" \
        --arg web_count   "$web_count" \
        --arg vuln_count  "$vuln_count" \
        --arg osint_count "$osint_count" \
        --arg param_count "$param_count" \
        '{
            subdomains:      $sub,
            subdomains_all:  $sub_all,
            subdomains_live: $sub_live,
            web:             $web,
            vulnerabilities: $vuln,
            osint:           $osint,
            parameters:      $params,
            hosts:           $hosts,
            summary: {
                subdomains_found:   ($sub_count   | tonumber),
                web_services_found: ($web_count   | tonumber),
                vuln_findings:      ($vuln_count  | tonumber),
                osint_entries:      ($osint_count | tonumber),
                parameters_found:   ($param_count | tonumber)
            }
        }' > "$out/reconvault_report.json"

    if [ $? -eq 0 ]; then
        log_success "Report generated -> $out/reconvault_report.json"
        return 0
    fi

    log_error "jq failed — saving raw fallback report."

    jq -n \
        --rawfile sub     "$sub_file" \
        --rawfile sub_all "$out/subdomains_all.txt" \
        --rawfile sub_live "$out/subdomains_live.txt" \
        --rawfile web     "$out/web.txt" \
        --rawfile vuln    "$out/vulns.txt" \
        --rawfile osint   "$out/osint.txt" \
        --rawfile params  "$out/parameters.txt" \
        --rawfile hosts   "$out/hosts_detail.txt" \
        '{
            subdomains: $sub,
            subdomains_all: $sub_all,
            subdomains_live: $sub_live,
            web: $web,
            vulnerabilities: $vuln,
            osint: $osint,
            parameters: $params,
            hosts: $hosts
        }' > "$out/reconvault_report.json"
}
