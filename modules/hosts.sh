#!/bin/bash
# Path: /home/kali/ReconVault/modules/hosts.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECON_HOME="/home/kali/ReconVault"

if [ -f "$SCRIPT_DIR/utils.sh" ]; then
    source "$SCRIPT_DIR/utils.sh"
elif [ -f "$RECON_HOME/modules/utils.sh" ]; then
    source "$RECON_HOME/modules/utils.sh"
else
    log_info()    { echo -e "[\e[34mINFO\e[0m] $1"; }
    log_error()   { echo -e "[\e[31mERROR\e[0m] $1"; }
    log_success() { echo -e "[\e[32mSUCCESS\e[0m] $1"; }
    log_warn()    { echo -e "[\e[33mWARN\e[0m] $1"; }
fi

run_hosts_analysis() {
    local target=$1
    local out=$2
    local host_file="$out/hosts_detail.txt"

    mkdir -p "$out/temp"

    log_info "Resolving IP for $target..."
    local target_ip
    target_ip=$(dig +short "$target" | grep -E '^[0-9.]+$' | head -n1)

    if [ -z "$target_ip" ]; then
        log_error "Could not resolve IP for $target. Skipping host analysis."
        echo "Error: DNS Resolution failed for $target" > "$host_file"
        return 1
    fi
    log_info "Resolved: $target -> $target_ip"

    # Reverse DNS
    log_info "Performing reverse DNS lookup..."
    local rdns
    rdns=$(dig +short -x "$target_ip" 2>/dev/null | sed 's/\.$//')
    [ -z "$rdns" ] && rdns="No reverse DNS record found"

    # ASN & Geolocation
    log_info "Looking up ASN and network ownership..."
    local asn_info
    asn_info=$(curl -s --max-time 10 "https://ipinfo.io/$target_ip/json" 2>/dev/null)

    # WAF/CDN
    log_info "Detecting WAF/CDN..."
    if command -v wafw00f &>/dev/null; then
        wafw00f "$target" > "$out/temp/waf.txt" 2>&1
    else
        echo "wafw00f not installed." > "$out/temp/waf.txt"
    fi

    # Port scan
    log_info "Scanning ports (Top 100)..."
    if command -v nmap &>/dev/null; then
        nmap -sV -T4 -Pn --top-ports 100 --open "$target_ip" -oN "$out/temp/nmap.txt" &>/dev/null
    else
        echo "nmap not installed." > "$out/temp/nmap.txt"
    fi

    # SSL cert
    log_info "Extracting SSL certificate details..."
    local ssl_info
    ssl_info=$(echo | timeout 10 openssl s_client -connect "$target:443" -servername "$target" 2>/dev/null \
        | openssl x509 -noout -subject -issuer -dates 2>/dev/null)
    [ -z "$ssl_info" ] && ssl_info="SSL cert unavailable or port 443 not open."

    # DNS records
    log_info "Enumerating DNS records..."
    local a_records mx_records ns_records txt_records
    a_records=$(dig +short A "$target" 2>/dev/null | tr '\n' ' ')
    mx_records=$(dig +short MX "$target" 2>/dev/null | tr '\n' ', ' | sed 's/, $//')
    ns_records=$(dig +short NS "$target" 2>/dev/null | tr '\n' ', ' | sed 's/, $//')
    txt_records=$(dig +short TXT "$target" 2>/dev/null | head -5)

    # Write report
    {
        echo "========================================="
        echo "  HOST INFRASTRUCTURE REPORT: $target"
        echo "  Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "========================================="

        echo -e "\n--- RESOLUTION ---"
        echo "Primary IP   : $target_ip"
        echo "Reverse DNS  : $rdns"

        echo -e "\n--- GEOLOCATION & NETWORK ---"
        if [ -n "$asn_info" ]; then
            echo "$asn_info" | jq -r '"City       : " + (.city // "N/A") +
                "\nRegion     : " + (.region // "N/A") +
                "\nCountry    : " + (.country // "N/A") +
                "\nOrg/ASN    : " + (.org // "N/A") +
                "\nHostname   : " + (.hostname // "N/A")' 2>/dev/null || echo "$asn_info"
        else
            echo "Geolocation data unavailable."
        fi

        echo -e "\n--- DNS RECORDS ---"
        echo "A Records    : ${a_records:-none}"
        echo "MX Records   : ${mx_records:-none}"
        echo "NS Records   : ${ns_records:-none}"
        echo -e "TXT Records  :\n${txt_records:-none}"

        echo -e "\n--- SSL/TLS CERTIFICATE ---"
        echo "$ssl_info"

        echo -e "\n--- WAF / CDN STATUS ---"
        if grep -qi "is behind" "$out/temp/waf.txt" 2>/dev/null; then
            grep -i "is behind" "$out/temp/waf.txt" | head -n3
        else
            echo "No WAF/CDN detected or target unreachable."
        fi

        echo -e "\n--- OPEN SERVICES (Nmap Top 100) ---"
        if grep -q "open" "$out/temp/nmap.txt" 2>/dev/null; then
            grep "open" "$out/temp/nmap.txt"
        else
            echo "No open ports found in top 100."
        fi

    } > "$host_file"

    rm -f "$out/temp/waf.txt" "$out/temp/nmap.txt"
    log_success "Host analysis complete -> hosts_detail.txt"
}
