#!/bin/bash
# modules/osint.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/utils.sh"

run_osint() {
    local target=$1
    local out=$2
    local mode=$3
    local osint_output="$out/osint.txt"
    local temp_raw="$out/temp/osint_raw.txt"

    mkdir -p "$out/temp"

    {
        echo "========================================="
        echo "  OSINT REPORT: $target"
        echo "  Mode: $mode | $(date '+%Y-%m-%d %H:%M:%S')"
        echo "========================================="
    } > "$osint_output"

    # --- SECTION A: PASSIVE (FAST & FULL) ---
    log_info "WHOIS & Registration info..."
    {
        echo -e "\n[+] WHOIS & REGISTRATION"
        whois "$target" 2>/dev/null \
            | grep -E "Registrar:|Registry Expiry Date:|Registrant Organization:|Creation Date:|Updated Date:" \
            | sed 's/^[[:space:]]*//'
    } >> "$osint_output"

    log_info "Checking mail hygiene (SPF / DMARC / DKIM)..."
    {
        echo -e "\n[+] MAIL HYGIENE"
        local spf dmarc dkim
        spf=$(dig "$target" TXT +short 2>/dev/null | grep "v=spf1")
        dmarc=$(dig "_dmarc.$target" TXT +short 2>/dev/null | grep "v=DMARC1")
        dkim=$(dig "default._domainkey.$target" TXT +short 2>/dev/null)

        [ -n "$spf"   ] && echo "SPF   : $spf"   || echo "SPF   : NOT FOUND (spoofing risk)"
        [ -n "$dmarc" ] && echo "DMARC : $dmarc" || echo "DMARC : NOT FOUND (spoofing risk)"
        [ -n "$dkim"  ] && echo "DKIM  : $dkim"  || echo "DKIM  : NOT FOUND"
    } >> "$osint_output"

    log_info "Enumerating DNS records..."
    {
        echo -e "\n[+] DNS ENUMERATION"
        for rtype in A AAAA MX NS TXT CNAME SOA; do
            local result
            result=$(dig "$target" "$rtype" +short 2>/dev/null)
            [ -n "$result" ] && echo "$rtype: $result"
        done
        # Zone transfer attempt (usually fails but worth logging)
        local ns1
        ns1=$(dig "$target" NS +short 2>/dev/null | head -1)
        if [ -n "$ns1" ]; then
            echo -e "\nZone Transfer Attempt vs $ns1:"
            dig axfr "$target" "@$ns1" 2>/dev/null | head -20 || echo "  Zone transfer denied (expected)."
        fi
    } >> "$osint_output"

    log_info "Checking for open redirects and known paths..."
    {
        echo -e "\n[+] COMMON SENSITIVE PATHS"
        for path in robots.txt sitemap.xml .well-known/security.txt crossdomain.xml; do
            local http_code
            http_code=$(curl -o /dev/null -s -w "%{http_code}" --max-time 6 "https://$target/$path")
            echo "[$http_code] https://$target/$path"
        done
    } >> "$osint_output"

    # --- SECTION B: DEEP (FULL MODE ONLY) ---
    if [ "$mode" == "full" ]; then
        log_info "Deep OSINT: theHarvester..."
        if command -v theHarvester &>/dev/null; then
            theHarvester -d "$target" -b google,bing,crtsh -l 100 > "$temp_raw" 2>&1
            {
                echo -e "\n[+] HARVESTED EMAILS"
                sed -n '/\[*\] Emails found:/,/^$/p' "$temp_raw" | grep -v "Emails found"

                echo -e "\n[+] HARVESTED HOSTS"
                sed -n '/\[*\] Hosts found:/,/^$/p' "$temp_raw" | grep -v "Hosts found"

                echo -e "\n[+] HARVESTED IPS"
                sed -n '/\[*\] IPs found:/,/^$/p' "$temp_raw" | grep -v "IPs found"
            } >> "$osint_output"
        else
            echo -e "\n[!] theHarvester not installed." >> "$osint_output"
        fi

        log_info "Cloud storage enumeration..."
        if command -v cloud_enum &>/dev/null; then
            {
                echo -e "\n[+] CLOUD STORAGE EXPOSURE (S3 / Azure / GCP)"
                cloud_enum -d "$target" -qs 2>/dev/null
            } >> "$osint_output"
        else
            echo -e "\n[!] cloud_enum not installed — skipping bucket scan." >> "$osint_output"
        fi

        log_info "GitHub repository search..."
        {
            echo -e "\n[+] GITHUB REPOSITORIES"
            curl -s --max-time 10 "https://api.github.com/search/repositories?q=$target&sort=updated&per_page=5" \
                2>/dev/null \
                | jq -r '.items[] | "\(.html_url)  [\(.stargazers_count) stars] - \(.description // "no description")"' \
                2>/dev/null \
                | head -10 \
                || echo "GitHub API unavailable or no results."
        } >> "$osint_output"

        log_info "Checking certificate transparency logs..."
        {
            echo -e "\n[+] CERTIFICATE TRANSPARENCY (crt.sh)"
            curl -s --max-time 15 "https://crt.sh/?q=%25.$target&output=json" 2>/dev/null \
                | jq -r '.[].name_value' 2>/dev/null \
                | sort -u | head -30 \
                || echo "crt.sh unavailable."
        } >> "$osint_output"

    else
        echo -e "\n[!] Deep OSINT skipped (Fast Mode)." >> "$osint_output"
    fi

    rm -f "$temp_raw"
    log_success "OSINT analysis complete."
}
