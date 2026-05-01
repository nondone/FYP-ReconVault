#!/bin/bash
# modules/web.sh

run_web() {
    local target=$1
    local out_dir=$2
    local mode="${3:-full}"
    local subs_file="$out_dir/subdomains_live.txt"
    local web_output="$out_dir/web.txt"
    local temp_targets="$out_dir/temp/web_targets.txt"
    local live_urls_file="$out_dir/temp/live_urls.txt"

    mkdir -p "$out_dir/temp"
    : > "$live_urls_file"

    log_info "Starting Web Analysis for $target (mode=$mode)"

    # --- 1. TARGET SELECTION ---
    if [[ -s "$subs_file" ]] && ! grep -qE "Skipped|Error" "$subs_file"; then
        log_info "Subdomain list found — probing all targets..."
        sed -E 's#^\*\.##' "$subs_file" | tr -d '\r' | sort -u > "$temp_targets"
    else
        log_info "No subdomain list — probing main domain only."
        echo "$target" > "$temp_targets"
    fi

    local target_count
    target_count=$(wc -l < "$temp_targets")
    log_info "Probing $target_count target(s)..."

    # --- 2. HTTPX PROBE ---
    {
        echo "========================================="
        echo "  WEB SERVICES REPORT: $target"
        echo "  Targets: $target_count | $(date '+%Y-%m-%d %H:%M:%S')"
        echo "========================================="
        echo -e "\n--- LIVE WEB SERVICES ---"
    } > "$web_output"

    if command -v httpx &>/dev/null; then
        log_info "Running httpx probe (50 threads)..."
        cat "$temp_targets" | timeout 120s httpx \
            -silent -threads 50 \
            -random-agent -follow-host-redirects \
            -td -title -status-code -location \
            -web-server -content-length -cdn -no-color \
            2>/dev/null >> "$web_output"
    else
        log_warn "httpx not found — falling back to curl..."
        while read -r domain; do
            local status final_url
            final_url=$(curl -L -A "Mozilla/5.0" -o /dev/null -s \
                -w "%{url_effective}" --connect-timeout 5 "http://$domain" 2>/dev/null)
            status=$(curl -L -A "Mozilla/5.0" -o /dev/null -s \
                -w "%{http_code}" --connect-timeout 5 "http://$domain" 2>/dev/null)
            [ "$status" != "000" ] && echo "http://$domain [$status] -> $final_url" >> "$web_output"
        done < "$temp_targets"
    fi

    grep -oE '^https?://[^ ]+' "$web_output" | sort -u > "$live_urls_file"

    local live_count
    live_count=$(wc -l < "$live_urls_file" 2>/dev/null || echo 0)
    log_info "Found $live_count live web services."

    # --- 3. STATUS + REDIRECT SUMMARY ---
    {
        echo -e "\n--- HTTP STATUS SUMMARY ---"
        grep -oE '\[[0-9]{3}\]' "$web_output" | tr -d '[]' | sort | uniq -c | sort -rn \
            | awk '{printf "  %-5s -> %s responses\n", $2, $1}'

        echo -e "\n--- REDIRECT SUMMARY ---"
        grep -E '\[30[1278]\]' "$web_output" | head -20 || echo "  No notable redirects recorded."
    } >> "$web_output"

    # Fast mode stops after live discovery + summary
    if [[ "$mode" == "fast" ]]; then
        {
            echo -e "\n--- FAST MODE NOTE ---"
            echo "  Technology fingerprinting, WAF detection, common file checks,"
            echo "  header snapshots, and gf pattern matching were skipped in fast mode."
            echo -e "\n--- WEB EXPORTS ---"
            echo "  Live URLs -> $live_urls_file"
        } >> "$web_output"

        rm -f "$temp_targets"
        log_success "Web analysis complete -> web.txt ($live_count live services, fast mode)"
        return 0
    fi


    # --- 4. TECHNOLOGY FINGERPRINTING (whatweb) ---
    if command -v whatweb &>/dev/null && [[ -s "$live_urls_file" ]]; then
        log_info "Fingerprinting technologies (whatweb)..."
        {
            echo -e "\n--- TECHNOLOGY FINGERPRINT ---"
            head -20 "$live_urls_file" | while read -r url; do
                whatweb --no-errors -q "$url" 2>/dev/null
            done
        } >> "$web_output"
    fi

    # --- 5. WAF DETECTION ---
    if command -v wafw00f &>/dev/null && [[ -s "$live_urls_file" ]]; then
        log_info "Detecting WAFs..."
        {
            echo -e "\n--- WAF DETECTION ---"
            head -20 "$live_urls_file" | while read -r url; do
                local waf_res
                waf_res=$(timeout 15s wafw00f "$url" 2>/dev/null \
                    | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g")
                if echo "$waf_res" | grep -q "is behind"; then
                    echo "[WAF] $url: $(echo "$waf_res" | grep "is behind" | awk -F 'is behind ' '{print $2}')"
                else
                    echo "[---] $url: No WAF detected"
                fi
            done
        } >> "$web_output"
    fi

    # --- 6. COMMON WEB FILES ---
    if [[ -s "$live_urls_file" ]]; then
        log_info "Checking common web files..."
        {
            echo -e "\n--- COMMON WEB FILES ---"
            head -20 "$live_urls_file" | while read -r url; do
                for path in /robots.txt /.well-known/security.txt /sitemap.xml; do
                    local code
                    code=$(curl -k -L -A "Mozilla/5.0" -o /dev/null -s \
                        -w "%{http_code}" --connect-timeout 5 "${url}${path}" 2>/dev/null)
                    [ "$code" != "000" ] && echo "$url$path [$code]"
                done
            done
        } >> "$web_output"
    fi

    # --- 7. SECURITY HEADER SNAPSHOT ---
    if [[ -s "$live_urls_file" ]]; then
        log_info "Collecting header snapshots..."
        {
            echo -e "\n--- SECURITY HEADERS SNAPSHOT ---"
            head -10 "$live_urls_file" | while read -r url; do
                echo "[URL] $url"
                curl -k -I -L -A "Mozilla/5.0" --connect-timeout 5 -s "$url" 2>/dev/null \
                    | grep -Ei '^(server:|x-powered-by:|content-security-policy:|strict-transport-security:|x-frame-options:|x-content-type-options:|referrer-policy:)'
                echo ""
            done
        } >> "$web_output"
    fi

    # --- 8. VULNERABLE PARAMETER PATTERNS (gf) ---
    if command -v gf &>/dev/null && [[ -s "$web_output" ]]; then
        log_info "Checking for vulnerable parameter patterns (gf)..."
        {
            echo -e "\n--- VULNERABLE PARAMETER PATTERNS ---"
            for pattern in xss sqli ssrf lfi ssti redirect; do
                local matches
                matches=$(gf "$pattern" "$web_output" 2>/dev/null | wc -l)
                if [ "$matches" -gt 0 ]; then
                    echo "[!] $pattern — $matches potential entry point(s)"
                    gf "$pattern" "$web_output" 2>/dev/null | head -5
                fi
            done
        } >> "$web_output"
    fi

    {
        echo -e "\n--- WEB EXPORTS ---"
        echo "  Live URLs -> $live_urls_file"
    } >> "$web_output"

    rm -f "$temp_targets"
    log_success "Web analysis complete -> web.txt ($live_count live services)"
}
