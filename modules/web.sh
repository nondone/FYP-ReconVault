#!/bin/bash
# modules/web.sh

run_web() {
    local target=$1
    local out_dir=$2
    local mode="${3:-full}"
    local subs_file="$out_dir/subdomains_live.txt"
    local subs_fallback="$out_dir/subdomains.txt"
    local web_output="$out_dir/web.txt"
    local temp_targets="$out_dir/temp/web_targets.txt"
    local live_urls_file="$out_dir/temp/live_urls.txt"

    mkdir -p "$out_dir/temp"
    : > "$live_urls_file"

    log_info "Starting Web Analysis for $target (mode=$mode)"

    # --- 1. TARGET SELECTION ---
    if [[ -s "$subs_file" ]] && ! grep -qE "Skipped|Error" "$subs_file"; then
        log_info "Live subdomain list found — probing all live targets..."
        sed -E 's#^\*\.##' "$subs_file" | tr -d '\r' | sort -u > "$temp_targets"
    elif [[ -s "$subs_fallback" ]] && ! grep -qE "Skipped|Error" "$subs_fallback"; then
        log_info "Subdomain list found — probing discovered targets..."
        sed -E 's#^\*\.##' "$subs_fallback" | tr -d '\r' | sort -u > "$temp_targets"
    else
        log_info "No subdomain list — probing main domain only."
        echo "$target" > "$temp_targets"
    fi

    local target_count
    target_count=$(wc -l < "$temp_targets")
    log_info "Probing $target_count target(s)..."

    {
        echo "========================================="
        echo "  WEB SERVICES REPORT: $target"
        echo "  Targets: $target_count | $(date '+%Y-%m-%d %H:%M:%S')"
        echo "========================================="
        echo
        echo "--- LIVE WEB SERVICES ---"
        printf "%-38s %-8s %s\n" "DOMAIN" "STATUS" "REDIRECT / NOTES"
        printf "%-38s %-8s %s\n" "------" "------" "----------------"
    } > "$web_output"

    # --- 2. HTTPX PROBE ---
    if command -v httpx &>/dev/null; then
        log_info "Running httpx probe (50 threads)..."
        timeout 90s httpx \
            -l "$temp_targets" \
            -silent \
            -threads 100 \
            -random-agent \
            -status-code \
            -location \
            -no-color \
            2>/dev/null | while IFS= read -r line; do
                local url status redirect host
                url=$(echo "$line" | grep -oE '^https?://[^ ]+')
                status=$(echo "$line" | grep -oE '\[[0-9]{3}\]' | head -n1 | tr -d '[]')
                redirect=$(echo "$line" | grep -oE '\[https?://[^]]+\]|\[/[^]]*\]' | tail -n1 | sed 's/^\[//; s/\]$//')
                host=$(echo "$url" | sed -E 's#^https?://##; s#/.*$##')

                [[ -n "$url" ]] && echo "$url" >> "$live_urls_file"
                [[ -z "$host" ]] && host="$url"
                [[ -z "$status" ]] && status="-"
                [[ -z "$redirect" ]] && redirect="-"

                printf "%-38s %-8s %s\n" "$host" "$status" "$redirect"
            done >> "$web_output"
    else
        log_warn "httpx not found — falling back to curl..."
        while read -r domain; do
            local status final_url note
            final_url=$(curl -L -A "Mozilla/5.0" -o /dev/null -s -w "%{url_effective}" --connect-timeout 5 "http://$domain" 2>/dev/null)
            status=$(curl -L -A "Mozilla/5.0" -o /dev/null -s -w "%{http_code}" --connect-timeout 5 "http://$domain" 2>/dev/null)
            [[ "$status" == "000" ]] && continue
            note="-"
            [[ -n "$final_url" && "$final_url" != "http://$domain" ]] && note="$final_url"
            printf "%-38s %-8s %s\n" "$domain" "$status" "$note" >> "$web_output"
            echo "http://$domain" >> "$live_urls_file"
        done < "$temp_targets"
    fi

    sort -u "$live_urls_file" -o "$live_urls_file"

    local live_count
    live_count=$(wc -l < "$live_urls_file" 2>/dev/null || echo 0)
    log_info "Found $live_count live web services."

    # --- 3. STATUS + REDIRECT SUMMARY ---
    {
        echo
        echo "--- HTTP STATUS SUMMARY ---"
        grep -oE '[[:space:]][0-9]{3}[[:space:]]' "$web_output" \
            | tr -d ' ' \
            | sort | uniq -c | sort -rn \
            | awk '{printf "  %-5s -> %s responses\n", $2, $1}'
        echo
        echo "--- REDIRECT SUMMARY ---"
        awk '
            /^[a-zA-Z0-9._-]+[[:space:]]+(301|302|303|307|308)[[:space:]]+/ {
                printf "  %-38s -> %s\n", $1, substr($0, index($0, $3))
            }
        ' "$web_output" | head -20
    } >> "$web_output"

    # Fast mode stops after live discovery + summary
    if [[ "$mode" == "fast" ]]; then
        {
            echo
            echo "--- FAST MODE NOTE ---"
            echo "  Technology fingerprinting, WAF detection, common file checks,"
            echo "  header snapshots, and gf pattern matching were skipped in fast mode."
            echo
            echo "--- WEB EXPORTS ---"
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
            echo
            echo "--- TECHNOLOGY FINGERPRINT ---"
            while read -r url; do
                local host ww
                host=$(echo "$url" | sed -E 's#^https?://##; s#/.*$##')
                ww=$(whatweb --no-errors -q "$url" 2>/dev/null)
                [[ -n "$ww" ]] && echo "[$host] $ww"
            done < <(head -20 "$live_urls_file")
        } >> "$web_output"
    fi

    # --- 5. WAF DETECTION ---
    if command -v wafw00f &>/dev/null && [[ -s "$live_urls_file" ]]; then
        log_info "Detecting WAFs..."
        {
            echo
            echo "--- WAF DETECTION ---"
            printf "%-38s %s\n" "DOMAIN" "WAF STATUS"
            printf "%-38s %s\n" "------" "----------"
            while read -r url; do
                local host waf_res waf_note
                host=$(echo "$url" | sed -E 's#^https?://##; s#/.*$##')
                waf_res=$(timeout 15s wafw00f "$url" 2>/dev/null | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g")
                if echo "$waf_res" | grep -q "is behind"; then
                    waf_note=$(echo "$waf_res" | grep "is behind" | head -n1 | awk -F 'is behind ' '{print $2}')
                else
                    waf_note="No WAF detected"
                fi
                printf "%-38s %s\n" "$host" "$waf_note"
            done < <(head -20 "$live_urls_file")
        } >> "$web_output"
    fi

    # --- 6. COMMON WEB FILES ---
    if [[ -s "$live_urls_file" ]]; then
        log_info "Checking common web files..."
        {
            echo
            echo "--- COMMON WEB FILES ---"
            printf "%-38s %-28s %s\n" "DOMAIN" "PATH" "STATUS"
            printf "%-38s %-28s %s\n" "------" "----" "------"
            while read -r url; do
                local host
                host=$(echo "$url" | sed -E 's#^https?://##; s#/.*$##')
                for path in /robots.txt /.well-known/security.txt /sitemap.xml; do
                    local code
                    code=$(curl -k -L -A "Mozilla/5.0" -o /dev/null -s -w "%{http_code}" --connect-timeout 5 "${url}${path}" 2>/dev/null)
                    [[ "$code" != "000" ]] && printf "%-38s %-28s %s\n" "$host" "$path" "$code"
                done
            done < <(head -20 "$live_urls_file")
        } >> "$web_output"
    fi

    # --- 7. SECURITY HEADER SNAPSHOT ---
    if [[ -s "$live_urls_file" ]]; then
        log_info "Collecting header snapshots..."
        {
            echo
            echo "--- SECURITY HEADERS SNAPSHOT ---"
            while read -r url; do
                local host
                host=$(echo "$url" | sed -E 's#^https?://##; s#/.*$##')
                echo "[$host]"
                curl -k -I -L -A "Mozilla/5.0" --connect-timeout 5 -s "$url" 2>/dev/null \
                    | grep -Ei '^(server:|x-powered-by:|content-security-policy:|strict-transport-security:|x-frame-options:|x-content-type-options:|referrer-policy:)' \
                    | sed 's/^/  /'
                echo
            done < <(head -10 "$live_urls_file")
        } >> "$web_output"
    fi

    # --- 8. VULNERABLE PARAMETER PATTERNS (gf) ---
    if command -v gf &>/dev/null && [[ -s "$web_output" ]]; then
        log_info "Checking for vulnerable parameter patterns (gf)..."
        {
            echo
            echo "--- VULNERABLE PARAMETER PATTERNS ---"
            for pattern in xss sqli ssrf lfi ssti redirect; do
                local matches
                matches=$(gf "$pattern" "$web_output" 2>/dev/null | wc -l)
                if [ "$matches" -gt 0 ]; then
                    echo "[!] $pattern — $matches potential entry point(s)"
                    gf "$pattern" "$web_output" 2>/dev/null | head -5 | sed 's/^/  /'
                fi
            done
        } >> "$web_output"
    fi

    {
        echo
        echo "--- WEB EXPORTS ---"
        echo "  Live URLs -> $live_urls_file"
    } >> "$web_output"

    rm -f "$temp_targets"
    log_success "Web analysis complete -> web.txt ($live_count live services)"
}