#!/bin/bash
# modules/vulns.sh

append_owasp_mapping() {
    local vulns_output="$1"
    local detected=0

    echo -e "\n[+] OWASP TOP 10 MAPPING" >> "$vulns_output"

    # Keep only likely-positive evidence lines
    local evidence
    evidence=$(
        grep -Eiv \
            '^\[\+\]|^=+|scan summary|owasp top 10 mapping|skipped in fast mode|timed out|no .*found|no .*candidates|target unreachable|^  no |testssl \[options\]|single check as <options>|tuning / connect options|output options|file output options|<URI> always needs to be the last parameter' \
            "$vulns_output" \
        | tr -d '\r'
    )

    has_match() {
        local re="$1"
        echo "$evidence" | grep -Eiq "$re"
    }

    # A01 Broken Access Control
    if has_match '(403[[:space:]-]*bypass.*(success|vulnerable|found))|(forbidden[[:space:]-]*bypass.*(success|found))|(access[[:space:]-]*control.*(bypass|vulnerable|weak))'; then
        echo "[OWASP:A01:2021] Broken Access Control -> Access-control bypass indicators detected." >> "$vulns_output"
        detected=1
    fi

    # A02 Cryptographic Failures
    if has_match '(weak|deprecated|insecure).*(ssl|tls|cipher)|(sslv2|sslv3|tls1\.0|tls1\.1)|(expired certificate|self-signed|heartbleed)'; then
        echo "[OWASP:A02:2021] Cryptographic Failures -> Weak/legacy TLS or certificate issues detected." >> "$vulns_output"
        detected=1
    fi

    # A03 Injection
    if has_match '(sql injection|sqli|xss|cross-site scripting|ssti|command injection).*(found|detected|vulnerable)|parameter.*(vulnerable|injectable)|title:.*(sql|xss|ssti|inject)'; then
        echo "[OWASP:A03:2021] Injection -> SQLi/XSS/SSTI/Command Injection indicators detected." >> "$vulns_output"
        detected=1
    fi

    # A05 Security Misconfiguration
    if has_match '(directory listing|misconfig|security misconfiguration|default config|exposure|subdomain takeover|takeover candidate)'; then
        echo "[OWASP:A05:2021] Security Misconfiguration -> Misconfiguration/exposure/takeover indicators detected." >> "$vulns_output"
        detected=1
    fi

    # A06 Vulnerable and Outdated Components
    if has_match '(cve-[0-9]{4}-[0-9]+)|(outdated component|vulnerable library|known vulnerability|severity[: ]*(critical|high|medium))'; then
        echo "[OWASP:A06:2021] Vulnerable and Outdated Components -> CVE/component vulnerability indicators detected." >> "$vulns_output"
        detected=1
    fi

    # A10 SSRF
    if has_match '(^|[^a-z])ssrf([^a-z]|$)|server[- ]side request forgery'; then
        echo "[OWASP:A10:2021] Server-Side Request Forgery (SSRF) -> SSRF indicators detected." >> "$vulns_output"
        detected=1
    fi

    if [[ "$detected" -eq 0 ]]; then
        echo "[OWASP] No direct OWASP Top 10 mapping identified from current positive findings." >> "$vulns_output"
    fi
}

tidy_vulns_output() {
    local file="$1"
    local tmp="${file}.tidy"

    awk '
    BEGIN { blank=0 }
    {
        gsub(/\r/, "", $0)
        gsub(/\x1B\[[0-9;]*[A-Za-z]/, "", $0)
        sub(/[ \t]+$/, "", $0)

        if ($0 ~ /^[[:space:]]*$/) {
            if (blank == 0) print ""
            blank = 1
            next
        }
        blank = 0

        if ($0 ~ /^\[\+\]/) {
            print "-----------------------------------------"
            print $0
            next
        }

        if ($0 ~ /^=+/ || $0 ~ /^\[OWASP/ || $0 ~ /^  SCAN SUMMARY/ || $0 ~ /^  Critical\/High/ || $0 ~ /^  Medium/ || $0 ~ /^  Live targets/ || $0 ~ /^  Param targets/) {
            print $0
            next
        }

        # Drop especially noisy raw tool lines
        if ($0 ~ /NOMORE403|AUTO-CALIBRATION RESULTS|DEFAULT REQUEST|VERB TAMPERING|HEADERS|CUSTOM PATHS|DOUBLE-ENCODING|UNICODE ENCODING|HTTP VERSIONS|PATH CASE SWITCHING|Further IP addresses|rDNS|vipd-healthcheck/) {
            next
        }

        if (length($0) > 220) {
            print "  " substr($0, 1, 220) " ..."
            next
        }

        print "  " $0
    }' "$file" > "$tmp"

    mv "$tmp" "$file"
}

run_vulns() {
    local target=$1
    local out_dir=$2
    local mode=$3
    local subdomain_file="$out_dir/subdomains.txt"
    local vuln_targets_raw="$out_dir/temp/vuln_targets_raw.txt"
    local vuln_targets="$out_dir/temp/vuln_targets.txt"
    local param_targets="$out_dir/temp/param_targets.txt"
    local vulns_output="$out_dir/vulns.txt"
    local ai_params_file="$out_dir/temp/ai_params.txt"

    mkdir -p "$out_dir/temp"
    : > "$ai_params_file"

    log_info "Starting Vulnerability Scanning for $target (mode=$mode)"
    {
        echo "========================================="
        echo "  VULNERABILITY REPORT: $target"
        echo "  Mode: $mode | $(date '+%Y-%m-%d %H:%M:%S')"
        echo "========================================="
    } > "$vulns_output"

    [[ ! $target =~ ^http ]] && target="http://$target"

    local target_host
    target_host="${target#http://}"
    target_host="${target_host#https://}"
    target_host="${target_host%%/*}"

    # --- 1. PREPARE TARGET LIST ---
    # Fast mode stays focused on the main target only.
    # Full mode expands scope to discovered subdomains when available.
    if [[ "$mode" == "fast" ]]; then
        echo "$target" > "$vuln_targets_raw"
    else
        if [[ -s "$subdomain_file" ]] && ! grep -q "Skipped\|Error" "$subdomain_file"; then
            awk '{print "http://"$1}' "$subdomain_file" | tr -d '\r' | sort -u > "$vuln_targets_raw"
        else
            echo "$target" > "$vuln_targets_raw"
        fi
    fi

    # --- 2. FILTER TO LIVE WEB TARGETS USING HTTPX ---
    # This avoids wasting scanner time on dead or unreachable hosts.
    if command -v httpx &>/dev/null; then
        log_info "Filtering live web targets with httpx..."
        timeout "${httpx_limit}s" httpx \
            -l "$vuln_targets_raw" \
            -silent \
            -threads 40 \
            -rate-limit 80 \
            -mc 200,201,202,203,204,301,302,307,308,401,403 \
            > "$vuln_targets" 2>/dev/null

        if [[ ! -s "$vuln_targets" ]]; then
            echo "$target" > "$vuln_targets"
        fi
    else
        cp "$vuln_targets_raw" "$vuln_targets"
    fi

    local target_count
    target_count=$(wc -l < "$vuln_targets")

    # --- 3. BUILD PARAMETERIZED TARGET LIST ---
    # Reuse mined parameter URLs first, then optionally synthesize test URLs
    # from AI-predicted parameter names.
    : > "$param_targets"

    if [[ -s "$out_dir/parameters.txt" ]]; then
        grep '=' "$out_dir/parameters.txt" | tr -d '\r' | sort -u > "$param_targets" 2>/dev/null || true
    else
        grep '=' "$vuln_targets" | tr -d '\r' | sort -u > "$param_targets" 2>/dev/null || true
    fi

    # --- 3b. EXTRACT AI-PREDICTED PARAMETER NAMES ---
    if [[ -s "$out_dir/parameters.txt" ]]; then
        awk '
            BEGIN{in_ai=0}
            /=== AI-PREDICTED PARAMETERS ===/{in_ai=1; next}
            /^===/{if(in_ai){exit}}
            in_ai && /->/ {
                p=$1
                gsub(/[^a-zA-Z0-9_.-]/, "", p)
                if(length(p)>0) print p
            }
        ' "$out_dir/parameters.txt" | sort -u > "$ai_params_file" 2>/dev/null || true
    fi

    # --- 3c. BUILD SYNTHETIC PARAMETER TEST URLS ---
    if [[ -s "$ai_params_file" && -s "$vuln_targets" ]]; then
        while IFS= read -r base; do
            [[ -z "$base" ]] && continue
            while IFS= read -r p; do
                [[ -z "$p" ]] && continue
                echo "${base}?${p}=test"
            done < "$ai_params_file"
        done < "$vuln_targets" >> "$param_targets"
    fi

    sort -u "$param_targets" -o "$param_targets"

    local param_count
    param_count=$(wc -l < "$param_targets" 2>/dev/null || echo 0)

    log_info "Scanning $target_count live target(s)..."
    log_info "Found $param_count parameterized target(s)..."

    local nuclei_tmp="$out_dir/temp/nuclei.txt"
    local sqlmap_tmp="$out_dir/temp/sqlmap.txt"
    local dalfox_tmp="$out_dir/temp/dalfox.txt"
    local tinja_tmp="$out_dir/temp/tinja.txt"
    local testssl_tmp="$out_dir/temp/testssl.txt"
    local commix_tmp="$out_dir/temp/commix.txt"
    local nomore403_tmp="$out_dir/temp/nomore403.txt"
    local subzy_tmp="$out_dir/temp/subzy.txt"

    : > "$nuclei_tmp"
    : > "$sqlmap_tmp"
    : > "$dalfox_tmp"
    : > "$tinja_tmp"
    : > "$testssl_tmp"
    : > "$commix_tmp"
    : > "$nomore403_tmp"
    : > "$subzy_tmp"

    # --- 4. RUN SCANNERS ---
    # Fast mode runs lightweight Nuclei only.
    # Full mode adds deeper checks in parallel.
     if command -v nuclei &>/dev/null; then
        (
            if [[ "$mode" == "fast" ]]; then
                log_info "Running lightweight Nuclei scan (${nuclei_limit}s)..."
                {
                    echo -e "\n[+] NUCLEI - LIGHTWEIGHT FINDINGS"
                    timeout "${nuclei_limit}s" nuclei \
                        -l "$vuln_targets" \
                        -tags cve,vuln,misconfig,exposure \
                        -severity critical,high,medium \
                        -silent -ni -nc \
                        -rate-limit 40 \
                        -bulk-size 10 \
                        -c 10 \
                        2>/dev/null || echo "  Nuclei timed out or no findings."
                } >> "$nuclei_tmp"
            else
                log_info "Running Nuclei (CVE + DAST) (${nuclei_limit}s)..."
                {
                    echo -e "\n[+] NUCLEI - CVE & DAST FINDINGS"
                    timeout "${nuclei_limit}s" nuclei \
                        -l "$vuln_targets" \
                        -tags cve,dast,vuln,misconfig,exposure \
                        -severity critical,high,medium \
                        -silent -ni -nc \
                        -rate-limit 80 \
                        -bulk-size 20 \
                        -c 25 \
                        2>/dev/null || echo "  Nuclei timed out or no findings."
                } >> "$nuclei_tmp"
            fi
        ) &
    else
        log_warn "nuclei not installed - skipping."
    fi

    if [[ "$mode" == "full" ]]; then
        if command -v dalfox &>/dev/null; then
            (
                log_info "Scanning for XSS (Dalfox)..."
                {
                    echo -e "\n[+] XSS (Dalfox)"
                    if [[ -s "$param_targets" ]]; then
                        local first_param_target
                        first_param_target=$(head -n 1 "$param_targets")
                        timeout 45s dalfox url "$first_param_target" \
                            --silence \
                            --skip-bav \
                            --no-color \
                            2>/dev/null || echo "  No XSS found or timed out."
                    else
                        echo "  No parameterized URLs found. Skipping Dalfox."
                    fi
                } >> "$dalfox_tmp"
            ) &
        else
            log_warn "dalfox not installed - skipping."
        fi

        if command -v tinja &>/dev/null; then
            (
                log_info "Checking for SSTI (TInjA)..."
                {
                    echo -e "\n[+] SSTI (TInjA)"
                    timeout 45s tinja url -u "$target" -silent \
                        2>/dev/null || echo "  No SSTI found or timed out."
                } >> "$tinja_tmp"
            ) &
        else
            log_warn "tinja not installed - skipping."
        fi

        if command -v testssl &>/dev/null; then
            (
                log_info "Checking SSL/TLS security..."
                {
                    echo -e "\n[+] SSL/TLS REPORT"
                    timeout 60s testssl --quiet --severity MEDIUM --color 0 "$target_host" \
                        2>/dev/null || echo "  testssl timed out or target unreachable."
                } >> "$testssl_tmp"
            ) &
        else
            log_warn "testssl not installed - skipping."
        fi

        if command -v nomore403 &>/dev/null; then
            (
                log_info "Attempting 403 bypass (nomore403)..."
                {
                    echo -e "\n[+] 403 BYPASS ATTEMPTS"
                    timeout 30s nomore403 -u "$target" \
                        2>/dev/null || echo "  No bypass found or timed out."
                } >> "$nomore403_tmp"
            ) &
        else
            log_warn "nomore403 not installed - skipping."
        fi

        if command -v subzy &>/dev/null && [[ -s "$subdomain_file" ]]; then
            (
                log_info "Checking for subdomain takeover (subzy)..."
                {
                    echo -e "\n[+] SUBDOMAIN TAKEOVER"
                    timeout 45s subzy run \
                        --targets "$subdomain_file" \
                        --hide-fails \
                        --concurrency 40 \
                        2>/dev/null || echo "  No takeover candidates found or timed out."
                } >> "$subzy_tmp"
            ) &
        fi

        if command -v sqlmap &>/dev/null; then
            (
                log_info "Checking SQL Injection on parameterized targets..."
                {
                    echo -e "\n[+] SQL INJECTION (SQLMap)"
                    if [[ -s "$param_targets" ]]; then
                        local first_param_target
                        first_param_target=$(head -n 1 "$param_targets")
                        timeout 60s sqlmap \
                            -u "$first_param_target" \
                            --batch \
                            --random-agent \
                            --level=1 \
                            --risk=1 \
                            --threads=4 \
                            --smart \
                            2>/dev/null | grep -E "Parameter|Type:|Title:|injected|vulnerable" \
                            || echo "  No SQL injection found or timed out."
                    else
                        echo "  No parameterized URLs found. Skipping SQLMap."
                    fi
                } >> "$sqlmap_tmp"
            ) &
        else
            log_warn "sqlmap not installed - skipping."
        fi

        if command -v commix &>/dev/null; then
            (
                log_info "Checking for Command Injection (Commix)..."
                {
                    echo -e "\n[+] COMMAND INJECTION (Commix)"
                    if [[ -s "$param_targets" ]]; then
                        local first_param_target
                        first_param_target=$(head -n 1 "$param_targets")
                        timeout 45s commix --url="$first_param_target" --batch \
                            2>/dev/null | grep -E "vulnerable|injected|payload" \
                            || echo "  No command injection found or timed out."
                    else
                        echo "  No parameterized URLs found. Skipping Commix."
                    fi
                } >> "$commix_tmp"
            ) &
        else
            log_warn "commix not installed - skipping."
        fi
    else
        echo -e "\n[+] XSS (Dalfox)\n  Skipped in fast mode." >> "$dalfox_tmp"
        echo -e "\n[+] SSTI (TInjA)\n  Skipped in fast mode." >> "$tinja_tmp"
        echo -e "\n[+] SSL/TLS REPORT\n  Skipped in fast mode." >> "$testssl_tmp"
        echo -e "\n[+] 403 BYPASS ATTEMPTS\n  Skipped in fast mode." >> "$nomore403_tmp"
        echo -e "\n[+] SUBDOMAIN TAKEOVER\n  Skipped in fast mode." >> "$subzy_tmp"
        echo -e "\n[+] SQL INJECTION (SQLMap)\n  Skipped in fast mode." >> "$sqlmap_tmp"
        echo -e "\n[+] COMMAND INJECTION (Commix)\n  Skipped in fast mode." >> "$commix_tmp"
    fi

    wait

    # --- 5. MERGE TOOL OUTPUTS ---
    cat \
        "$nuclei_tmp" \
        "$sqlmap_tmp" \
        "$dalfox_tmp" \
        "$tinja_tmp" \
        "$testssl_tmp" \
        "$commix_tmp" \
        "$nomore403_tmp" \
        "$subzy_tmp" >> "$vulns_output"

    # --- 6. APPEND OWASP MAPPING ---
    append_owasp_mapping "$vulns_output"

    # --- 7. WRITE SUMMARY BLOCK ---
    local critical_high_count medium_count
    critical_high_count=$(grep -cE '\[critical\]|\[high\]' "$vulns_output" 2>/dev/null || true)
    medium_count=$(grep -c '\[medium\]' "$vulns_output" 2>/dev/null || true)

    {
        echo -e "\n========================================="
        echo "  SCAN SUMMARY"
        echo "  Critical/High findings: ${critical_high_count:-0}"
        echo "  Medium findings       : ${medium_count:-0}"
        echo "  Live targets scanned  : $target_count"
        echo "  Param targets found   : $param_count"
        echo "========================================="
    } >> "$vulns_output"

    # --- 8. TIDY FINAL OUTPUT ---
    tidy_vulns_output "$vulns_output"

    rm -f \
        "$vuln_targets_raw" \
        "$vuln_targets" \
        "$param_targets" \
        "$nuclei_tmp" \
        "$sqlmap_tmp" \
        "$dalfox_tmp" \
        "$tinja_tmp" \
        "$testssl_tmp" \
        "$commix_tmp" \
        "$nomore403_tmp" \
        "$subzy_tmp" \
        "$ai_params_file"

    log_success "Vulnerability scan complete for $target."
}
