#!/bin/bash
# modules/paramining.sh

run_paramining() {
    local target=$1
    local out=$2
    local mode="${3:-full}"
    local subs="$out/subdomains.txt"
    local mining_out="$out/parameters.txt"
    local temp_urls="$out/temp/all_urls.txt"
    local param_urls_file="$out/temp/param_urls.txt"
    local param_names_file="$out/temp/param_names.txt"
    local gowitness_targets="$out/temp/gowitness_targets.txt"
    local targets_for_mining=()

    mkdir -p "$out/temp"
    : > "$mining_out"
    : > "$temp_urls"
    : > "$param_urls_file"
    : > "$param_names_file"
    : > "$gowitness_targets"

    # --- LOAD API KEY from cfg as fallback ---
    local BASE_DIR="/home/kali/ReconVault"
    if { [ -z "$GEMINI_API_KEY" ] || [ "$GEMINI_API_KEY" == "your_gemini_key_here" ]; } \
    && { [ -z "$OPENAI_API_KEY" ] || [ "$OPENAI_API_KEY" == "your_openai_key_here" ]; }; then
       [ -f "$BASE_DIR/reconvault.cfg" ] && source "$BASE_DIR/reconvault.cfg"
    fi

    # ── DECIDE TARGETS (root first, then subs) ────────────────────
    targets_for_mining=("$target")

    if [ -s "$subs" ] && ! grep -qE "^Skipped|^Error|^No data" "$subs"; then
        log_info "Subdomain list found — mining all subdomains + root domain."
        while IFS= read -r line; do
            line="$(echo -n "$line" | tr -d '\r' | xargs)"
            [[ -z "$line" ]] && continue
            [[ "$line" =~ ^Skipped|^Error|^No[[:space:]]data ]] && continue
            targets_for_mining+=("$line")
        done < "$subs"
    else
        log_warn "No valid subdomains.txt — using root domain only."
    fi

    # Dedupe targets (preserve first-seen order)
    mapfile -t targets_for_mining < <(
        printf '%s\n' "${targets_for_mining[@]}" \
        | sed '/^$/d' \
        | awk '!seen[$0]++'
    )

    # Cap mining targets to keep it fast when subdomains explode
    local MAX_MINING_TARGETS="${MAX_MINING_TARGETS:-300}"   # tune in reconvault.cfg
    if [ "${#targets_for_mining[@]}" -gt "$MAX_MINING_TARGETS" ]; then
        log_warn "Too many targets (${#targets_for_mining[@]}). Capping to $MAX_MINING_TARGETS for speed."
        # keep root + first (MAX-1) others
        mapfile -t targets_for_mining < <(
            printf '%s\n' "${targets_for_mining[@]}" | head -n "$MAX_MINING_TARGETS"
        )
    fi

    local target_count=${#targets_for_mining[@]}
    log_info "Targets for parameter mining: $target_count (mode=$mode)"


    # ── REPORT HEADER ─────────────────────────────────────────────
    {
        echo "========================================="
        echo "  PARAMETER MINING REPORT: $target"
        echo "  Targets: $target_count | $(date '+%Y-%m-%d %H:%M:%S')"
        echo "========================================="
    } >> "$mining_out"

    # ── 1. HISTORICAL URLS (Wayback + GAU) ───────────────────────
    {
        echo -e "\n--- HISTORICAL URL DISCOVERY ---"
    } >> "$mining_out"

    local wayback_ok=false
    local gau_ok=false

    # Speed knobs (set in reconvault.cfg if you want)
    local WAYBACK_TIMEOUT="${WAYBACK_TIMEOUT:-120}"     # seconds (batched)
    local GAU_TIMEOUT="${GAU_TIMEOUT:-25}"              # seconds per domain
    local GAU_PARALLEL="${GAU_PARALLEL:-25}"            # parallel workers

    # Waybackurls supports many targets via stdin: run ONCE (huge speedup)
    if command -v waybackurls &>/dev/null; then
        wayback_ok=true
        (
            printf '%s\n' "${targets_for_mining[@]}" \
            | timeout "${WAYBACK_TIMEOUT}s" waybackurls 2>/dev/null
        ) >> "$temp_urls" &
    fi

    # GAU is per-domain: run in parallel but LIMIT concurrency (avoid 2000+ jobs)
    if command -v gau &>/dev/null; then
        gau_ok=true
        (
            printf '%s\n' "${targets_for_mining[@]}" \
            | xargs -r -n 1 -P "$GAU_PARALLEL" bash -lc \
                'timeout '"${GAU_TIMEOUT}"'s gau "$1" 2>/dev/null' _ \
            | cat
        ) >> "$temp_urls" &
    fi

    wait

    [ "$wayback_ok" = false ] && log_warn "waybackurls not found — install: go install github.com/tomnomnom/waybackurls@latest"
    [ "$gau_ok" = false ] && log_warn "gau not found — install: go install github.com/lc/gau/v2/cmd/gau@latest"

    sort -u "$temp_urls" -o "$temp_urls"

    grep '?' "$temp_urls" | sort -u > "$param_urls_file"
    grep -oP '(?<=\?|&)[^=&]+(?==)' "$temp_urls" | sed '/^$/d' | sort -u > "$param_names_file"

    if [ -s "$temp_urls" ]; then
        local url_count
        local param_url_count
        url_count=$(wc -l < "$temp_urls")
        param_url_count=$(wc -l < "$param_urls_file" 2>/dev/null || echo 0)

        log_info "Collected $url_count unique historical URLs."
        {
            echo "Collected URLs: $url_count"
            echo "Collected parameterized URLs: $param_url_count"

            echo -e "\n=== DISCOVERED PARAMETERS (by frequency) ==="
            grep -oP '(?<=\?|&)[^=&]+(?==)' "$temp_urls" \
                | sed '/^$/d' \
                | sort | uniq -c | sort -rn | head -50 \
                | awk '{printf "  %-5s hits  ->  %s\n", $1, $2}'

            echo -e "\n=== FULL URLS WITH PARAMETERS (top 50) ==="
            head -50 "$param_urls_file"
        } >> "$mining_out"
    else
        echo "  No historical URLs found." >> "$mining_out"
    fi

    # ── 2. OWASP TOP 25 (always included) ────────────────────────
    log_info "Appending OWASP Top 25 high-risk parameters..."
    {
        echo -e "\n=== OWASP TOP 25 HIGH-RISK PARAMETERS ==="
        echo "  (Always test these against discovered endpoints)"
        echo ""
        cat << 'EOF'
  id          ->  SQLi / IDOR
  url         ->  SSRF / Open Redirect
  file        ->  LFI / Path Traversal
  path        ->  LFI / Path Traversal
  page        ->  LFI / Template Injection
  redirect    ->  Open Redirect
  dest        ->  Open Redirect
  return      ->  Open Redirect
  next        ->  Open Redirect
  token       ->  Auth Bypass
  admin       ->  Privilege Escalation
  debug       ->  Info Disclosure
  config      ->  Info Disclosure
  cmd         ->  RCE / Command Injection
  exec        ->  RCE / Command Injection
  query       ->  SQLi
  search      ->  XSS / SQLi
  lang        ->  LFI
  template    ->  SSTI
  view        ->  LFI / SSRF
  dir         ->  Path Traversal
  img         ->  SSRF
  src         ->  SSRF / XSS
  callback    ->  JSONP Injection
  format      ->  Content-Type Injection
EOF
    } >> "$mining_out"

       # ── 3. AI PREDICTION (Gemini) ────────────────────────────────
    {
        echo -e "\n=== AI-PREDICTED PARAMETERS ==="
    } >> "$mining_out"

    if [[ "$mode" == "fast" ]]; then
        log_info "Fast mode: skipping AI parameter prediction."
        echo "  AI prediction skipped in fast mode." >> "$mining_out"
    else
        GEMINI_API_KEY="$(echo -n "$GEMINI_API_KEY" | tr -d '\r\n[:space:]')"
        log_info "Gemini key length: $(echo -n "$GEMINI_API_KEY" | wc -c)"

        local GEMINI_API_KEY="${GEMINI_API_KEY:-$OPENAI_API_KEY}"
        local GEMINI_MODEL="${GEMINI_MODEL:-gemini-3.1-flash-lite-preview}"
        local GEMINI_URL="https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent"

        if [ -z "$GEMINI_API_KEY" ] || [ "$GEMINI_API_KEY" == "your_gemini_key_here" ]; then
            log_warn "GEMINI_API_KEY not configured — skipping AI prediction."
            echo "  AI prediction skipped: GEMINI_API_KEY not set" >> "$mining_out"
        else
            log_info "Consulting Gemini for parameter prediction..."

            local ai_context top_params ai_prompt request_body
            local http_file resp_file http_code ai_resp prediction err_msg

            if [ "${#targets_for_mining[@]}" -gt 1 ]; then
                ai_context=$(printf '%s\n' "${targets_for_mining[@]}" | head -10 | tr '\n' ', ' | sed 's/, $//')
            else
                ai_context="$target"
            fi

            top_params=$(head -20 "$param_names_file" 2>/dev/null | tr '\n' ', ' | sed 's/, $//')

            ai_prompt="You are a web security expert. Based on these web targets: $ai_context

Observed parameter names: ${top_params:-none}

Predict 20 GET and POST parameters likely used in this application.
Return exactly 20 lines only. No heading, no markdown, no explanation.
Format each line exactly as:
param_name  ->  vulnerability_type | purpose
Focus on practical/exploitable parameters."

            request_body=$(jq -n --arg prompt "$ai_prompt" '{
                contents: [
                    { parts: [ { text: $prompt } ] }
                ],
                generationConfig: {
                    temperature: 0.4,
                    maxOutputTokens: 700
                }
            }')

            http_file="$out/temp/ai_http_code.txt"
            resp_file="$out/temp/ai_response.json"

            curl -sS --max-time 60 \
                -o "$resp_file" \
                -w "%{http_code}" \
                -X POST \
                "${GEMINI_URL}?key=${GEMINI_API_KEY}" \
                -H "Content-Type: application/json" \
                -d "$request_body" > "$http_file"

            http_code=$(cat "$http_file" 2>/dev/null)
            ai_resp=$(cat "$resp_file" 2>/dev/null)

            prediction=$(echo "$ai_resp" | jq -r '.candidates[0].content.parts[0].text // empty' 2>/dev/null)

            if [ -n "$prediction" ] && [ "$prediction" != "null" ]; then
                echo "$prediction" >> "$mining_out"

                local ai_pred_count
                ai_pred_count=$(echo "$prediction" | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')
                log_info "AI prediction complete. Predicted parameters: $ai_pred_count"
                echo "  AI predicted parameter lines: $ai_pred_count" >> "$mining_out"
            else
                err_msg=$(echo "$ai_resp" | jq -r '.error.message // .message // empty' 2>/dev/null)
                echo "  AI prediction failed (HTTP $http_code)${err_msg:+: $err_msg}" >> "$mining_out"
                echo "  Raw response: ${ai_resp:0:500}" >> "$mining_out"
                log_warn "AI prediction returned empty response."
                echo "  Debug model: $GEMINI_MODEL" >> "$mining_out"
                echo "  Debug endpoint: $GEMINI_URL" >> "$mining_out"
            fi
        fi
    fi

    # ── 4. GOWITNESS VISUAL RECON ─────────────────────────────────
    if [[ "$mode" == "fast" ]]; then
        log_info "Fast mode: skipping Gowitness visual recon."
        echo -e "\n=== VISUAL RECON ===\n  Skipped in fast mode." >> "$mining_out"
    else
        log_info "Preparing targets for Gowitness (httpx)..."
        if command -v httpx &>/dev/null && [ -s "$subs" ]; then
            timeout 60s httpx -l "$subs" -silent 2>/dev/null > "$gowitness_targets" || true
        fi

        if command -v gowitness &>/dev/null && [ -s "$gowitness_targets" ]; then
            log_info "Running Gowitness for visual recon..."
            timeout 180s gowitness scan file -f "$gowitness_targets" \
                --write-db --destination "$out/gowitness" &>/dev/null || true

            local screenshot_count
            screenshot_count=$(find "$out/gowitness" -name "*.png" 2>/dev/null | wc -l)

            {
                echo -e "\n=== VISUAL RECON ==="
                echo "  Gowitness captured $screenshot_count screenshots -> $out/gowitness/"
            } >> "$mining_out"

            log_info "Gowitness: $screenshot_count screenshots."
        else
            echo -e "\n=== VISUAL RECON ===\n  No Gowitness targets or tool missing." >> "$mining_out"
        fi
    fi


    # ── 5. EXPORTS ────────────────────────────────────────────────
    {
        echo -e "\n=== PARAMETER MINING EXPORTS ==="
        echo "  URLs with parameters  -> $param_urls_file"
        echo "  Unique parameter names -> $param_names_file"
    } >> "$mining_out"

    rm -f "$temp_urls"
    log_success "Parameter mining complete -> $mining_out"
}
