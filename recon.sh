#!/bin/bash

# --- Configuration & Banner ---
FINAL_OUTPUT="all_subdomains.txt"
WILDCARD_OUTPUT="wildcard_domains.txt" 
EXCLUDE_LIST=""
RUN_HTTPX=false 

# Colors
RED="\e[31m"
GREEN="\e[32m"
BOLD="\e[1m"
BLUE="\e[34m"
YELLOW="\e[33m"
END="\e[0m"

echo -e "${BOLD}${GREEN}"
echo "    ULTIMATE RECON TOOL (Merged Edition)"
echo "    Integrates Logic from SubEnum & Recon"
echo "    + Advanced Right-to-Left Wildcard Engine"
echo -e "${END}"

# --- Safety Trap ---
trap "rm -f temp_*.txt wildcard_temp_*.txt temp_matches.txt active_patterns.tmp next_wildcards.tmp temp_pending_wildcards.tmp processed_tracking_list.tmp; echo -e '\n${RED}[!] Interrupted. Temp files cleaned.${END}'; exit" INT TERM

# --- Helper Functions ---

# Check if a tool should be skipped
should_run() {
    local tool_name=$1
    if [[ ",$EXCLUDE_LIST," == *",$tool_name,"* ]]; then
        echo -e "${RED}[-] Skipping $tool_name (Excluded)${END}"
        return 1
    fi
    return 0
}

# --- Tool Processing Functions ---

run_subfinder() {
    should_run "Subfinder" || return
    local domain=$1
    if command -v subfinder &> /dev/null; then
        echo -e "${BOLD}[*] Running Subfinder...${END}"
        subfinder -d "$domain" --all --recursive -o temp_subfinder.txt > /dev/null 2>&1
    fi
}

run_assetfinder() {
    should_run "Assetfinder" || return
    local domain=$1
    if command -v assetfinder &> /dev/null; then
        echo -e "${BOLD}[*] Running Assetfinder...${END}"
        assetfinder --subs-only "$domain" > temp_assetfinder.txt
    fi
}

run_findomain() {
    should_run "Findomain" || return
    local domain=$1
    if command -v findomain &> /dev/null; then
        echo -e "${BOLD}[*] Running Findomain...${END}"
        findomain -t "$domain" -q 2>/dev/null > temp_findomain.txt
    fi
}

run_amass() {
    should_run "Amass" || return
    local domain=$1
    if command -v amass &> /dev/null; then
        echo -e "${BOLD}[*] Running Amass (Passive)...${END}"
        amass enum -passive -norecursive -noalts -d "$domain" 1> temp_amass.txt 2>/dev/null
    fi
}

run_crtsh() {
    should_run "crt" || return
    local domain=$1
    echo -e "${BOLD}[*] Fetching from crt.sh...${END}"
    curl -sk "https://crt.sh/?q=%.$domain&output=json" | tr ',' '\n' | awk -F'"' '/name_value/ {gsub(/\*\./, "", $4); gsub(/\\n/,"\n",$4);print $4}' | sort -u > temp_crt.txt
}

run_wayback() {
    should_run "wayback" || return
    local domain=$1
    echo -e "${BOLD}[*] Fetching from Wayback Machine...${END}"
    curl -sk "http://web.archive.org/cdx/search/cdx?url=*.$domain&output=txt&fl=original&collapse=urlkey&page=" | awk -F/ '{gsub(/:.*/, "", $3); print $3}' | sort -u > temp_wayback.txt
}

run_abuseipdb() {
    should_run "abuseipdb" || return
    local domain=$1
    echo -e "${BOLD}[*] Fetching from AbuseIPDB...${END}"
    curl -s "https://www.abuseipdb.com/whois/$domain" -H "user-agent: firefox" -b "abuseipdb_session=" | grep -E '<li>\w.*</li>' | sed -E 's/<\/?li>//g' | sed -e "s/$/.$domain/" | sed 's/^[[:space:]]*//' | sort -u > temp_abuseipdb.txt
}

run_alienvault() {
    should_run "AlienVault" || return
    local domain=$1
    echo -e "${BOLD}[*] Fetching from AlienVault...${END}"
    curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/$domain/passive_dns" | jq -r '.passive_dns[]?.hostname' | grep -E "^[a-zA-Z0-9.-]+\.$domain$" > temp_alienvault.txt
}

run_urlscan() {
    should_run "urlscan" || return
    local domain=$1
    echo -e "${BOLD}[*] Fetching from UrlScan...${END}"
    curl -s "https://urlscan.io/api/v1/search/?q=domain:$domain&size=10000" | jq -r '.results[]?.page?.domain' | grep -E "^[a-zA-Z0-9.-]+\.$domain$" > temp_urlscan.txt
}

run_chaos() {
    should_run "chaos" || return
    
    # Check if PDCP_API_KEY is exported/set
    if [[ -z "$PDCP_API_KEY" ]]; then
        return
    fi

    local domain=$1
    if command -v chaos &> /dev/null; then
        echo -e "${BOLD}[*] Running chaos...${END}"
        chaos -d "$domain" -silent > temp_chaos.txt 2>/dev/null
    fi
}


# --- Main Processing Logic ---

process_domain() {
    local domain=$1
    echo "------------------------------------------------"
    echo -e "${GREEN}Processing domain: $domain${END}"

    # 1. Run all tools (Checks exclusion internally)
    run_subfinder "$domain"
    run_assetfinder "$domain"
    run_findomain "$domain"
    run_amass "$domain"
    run_crtsh "$domain"
    run_wayback "$domain"
    run_abuseipdb "$domain"
    run_alienvault "$domain"
    run_urlscan "$domain"
    run_chaos "$domain"

    # 2. Merge Results
    echo "Merging results for $domain into $FINAL_OUTPUT..."
    
    # Ensure the input domain itself is in the list
    echo "$domain" | anew "$FINAL_OUTPUT"

    # Concatenate all temp files, suppress errors
    # Filter: Ensure lines contain at least one dot to be considered a domain/FQDN
    cat temp_*.txt 2>/dev/null | awk 'NF' | grep -F "." | anew "$FINAL_OUTPUT"

    # 3. Cleanup for this domain
    rm -f temp_*.txt
}

# --- Initialization & Arguments ---

domains=()

while getopts "l:d:e:rh" opt; do
    case $opt in
        l)
            if [[ -f $OPTARG ]]; then
                while IFS= read -r line; do
                    line=$(echo "$line" | xargs) # Trim whitespace
                    [[ -z "$line" ]] && continue
                    
                    if [[ "$line" == *"*"* ]]; then
                        # Send complex wildcards directly to the new engine
                        echo "$line" | anew "$WILDCARD_OUTPUT"
                        echo "$line" >> temp_pending_wildcards.tmp
                    else
                        domains+=("$line")
                    fi
                done < "$OPTARG"
            else
                echo "Error: File $OPTARG not found."
                exit 1
            fi
            ;;
        d)
            input_domain=$OPTARG
            if [[ "$input_domain" == *"*"* ]]; then
                echo "$input_domain" | anew "$WILDCARD_OUTPUT"
                echo "$input_domain" >> temp_pending_wildcards.tmp
            else
                domains+=("$input_domain")
            fi
            ;;
        e)
            EXCLUDE_LIST=$(echo "$OPTARG" | tr -d ' ')
            echo -e "${RED}[!] Excluded Tools: $EXCLUDE_LIST${END}"
            ;;
        r)
            RUN_HTTPX=true
            ;;
        h)
            echo -e "${YELLOW}Usage:${END} $0 [OPTIONS]"
            echo ""
            echo -e "${BOLD}Target Selection:${END}"
            echo -e "  -d ${BLUE}<domain>${END}   Target a single domain (e.g., example.com)"
            echo -e "  -l ${BLUE}<file>${END}     Target a list of domains from a file"
            echo ""
            echo -e "${BOLD}Scan Options:${END}"
            echo -e "  -r            Run ${BOLD}httpx${END} on final output (Alive Check)"
            echo -e "  -e ${BLUE}<tools>${END}    Exclude specific tools (Comma separated)"
            echo ""
            echo -e "${BOLD}Example:${END}"
            echo -e "  $0 -d example.com -r"
            echo -e "  $0 -d \"*.test1.*.hello.com\""
            exit 0
            ;;
        *)
            echo "Usage: $0 [-l list.txt] [-d domain.com] [-e Tool1,Tool2] [-r]"
            exit 1
            ;;
    esac
done

# Validation
if [ ${#domains[@]} -eq 0 ] && [ ! -f temp_pending_wildcards.tmp ]; then
    echo "Error: No domains provided. Use -l or -d."
    exit 1
fi

# --- Cleanup Old Output (Only runs if we are actually scanning) ---
if [ -f "$FINAL_OUTPUT" ]; then
    echo "Found old $FINAL_OUTPUT. Removing it..."
    rm "$FINAL_OUTPUT"
fi

# Push pending wildcards from input directly into FINAL_OUTPUT so the engine picks them up
if [ -f temp_pending_wildcards.tmp ]; then
    cat temp_pending_wildcards.tmp >> "$FINAL_OUTPUT"
    rm temp_pending_wildcards.tmp
fi

# --- DEDUPLICATION ---
IFS=$'\n' read -d '' -r -a unique_domains <<< "$(printf "%s\n" "${domains[@]}" | sort -u)"
domains=("${unique_domains[@]}")

# Process Loop (Initial Pass for normal domains)
for domain in "${domains[@]}"; do
    process_domain "$domain"
done

# --- Advanced Right-to-Left Wildcard Engine ---
touch processed_tracking_list.tmp

for domain in "${domains[@]}"; do
    echo "$domain" >> processed_tracking_list.tmp
done

echo "------------------------------------------------"
echo -e "${BOLD}${GREEN}[+] Checking for Wildcard (*) Domains to process (Right-to-Left)...${END}"

while true; do
    # 1. Check if there are any active wildcards left in the final output
    if ! grep -q "\*" "$FINAL_OUTPUT" 2>/dev/null; then
        break
    fi

    grep "\*" "$FINAL_OUTPUT" | sort -u > wildcard_temp_found.txt
    count=$(wc -l < wildcard_temp_found.txt)
    echo -e "${BOLD}Found $count wildcard pattern(s). Analyzing and Re-scanning...${END}"

    # Append to logging list
    cat wildcard_temp_found.txt | anew "$WILDCARD_OUTPUT" > /dev/null

    # Remove wildcards from main final output so they don't break httpx or loop infinitely
    grep -v "\*" "$FINAL_OUTPUT" > wildcard_temp_clean.txt
    mv wildcard_temp_clean.txt "$FINAL_OUTPUT"

    > wildcard_temp_targets.txt
    > active_patterns.tmp

    # 2. Extract safe "Base Domains" to scan from the wildcard patterns
    while read -r pattern; do
        [ -z "$pattern" ] && continue
        
        echo "$pattern" >> active_patterns.tmp

        B="${pattern##*\*}"
        clean_part="${B#\.}"
        
        # Determine the safest part of the string to pass to Recon Tools
        if [[ "$pattern" =~ ^\*\.[a-zA-Z0-9.-]+$ ]]; then
            echo "${pattern#\*.}" >> wildcard_temp_targets.txt
        else
            if [[ "$clean_part" != *"."* ]] || [[ $(echo "$clean_part" | grep -o "\." | wc -l) -eq 0 ]]; then
                echo "$pattern" | sed 's/\*//g' | sed 's/\.\./\./g' | sed 's/^\.//' >> wildcard_temp_targets.txt
            else
                echo "$clean_part" >> wildcard_temp_targets.txt
            fi
        fi
    done < wildcard_temp_found.txt

    # 3. Process the extracted Base Domains
    found_new_target=false
    while read -r target; do
        [ -z "$target" ] && continue
        if ! grep -Fxq "$target" processed_tracking_list.tmp; then
            echo "$target" >> processed_tracking_list.tmp
            process_domain "$target"
            found_new_target=true
        else
            echo "Skipping base target $target (Already processed)"
        fi
    done < wildcard_temp_targets.txt

    # 4. Pattern Substitution: Map discovered domains back to original wildcards
    > next_wildcards.tmp
    if [ -f active_patterns.tmp ]; then
        while read -r pattern; do
            B="${pattern##*\*}"
            A="${pattern%\**}"
            L="${A##*\*}"
            
            B_esc=$(echo "$B" | sed 's/\./\\./g')
            
            # Find newly discovered domains that match the rightmost section
            if [ -z "$B" ]; then
                L_esc=$(echo "$L" | sed 's/\./\\./g')
                grep "^${L_esc}" "$FINAL_OUTPUT" 2>/dev/null > temp_matches.txt
            else
                grep "${B_esc}$" "$FINAL_OUTPUT" 2>/dev/null > temp_matches.txt
            fi
            
            while read -r D; do
                R="${D%${B}}"
                [ -z "$R" ] && continue

                if [ -z "$L" ]; then
                    X="$R"
                else
                    if [[ "$R" == *"$L"* ]]; then
                        X="${R##*$L}"
                    else
                        L_clean="${L#\.}"
                        if [ -n "$L_clean" ] && [[ "$R" == *"$L_clean"* ]]; then
                            X="${R##*$L_clean}"
                        else
                            X="$R"
                        fi
                    fi
                fi

                X="${X#\.}"
                NEW_PATTERN="${A}${X}${B}"
                
                # If we successfully replaced a star, but more exist, cue it up for the next loop!
                if [[ "$NEW_PATTERN" == *"*"* ]]; then
                    if ! grep -Fxq "$NEW_PATTERN" "$WILDCARD_OUTPUT"; then
                        echo "$NEW_PATTERN" >> next_wildcards.tmp
                    fi
                else
                    # Fully resolved domain with NO stars left!
                    echo "$NEW_PATTERN" >> "$FINAL_OUTPUT"
                fi

            done < temp_matches.txt
        done < active_patterns.tmp
        rm -f active_patterns.tmp temp_matches.txt
    fi

    # Push newly generated wildcard patterns to FINAL_OUTPUT to trigger the next Right-to-Left phase
    if [ -s next_wildcards.tmp ]; then
        cat next_wildcards.tmp >> "$FINAL_OUTPUT"
        found_new_target=true
    fi
    rm -f next_wildcards.tmp

    # If no new domains were scanned AND no new substitutions were made, end recursion to prevent infinite loops.
    if [ "$found_new_target" = false ]; then
        break
    fi
done

# Cleanup recursive temp files
rm -f wildcard_temp_*.txt processed_tracking_list.tmp temp_pending_wildcards.tmp active_patterns.tmp next_wildcards.tmp temp_matches.txt

echo "------------------------------------------------"
echo -e "${GREEN}Done. All unique subdomains saved to: $FINAL_OUTPUT${END}"
echo -e "${GREEN}Wildcard domains saved to: $WILDCARD_OUTPUT${END}"

# --- HTTPX Logic (Alive Check) ---
if [ "$RUN_HTTPX" = true ]; then
    echo "------------------------------------------------"
    echo -e "${BOLD}[*] Running httpx (Alive Check)...${END}"
    
    if [ -f "aliveSubs.txt" ]; then
        echo "Found old aliveSubs.txt. Removing it..."
        rm "aliveSubs.txt"
    fi

    if ! cat "$FINAL_OUTPUT" | httpx -silent -o aliveSubs.txt 2>/dev/null; then
        if ! cat "$FINAL_OUTPUT" | httpx-toolkit -silent -o aliveSubs.txt; then
            echo -e "${RED}httpx error !${END}"
        fi
    fi
fi
