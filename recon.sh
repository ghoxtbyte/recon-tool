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
echo "    + Wildcard Recursive Scanning"
echo -e "${END}"

# --- Safety Trap ---
trap "rm -f temp_*.txt wildcard_temp_*.txt; echo -e '\n${RED}[!] Interrupted. Temp files cleaned.${END}'; exit" INT TERM

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
                    
                    # --- FIXED LOGIC FOR INPUT WILDCARDS ---
                    # If input is *.example.com, treat it as example.com for processing
                    # but ensure it's logged as a wildcard first.
                    if [[ "$line" == \*\.* ]]; then
                        # 1. Log the wildcard domain directly
                        echo "$line" | anew "$WILDCARD_OUTPUT"
                        
                        # 2. Strip the wildcard prefix for processing
                        clean_domain=$(echo "$line" | sed 's/^\*\.//')
                        domains+=("$clean_domain")
                    else
                        # Normal domain
                        domains+=("$line")
                    fi
                done < "$OPTARG"
            else
                echo "Error: File $OPTARG not found."
                exit 1
            fi
            ;;
        d)
            # Handle single domain argument similarly if user manually enters *.domain
            input_domain=$OPTARG
            if [[ "$input_domain" == \*\.* ]]; then
                echo "$input_domain" | anew "$WILDCARD_OUTPUT"
                clean_domain=$(echo "$input_domain" | sed 's/^\*\.//')
                domains+=("$clean_domain")
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
            echo -e "${BOLD}Available Tools to Exclude:${END}"
            echo -e "  Subfinder, Assetfinder, Findomain, Amass, crt,"
            echo -e "  wayback, abuseipdb, AlienVault, urlscan"
            echo ""
            echo -e "${BOLD}Example:${END}"
            echo -e "  $0 -d example.com -r"
            echo -e "  $0 -l targets.txt -e Amass,crt"
            exit 0
            ;;
        *)
            echo "Usage: $0 [-l list.txt] [-d domain.com] [-e Tool1,Tool2] [-r]"
            exit 1
            ;;
    esac
done

# Validation
if [ ${#domains[@]} -eq 0 ]; then
    echo "Error: No domains provided. Use -l or -d."
    exit 1
fi

# --- Cleanup Old Output (Only runs if we are actually scanning) ---
if [ -f "$FINAL_OUTPUT" ]; then
    echo "Found old $FINAL_OUTPUT. Removing it..."
    rm "$FINAL_OUTPUT"
fi

# Note: We do NOT remove WILDCARD_OUTPUT here if it was populated during argument parsing (the -l loop)
# But we should ensure we don't keep VERY old runs if the user didn't use -l with wildcards.
# To be safe: if WILDCARD_OUTPUT exists and is empty, we leave it. If it has content from -l, we keep it.
# Actually, standard behavior: clear old run files. But we just added to it in the loop above.
# So we only clear it IF we haven't added anything yet. 
# Simplification: We already handled `anew` in the loop. We should ensure we don't delete what we just added.
# So we skip explicit deletion of WILDCARD_OUTPUT here to preserve -l inputs. 
# Instead, we just ensure it's created or appended to.

# --- DEDUPLICATION ---
# Prevent double processing (e.g. if file had example.com AND *.example.com)
# We sort and unique the array before the main loop.
IFS=$'\n' read -d '' -r -a unique_domains <<< "$(printf "%s\n" "${domains[@]}" | sort -u)"
domains=("${unique_domains[@]}")


# Process Loop (Initial Pass)
for domain in "${domains[@]}"; do
    process_domain "$domain"
done

# --- Wildcard Recursive Processing ---
# Tracks scanned domains to prevent infinite loops on the same domain
touch processed_tracking_list.tmp

# Add initial domains to tracking list to avoid re-scanning them immediately
for domain in "${domains[@]}"; do
    echo "$domain" >> processed_tracking_list.tmp
done

echo "------------------------------------------------"
echo -e "${BOLD}${GREEN}[+] Checking for Wildcard (*) Domains to process recursively...${END}"

while true; do
    # 1. Find lines starting with *. in the main output
    if ! grep -q "^\*\." "$FINAL_OUTPUT"; then
        # No more wildcards found, break the loop
        break
    fi

    # Extract wildcards
    grep "^\*\." "$FINAL_OUTPUT" | sort -u > wildcard_temp_found.txt
    
    # Show what we found
    count=$(wc -l < wildcard_temp_found.txt)
    echo -e "${BOLD}Found $count wildcard domain(s). Extracting and Re-scanning...${END}"

    # 2. Append them to WILDCARD_OUTPUT
    cat wildcard_temp_found.txt | anew "$WILDCARD_OUTPUT"

    # 3. Remove them from FINAL_OUTPUT (Sanitize the main list)
    grep -v "^\*\." "$FINAL_OUTPUT" > wildcard_temp_clean.txt
    mv wildcard_temp_clean.txt "$FINAL_OUTPUT"

    # 4. Prepare for processing: Remove *. prefix
    sed 's/^\*\.//' wildcard_temp_found.txt > wildcard_temp_targets.txt

    # 5. Process these new domains
    found_new_target=false
    
    while read -r target; do
        # Check if we already processed this target to avoid infinite recursion
        if ! grep -Fxq "$target" processed_tracking_list.tmp; then
            echo "$target" >> processed_tracking_list.tmp
            
            # RECURSIVE CALL: Scan the extracted domain
            process_domain "$target"
            found_new_target=true
        else
            echo "Skipping $target (Already processed)"
        fi
    done < wildcard_temp_targets.txt

    # If no new targets were processed in this iteration (all were duplicates), stop loop
    if [ "$found_new_target" = false ]; then
        break
    fi
done

# Cleanup recursive temp files
rm -f wildcard_temp_*.txt processed_tracking_list.tmp

echo "------------------------------------------------"
echo -e "${GREEN}Done. All unique subdomains saved to: $FINAL_OUTPUT${END}"
echo -e "${GREEN}Wildcard domains saved to: $WILDCARD_OUTPUT${END}"

# --- HTTPX Logic (Alive Check) ---
if [ "$RUN_HTTPX" = true ]; then
    echo "------------------------------------------------"
    echo -e "${BOLD}[*] Running httpx (Alive Check)...${END}"
    
    # 1. Check and delete old aliveSubs.txt if it exists
    if [ -f "aliveSubs.txt" ]; then
        echo "Found old aliveSubs.txt. Removing it..."
        rm "aliveSubs.txt"
    fi

    # 2. Run httpx with -silent
    # If first httpx fails, suppress error and try fallback immediately
    if ! cat "$FINAL_OUTPUT" | httpx -silent -o aliveSubs.txt 2>/dev/null; then
        # Fallback command (Retry) without showing error from previous attempt
        if ! cat "$FINAL_OUTPUT" | httpx-toolkit -silent -o aliveSubs.txt; then
            echo -e "${RED}httpx error !${END}"
        fi
    fi
fi
