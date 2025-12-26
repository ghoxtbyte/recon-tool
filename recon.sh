#!/bin/bash

# --- Configuration & Banner ---
FINAL_OUTPUT="all_subdomains.txt"
EXCLUDE_LIST=""

# Colors
RED="\e[31m"
GREEN="\e[32m"
BOLD="\e[1m"
END="\e[0m"

echo -e "${BOLD}${GREEN}"
echo "    ULTIMATE RECON TOOL (Merged Edition)"
echo "    Integrates Logic from SubEnum & Recon"
echo -e "${END}"

# --- Safety Trap ---
trap "rm -f temp_*.txt; echo -e '\n${RED}[!] Interrupted. Temp files cleaned.${END}'; exit" INT TERM

# --- Helper Functions ---

# Check if a tool should be skipped
# Returns 0 (true) if tool is allowed, 1 (false) if excluded
should_run() {
    local tool_name=$1
    # Check if tool_name exists in the comma-separated EXCLUDE_LIST
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
        # Using passive mode for speed, similar to subenum
        amass enum -passive -norecursive -noalts -d "$domain" 1> temp_amass.txt 2>/dev/null
    fi
}

run_crtsh() {
    should_run "crt" || return
    local domain=$1
    echo -e "${BOLD}[*] Fetching from crt.sh...${END}"
    # Logic from subenum
    curl -sk "https://crt.sh/?q=%.$domain&output=json" | tr ',' '\n' | awk -F'"' '/name_value/ {gsub(/\*\./, "", $4); gsub(/\\n/,"\n",$4);print $4}' | sort -u > temp_crt.txt
}

run_wayback() {
    should_run "wayback" || return
    local domain=$1
    echo -e "${BOLD}[*] Fetching from Wayback Machine...${END}"
    # Logic from subenum
    curl -sk "http://web.archive.org/cdx/search/cdx?url=*.$domain&output=txt&fl=original&collapse=urlkey&page=" | awk -F/ '{gsub(/:.*/, "", $3); print $3}' | sort -u > temp_wayback.txt
}

run_abuseipdb() {
    should_run "abuseipdb" || return
    local domain=$1
    echo -e "${BOLD}[*] Fetching from AbuseIPDB...${END}"
    # Logic from subenum
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
    
    # Concatenate all temp files, suppress errors, filter unique, append
    cat temp_*.txt 2>/dev/null | awk 'NF' | anew "$FINAL_OUTPUT"

    # 3. Cleanup for this domain
    rm -f temp_*.txt
}

# --- Initialization ---

# Check/Remove old output
if [ -f "$FINAL_OUTPUT" ]; then
    echo "Found old $FINAL_OUTPUT. Removing it..."
    rm "$FINAL_OUTPUT"
fi

# Parse Arguments
domains=()

while getopts "l:d:e:h" opt; do
    case $opt in
        l)
            if [[ -f $OPTARG ]]; then
                while IFS= read -r line; do
                    line=$(echo "$line" | xargs) # Trim whitespace
                    [[ -z "$line" ]] && continue
                    domains+=("$line")
                done < "$OPTARG"
            else
                echo "Error: File $OPTARG not found."
                exit 1
            fi
            ;;
        d)
            domains+=("$OPTARG")
            ;;
        e)
            # Store exclusion list, remove spaces
            EXCLUDE_LIST=$(echo "$OPTARG" | tr -d ' ')
            echo -e "${RED}[!] Excluded Tools: $EXCLUDE_LIST${END}"
            ;;
        h)
            echo "Usage: $0 [-l list.txt] [-d domain.com] [-e Tool1,Tool2]"
            echo "Available Tools to Exclude: Subfinder, Assetfinder, Findomain, Amass, crt, wayback, abuseipdb, AlienVault, urlscan"
            exit 0
            ;;
        *)
            echo "Usage: $0 [-l list.txt] [-d domain.com] [-e Tool1,Tool2]"
            exit 1
            ;;
    esac
done

# Validation
if [ ${#domains[@]} -eq 0 ]; then
    echo "Error: No domains provided. Use -l or -d."
    exit 1
fi

# Process Loop
for domain in "${domains[@]}"; do
    process_domain "$domain"
done

echo "------------------------------------------------"
echo -e "${GREEN}Done. All unique subdomains saved to: $FINAL_OUTPUT${END}"
