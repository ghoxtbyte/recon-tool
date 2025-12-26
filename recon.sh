#!/bin/bash

# Output file name
FINAL_OUTPUT="all_subdomains.txt"

# --- 1. Clean Start ---
# If the output file exists, remove it to start fresh (as you requested)
if [ -f "$FINAL_OUTPUT" ]; then
    echo "Found old $FINAL_OUTPUT. Removing it..."
    rm "$FINAL_OUTPUT"
fi

# --- 2. Safety Trap (New) ---
# This ensures temp files are deleted even if you press Ctrl+C
trap "rm -f temp_*.txt; echo -e '\nScript interrupted. Temp files cleaned.'; exit" INT TERM

# Function to process a single domain
process_domain() {
    local domain=$1
    echo "------------------------------------------------"
    echo "Processing domain: $domain"

    # --- Run Tools ---
    # Using specific temp names to avoid conflicts

    # 1. Subfinder
    if command -v subfinder &> /dev/null; then
        subfinder -d "$domain" --all --recursive -o temp_subfinder.txt > /dev/null 2>&1
    fi

    # 2. Assetfinder (Uncomment if needed)
    # assetfinder "$domain" > temp_assetfinder.txt

    # 3. crt.sh
    curl -s "https://crt.sh/json?q=%.$domain" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > temp_crt.txt

    # 4. AlienVault
    curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/$domain/passive_dns" | jq -r '.passive_dns[]?.hostname' | grep -E "^[a-zA-Z0-9.-]+\.$domain$" > temp_alienvault.txt

    # 5. UrlScan
    curl -s "https://urlscan.io/api/v1/search/?q=domain:$domain&size=10000" | jq -r '.results[]?.page?.domain' | grep -E "^[a-zA-Z0-9.-]+\.$domain$" > temp_urlscan.txt

    # --- Merge & Save Immediately ---
    echo "Merging results for $domain..."
    
    # Cat all temp files, suppress errors for missing files, unique them with anew, and append to FINAL_OUTPUT
    cat temp_*.txt 2>/dev/null | anew "$FINAL_OUTPUT"

    # --- Cleanup Temp Files ---
    rm -f temp_*.txt
}

# Check for required tools
for tool in subfinder curl jq grep sed anew; do
    if ! command -v "$tool" &> /dev/null; then
        echo "Error: Tool '$tool' is not installed."
        exit 1
    fi
done

# Parse command-line arguments
domains=()
while getopts "l:d:" opt; do
    case $opt in
        l)
            if [[ -f $OPTARG ]]; then
                while IFS= read -r line; do
                    # Remove whitespace/empty lines
                    line=$(echo "$line" | xargs)
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
        *)
            echo "Usage: $0 [-l domain_list.txt] [-d single_domain]"
            exit 1
            ;;
    esac
done

# Check if we have domains to process
if [ ${#domains[@]} -eq 0 ]; then
    echo "Error: No domains provided. Please use -l <file> or -d <domain>."
    exit 1
fi

# Process loop
for domain in "${domains[@]}"; do
    process_domain "$domain"
done

echo "------------------------------------------------"
echo "Done. All unique subdomains saved to: $FINAL_OUTPUT"
