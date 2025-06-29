#!/bin/bash

# Function to process a single domain
process_domain() {
    local domain=$1
    echo "Processing domain: $domain"

    # Run subfinder
    subfinder -d "$domain" --all --recursive -o sublist.txt -silent

    # Run assetfinder
    assetfinder "$domain" >> sublist.txt

    # Run shodanx
    shodanx subdomain -d "$domain" -ra -o shodax.txt 2>/dev/null

    # Fetch from crt.sh
    curl -s "https://crt.sh/json?q=%.$domain" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | tee -a subs_domain.txt

    # Fetch from AlienVault OTX
    curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/$domain/passive_dns" | jq -r '.passive_dns[]?.hostname' | grep -E "^[a-zA-Z0-9.-]+\.$domain$" | anew | tee alienvault_subs.txt

    # Fetch from urlscan.io
    curl -s "https://urlscan.io/api/v1/search/?q=domain:$domain&size=10000" | jq -r '.results[]?.page?.domain' | grep -E "^[a-zA-Z0-9.-]+\.$domain$" | anew | tee urlscan_subs.txt
}

# Function to merge and clean up
merge_and_cleanup() {
    echo "Merging results..."
    cat sublist.txt shodax.txt subs_domain.txt alienvault_subs.txt urlscan_subs.txt 2>/dev/null | anew > all_subdomains.txt
    echo "Results merged into all_subdomains.txt"

    echo "Cleaning up temporary files..."
    rm -f sublist.txt shodax.txt subs_domain.txt alienvault_subs.txt urlscan_subs.txt 2>/dev/null
    echo "Cleanup complete."
}

# Check for required tools
for tool in subfinder shodanx curl jq grep sed anew; do
    if ! command -v "$tool" &> /dev/null; then
        echo "Error: $tool is not installed."
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
                    domains+=("$line")
                done < "$OPTARG"
            else
                echo "Error: Domain list file $OPTARG not found."
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

# Check if at least one domain is provided
if [ ${#domains[@]} -eq 0 ]; then
    echo "Error: No domains provided. Use -l or -d."
    exit 1
fi

# Process each domain
for domain in "${domains[@]}"; do
    process_domain "$domain"
done

# Merge results and clean up
merge_and_cleanup

echo "Done."
