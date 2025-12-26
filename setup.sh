#!/bin/bash

# Ultimate Recon Setup Script (Auto-Shell Detection Edition)

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}[+] Starting Ultimate Recon Setup...${NC}"

# --- 0. Helper Functions ---

# Function to detect the user's shell profile
detect_shell_profile() {
    local shell_name
    shell_name=$(basename "$SHELL")
    
    case "$shell_name" in
        "zsh")
            echo "$HOME/.zshrc"
            ;;
        "bash")
            echo "$HOME/.bashrc"
            ;;
        *)
            # Default fallback
            echo "$HOME/.bashrc"
            ;;
    esac
}

# Identify the config file immediately
SHELL_CONFIG=$(detect_shell_profile)
echo -e "${YELLOW}[*] Detected Shell: $(basename "$SHELL")${NC}"
echo -e "${YELLOW}[*] Configuration will be saved to: $SHELL_CONFIG${NC}"

# --- 1. Update System & Install Base Dependencies ---
echo -e "${GREEN}[*] Updating system and installing base dependencies...${NC}"
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3-pip python3-venv git curl wget build-essential jq parallel unzip ffuf libpcap-dev || { echo -e "${RED}[-] Apt install failed${NC}"; exit 1; }

# --- 2. Install/Update Golang (Clean Install) ---
echo -e "${GREEN}[*] Setting up Golang...${NC}"
# Remove old versions
sudo rm -rf /usr/lib/go-* /usr/local/go

# Download Go (Updated to a stable recent version)
GO_VER="1.22.1"
wget -q "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz" && [ -s "go${GO_VER}.linux-amd64.tar.gz" ] || { echo -e "${RED}[-] Go download failed${NC}"; exit 1; }
sudo tar -C /usr/local -xzf "go${GO_VER}.linux-amd64.tar.gz"
rm "go${GO_VER}.linux-amd64.tar.gz"

# --- SMART PATH CONFIGURATION ---
echo -e "${BLUE}[*] Configuring Environment Variables for $SHELL_CONFIG...${NC}"

# Define the path line
GO_PATH_LINE='export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin'

# Function to add path if not exists
add_to_path() {
    local file=$1
    if [ -f "$file" ]; then
        if ! grep -q "/usr/local/go/bin" "$file"; then
            echo >> "$file"
            echo "# Golang Paths" >> "$file"
            echo "$GO_PATH_LINE" >> "$file"
            echo -e "${GREEN}[+] Added Go paths to $file${NC}"
        else
            echo -e "${YELLOW}[!] Go paths already exist in $file${NC}"
        fi
    fi
}

# Apply to the detected shell config
add_to_path "$SHELL_CONFIG"

# If the detected shell is NOT bash, also add to .bashrc as a fallback/compatibility measure
if [[ "$SHELL_CONFIG" != *".bashrc"* ]]; then
    add_to_path "$HOME/.bashrc"
fi

# Apply to current session explicitly for this script execution
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# Verify Go
if command -v go &> /dev/null; then
    go version
else
    echo -e "${RED}[-] Go installation failed or PATH not updated in current session.${NC}"
    exit 1
fi

# --- 3. Python Tools Setup ---
echo -e "${GREEN}[*] Installing Python tools...${NC}"
# Install pipx if not found
if ! command -v pipx &> /dev/null; then
    pip install --user pipx
    python3 -m pipx ensurepath
fi

pipx install alive-progress
pipx install arjun

# --- 4. Install Go Tools ---
echo -e "${GREEN}[*] Installing Go tools...${NC}"
GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/bitquark/shortscan/cmd/shortscan@latest"
    "github.com/OJ/gobuster/v3@latest"
    "github.com/Emoe/kxss@latest"
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/owasp-amass/amass/v4/...@master"
)

for tool in "${GO_TOOLS[@]}"; do
    tool_name=$(echo $tool | awk -F/ '{print $NF}' | cut -d@ -f1)
    echo -e "-> Installing ${BLUE}$tool_name${NC}..."
    go install -v "$tool" || echo -e "${RED}[-] Failed to install $tool_name${NC}"
done

# --- 5. Install Findomain (Binary) ---
echo -e "${GREEN}[*] Installing Findomain...${NC}"
wget -q https://github.com/Findomain/Findomain/releases/download/8.2.1/findomain-linux.zip -O findomain.zip
unzip -o findomain.zip &>/dev/null
chmod +x findomain
sudo mv findomain /usr/local/bin/
rm findomain.zip

# --- 6. Install ParamSpider ---
echo -e "${GREEN}[*] Installing ParamSpider...${NC}"
if [ -d "paramspider" ]; then rm -rf paramspider; fi
git clone https://github.com/devanshbatham/paramspider
cd paramspider && pip install . 
cd ..
rm -rf paramspider # Cleanup source after install if pip installed it globally/user

# --- 7. Install VulnX ---
echo -e "${GREEN}[*] Installing VulnX...${NC}"
# Installing to user's home/tools directory to keep it organized
mkdir -p ~/tools
cd ~/tools
if [ -d "VulnX" ]; then rm -rf VulnX; fi
git clone https://github.com/anouarbensaad/vulnx.git
cd VulnX
chmod +x install.sh
./install.sh
cd ../.. 

# --- 8. Download SecLists ---
echo -e "${GREEN}[*] Downloading SecLists (This may take a while)...${NC}"
sudo mkdir -p /usr/share/wordlists
if [ ! -d "/usr/share/wordlists/seclists" ]; then
    sudo git clone https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/seclists
else
    echo "SecLists already exists."
fi
# Ensure lowercase link exists
sudo ln -sf /usr/share/wordlists/seclists /usr/share/wordlists/SecLists

# --- 9. Final Verification ---
echo "--------------------------------------"
echo -e "${BLUE}[+] Setup Complete! Verifying key tools:${NC}"
CHECK_TOOLS="subfinder httpx nuclei arjun go ffuf findomain amass"

for tool in $CHECK_TOOLS; do
    if command -v $tool &> /dev/null; then
        echo -e "$tool: ${GREEN}Installed${NC}"
    else
        echo -e "$tool: ${RED}WARNING - Not found in PATH${NC}"
    fi
done

# Check VulnX separately as it might not be in PATH
if [ -f "$HOME/tools/VulnX/vulnx.py" ] || command -v vulnx &> /dev/null; then
     echo -e "vulnx: ${GREEN}Installed${NC}"
else
     echo -e "vulnx: ${RED}WARNING - Not found${NC}"
fi

echo "--------------------------------------"
echo -e "${YELLOW}[!] IMPORTANT: The installation modified your $SHELL_CONFIG file.${NC}"
echo -e "${YELLOW}[!] Please run the following command or restart your terminal:${NC}"
echo -e "${GREEN}    source $SHELL_CONFIG${NC}"
echo "--------------------------------------"
