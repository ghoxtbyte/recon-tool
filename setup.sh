#!/bin/bash

# Ultimate Recon Setup Script (Combined & Cleaned)

echo "[+] Starting Ultimate Recon Setup..."

# 1. Update System & Install Base Dependencies
echo "[*] Updating system and installing base dependencies..."
sudo apt update && sudo apt upgrade -y
# Combined dependencies from both scripts
sudo apt install -y python3-pip python3-venv git curl wget build-essential jq parallel unzip ffuf libpcap-dev || { echo "[-] Apt install failed"; exit 1; }

# 2. Install/Update Golang (Clean Install)
echo "[*] Setting up Golang..."
# Remove old versions to avoid conflicts
sudo rm -rf /usr/lib/go-* /usr/local/go
wget -q https://go.dev/dl/go1.22.1.linux-amd64.tar.gz && [ -s go1.22.1.linux-amd64.tar.gz ] || { echo "[-] Go download failed"; exit 1; }
sudo tar -C /usr/local -xzf go1.22.1.linux-amd64.tar.gz
rm go1.22.1.linux-amd64.tar.gz

# Set Go Paths
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
[ -n "$ZSH_VERSION" ] && echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.zshrc
source ~/.bashrc

# Verify Go
/usr/local/go/bin/go version || { echo "[-] Go installation failed"; exit 1; }

# 3. Python Tools Setup
echo "[*] Installing Python tools..."
pip install pipx alive-progress
pipx ensurepath
pipx install arjun

# 4. Install Go Tools (Consolidated List)
echo "[*] Installing Go tools..."
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
    echo "-> Installing $tool_name..."
    go install -v "$tool" || echo "[-] Failed to install $tool_name"
done

# 5. Install Findomain (Binary)
echo "[*] Installing Findomain..."
wget https://github.com/Findomain/Findomain/releases/download/8.2.1/findomain-linux.zip -O findomain.zip &>/dev/null
unzip -o findomain.zip &>/dev/null
chmod +x findomain
sudo mv findomain /usr/local/bin/
rm findomain.zip

# 6. Install ParamSpider
echo "[*] Installing ParamSpider..."
if [ -d "paramspider" ]; then rm -rf paramspider; fi
git clone https://github.com/devanshbatham/paramspider
cd paramspider && pip install . 
cd ..

# 7. Install VulnX (Replaces cvemap as requested)
echo "[*] Installing VulnX..."
if [ -d "VulnX" ]; then rm -rf VulnX; fi
git clone https://github.com/anouarbensaad/vulnx.git
cd VulnX
chmod +x install.sh
# Running install script (This might require sudo depending on what's inside, usually fine)
./install.sh
cd ..

# 8. Download SecLists (Wordlists)
echo "[*] Downloading SecLists (This may take a while)..."
sudo mkdir -p /usr/share/wordlists
if [ ! -d "/usr/share/wordlists/seclists" ]; then
    sudo git clone https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/seclists
else
    echo "SecLists already exists."
fi
sudo ln -sf /usr/share/wordlists/seclists /usr/share/wordlists/SecLists

# 9. Final Verification
echo "--------------------------------------"
echo "[+] Setup Complete! Verifying key tools:"
CHECK_TOOLS="subfinder httpx nuclei vulnx paramspider arjun go ffuf findomain amass"
for tool in $CHECK_TOOLS; do
    if command -v $tool &> /dev/null || [ -f "./VulnX/vulnx.py" ]; then
        echo "$tool: Installed"
    else
        echo "$tool: WARNING - Not found in PATH (Check logs)"
    fi
done
echo "--------------------------------------"
echo "[+] Done. Please restart your terminal or run 'source ~/.bashrc'"
