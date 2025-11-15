#!/bin/bash
echo "[+] Starting setup for ultimate_hunt.sh..."
apt update && sudo apt upgrade -y || { echo "[-] Apt failed"; exit 1; }
apt install -y python3-pip git curl wget build-essential || { echo "[-] Install failed"; exit 1; }
dpkg -l | grep golang && sudo apt remove golang -y
rm -rf /usr/lib/go-* /usr/local/go
wget -q https://go.dev/dl/go1.22.1.linux-amd64.tar.gz && [ -s go1.22.1.linux-amd64.tar.gz ] || { echo "[-] Go download failed"; exit 1; }
tar -C /usr/local -xzf go1.22.1.linux-amd64.tar.gz || { echo "[-] Go extract failed"; exit 1; }
rm go1.22.1.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
echo "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin" >> ~/.bashrc && source ~/.bashrc
[ -n "$ZSH_VERSION" ] && echo "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin" >> ~/.zshrc && source ~/.zshrc
/usr/local/go/bin/go version || { echo "[-] Go not installed"; exit 1; }
apt install -y ffuf jq || { echo "[-] FFUF/JQ install failed"; exit 1; }
pipx install arjun
pipx ensurepath && source ~/.*rc
pip install git+https://github.com/sanjai-AK47/ShodanX pipx
for tool in httpx naabu dnsx nuclei katana; do go install "github.com/projectdiscovery/$tool/cmd/$tool@latest" || echo "[-] $tool failed"; done
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/bitquark/shortscan/cmd/shortscan@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/OJ/gobuster/v3@latest
go install -v github.com/Emoe/kxss@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest
git clone https://github.com/devanshbatham/paramspider && cd paramspider && pip install . || { echo "[-] ParamSpider failed"; exit 1; }
mkdir -p /usr/share/wordlists
git clone https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/seclists || { echo "[-] SecLists failed"; exit 1; }
ln -sf /usr/share/wordlists/seclists /usr/share/wordlists/SecLists
for tool in subfinder httpx naabu dnsx nuclei gau arjun paramspider ffuf jq shodanx anew katana; do
    command -v $tool &> /dev/null && echo "$tool: Installed" || echo "$tool: Failed"
done
echo "[+] Setup complete!"
