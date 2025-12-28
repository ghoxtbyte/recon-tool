# ReconTool

A simple yet powerful bash-based subdomain reconnaissance tool for bug bounty and red teaming.

## 🔧 Features

- Collect subdomains from:
  - subfinder
  - assetfinder
  - crt.sh
  - Amass
  - Findomain
  - AlienVault OTX
  - urlscan.io
  - AbuseIPDB
  - WayBackMachine
  - httpx
- Merge and de-duplicate results automatically
- CLI support for both single domains and domain lists

## 📦 Installation

Use the provided setup script to install dependencies:

```bash
chmod +x setup.sh
sudo ./setup.sh
````

## 🚀 Usage

For a **single domain**:

```bash
chmod +x recon.sh
./recon.sh -h
./recon.sh -d example.com -r # Check which domains are alive using httpx
```

For a **list of domains** (one per line):

```bash
./recon.sh -l domains.txt
```

**Exclude:**

```bash
./recon.sh -d example.com -e Amass,wayback
```

## 📁 Output

The script generates:

* `all_subdomains.txt`: final list of merged and unique subdomains

Temporary files (`sublist.txt`, `assetfinder.txt`, etc.) are removed automatically.

## ✅ Requirements

Tools required (installed by `setup.sh`):

* [subfinder](https://github.com/projectdiscovery/subfinder)
* [assetfinder](https://github.com/tomnomnom/assetfinder)
* [findomain](https://github.com/Edu4rdSHL/findomain)
* [amass](https://github.com/OWASP/Amass)
* jq, curl, grep, sed, anew, httpx, etc.

## 📄 License

This project is licensed under the [MIT License](LICENSE).
