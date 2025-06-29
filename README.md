# ReconTool

A simple yet powerful bash-based subdomain reconnaissance tool for bug bounty and red teaming.

## 🔧 Features

- Collect subdomains from:
  - subfinder
  - assetfinder
  - crt.sh
  - ShodanX
  - AlienVault OTX
  - urlscan.io
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
./recon.sh -d example.com
```

For a **list of domains** (one per line):

```bash
./recon.sh -l domains.txt
```

## 📁 Output

The script generates:

* `all_subdomains.txt`: final list of merged and unique subdomains

Temporary files (`sublist.txt`, `shodax.txt`, etc.) are removed automatically.

## ✅ Requirements

Tools required (installed by `setup.sh`):

* [subfinder](https://github.com/projectdiscovery/subfinder)
* [assetfinder](https://github.com/tomnomnom/assetfinder)
* [ShodanX](https://github.com/sanjai-AK47/ShodanX)
* jq, curl, grep, sed, anew, ffuf, arjun, etc.

## 📄 License

This project is licensed under the [MIT License](LICENSE).
