# Subdomain Lister using Certificates

This tool discovers subdomains for a given domain by examining SSL certificates from certificate transparency logs. It can optionally check which subdomains are active.

## Features

- Discovers subdomains from certificate transparency logs (crt.sh)
- Optionally checks if subdomains are active (HTTP/HTTPS)
- Concurrent processing for faster results
- Generates JSON reports with all findings
- Command-line interface for easy use

## Installation

1. Clone this repository or download the files
2. Install the required dependencies:

```bash
pip install -r requirements.txt
python src/subdomain_lister.py example.com
python src/subdomain_lister.py example.com --no-check --threads 20 --output-dir my_outputs
