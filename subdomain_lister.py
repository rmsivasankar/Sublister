import os
import requests
import socket
import json
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

class SubdomainLister:
    def __init__(self, domain, output_dir="outputs", check_active=True, max_workers=10):
        """
        Initialize the SubdomainLister with configuration.
        
        Args:
            domain (str): The base domain to search for subdomains
            output_dir (str): Directory to save output files
            check_active (bool): Whether to check if subdomains are active
            max_workers (int): Maximum threads for concurrent processing
        """
        self.domain = domain.strip().lower()
        self.output_dir = output_dir
        self.check_active = check_active
        self.max_workers = max_workers
        self.subdomains = set()
        self.active_subdomains = set()
        
        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)
    
    def get_certificate_subdomains(self):
        """Fetch subdomains from certificate transparency logs."""
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            for entry in data:
                name_value = entry.get('name_value', '')
                if name_value:
                    # Split all names (some entries have multiple names)
                    names = name_value.split('\n')
                    for name in names:
                        name = name.strip().lower()
                        if name.startswith('*.'):
                            name = name[2:]
                        if name.endswith(self.domain) and name != self.domain:
                            self.subdomains.add(name)
        except Exception as e:
            print(f"Error fetching from crt.sh: {e}")
    
    def is_subdomain_active(self, subdomain):
        """Check if a subdomain is active by attempting HTTP/HTTPS connections."""
        try:
            # Try HTTPS first
            requests.get(f"https://{subdomain}", timeout=5)
            return True
        except:
            try:
                # Fall back to HTTP
                requests.get(f"http://{subdomain}", timeout=5)
                return True
            except:
                return False
    
    def check_subdomains_status(self):
        """Check status of all found subdomains."""
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self.is_subdomain_active, subdomain): subdomain 
                for subdomain in self.subdomains
            }
            
            for future in as_completed(futures):
                subdomain = futures[future]
                try:
                    if future.result():
                        self.active_subdomains.add(subdomain)
                except Exception as e:
                    print(f"Error checking {subdomain}: {e}")
    
    def generate_report(self):
        """Generate a report with all findings."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(
            self.output_dir, 
            f"{self.domain}_subdomains_{timestamp}.json"
        )
        
        report = {
            "domain": self.domain,
            "timestamp": timestamp,
            "total_subdomains_found": len(self.subdomains),
            "active_subdomains": len(self.active_subdomains) if self.check_active else "Not checked",
            "all_subdomains": sorted(list(self.subdomains)),
            "active_subdomains_list": sorted(list(self.active_subdomains)) if self.check_active else []
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        return output_file
    
    def run(self):
        """Execute the subdomain listing process."""
        print(f"Starting subdomain discovery for {self.domain}")
        
        # Step 1: Get subdomains from certificates
        print("Fetching subdomains from certificate transparency logs...")
        self.get_certificate_subdomains()
        print(f"Found {len(self.subdomains)} potential subdomains")
        
        # Step 2: Check active status if requested
        if self.check_active and self.subdomains:
            print("Checking subdomain activity status...")
            self.check_subdomains_status()
            print(f"Found {len(self.active_subdomains)} active subdomains")
        
        # Step 3: Generate report
        output_path = self.generate_report()
        print(f"Report generated at: {output_path}")
        
        return output_path


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Subdomain Lister using Certificate Transparency"
    )
    parser.add_argument("domain", help="Domain to search for subdomains")
    parser.add_argument("--no-check", action="store_false", dest="check_active",
                       help="Skip checking if subdomains are active")
    parser.add_argument("--output-dir", default="outputs",
                       help="Directory to save output files")
    parser.add_argument("--threads", type=int, default=10,
                       help="Maximum threads for concurrent processing")
    
    args = parser.parse_args()
    
    lister = SubdomainLister(
        domain=args.domain,
        output_dir=args.output_dir,
        check_active=args.check_active,
        max_workers=args.threads
    )
    
    lister.run()


if __name__ == "__main__":
    main()