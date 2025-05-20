#!/usr/bin/env python3

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urljoin

import requests
import urllib3
from colorama import init, Fore, Style

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init()

# Import local modules
from src.payloads import (
    cve_2024_2194,
    cve_2023_6961,
    cve_2024_9047,
    cve_2020_36326,
    valvepress_sqli,
    wp_statistics_sqli,
    wp_statistics_cve_2022_25148,
    wpdiscuz_rce,
    wp_file_upload_rce,
    wp_time_capsule_rce,
    smart_product_review_upload
)
from src.core.plugin_checker import PluginChecker
from src.utils.helpers import (
    get_random_headers,
    ensure_https,
    get_timestamp,
    ensure_reports_dir
)

class VulnScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.findings = []
        self.plugin_checker = PluginChecker()
        
        # Initialize all CVE modules
        self.cve_modules = {
            'CVE-2024-2194': cve_2024_2194,
            'CVE-2023-6961': cve_2023_6961,
            'CVE-2024-9047': cve_2024_9047,
            'CVE-2020-36326': cve_2020_36326,
            'ValvePress-SQLi': valvepress_sqli,
            'WP-Statistics-SQLi': wp_statistics_sqli,
            'CVE-2022-25148': wp_statistics_cve_2022_25148,
            'CVE-2020-24186': wpdiscuz_rce,
            'CVE-2024-11635': wp_file_upload_rce,
            'CVE-2024-8856': wp_time_capsule_rce,
            'CVE-2021-4455': smart_product_review_upload
        }

        # Map CVEs to plugin slugs
        self.cve_to_plugin = {
            'WP-Statistics-SQLi': 'wp-statistics',
            'CVE-2022-25148': 'wp-statistics',
            'CVE-2020-24186': 'wpdiscuz',
            'CVE-2024-11635': 'wp-file-upload',
            'CVE-2024-8856': 'wp-time-capsule',
            'CVE-2021-4455': 'smart-product-review'
        }

    def scan_cve(self, url, cve_name, module):
        """Scan a single CVE against a URL"""
        try:
            payload = module.get_payload()
            full_url = urljoin(url, payload['path'])
            
            # Update session headers
            self.session.headers.update(get_random_headers())
            if 'headers' in payload:
                self.session.headers.update(payload['headers'])
            
            # Make request
            if payload['method'] == 'GET':
                response = self.session.get(
                    full_url,
                    params=payload.get('params', {}),
                    cookies=payload.get('cookies', {}),
                    timeout=15
                )
            else:
                if 'files' in payload:
                    response = self.session.post(
                        full_url,
                        files=payload['files'],
                        data=payload.get('data', {}),
                        timeout=15
                    )
                else:
                    response = self.session.post(
                        full_url,
                        data=payload.get('data', {}),
                        timeout=15
                    )
            
            # Check if vulnerable
            if module.check_response(response):
                finding = {
                    "url": url,
                    "cve": cve_name,
                    "evidence": {
                        "status_code": response.status_code,
                        "response_length": len(response.text),
                        "response_sample": response.text[:200],
                        "response_time": response.elapsed.total_seconds()
                    },
                    "timestamp": get_timestamp()
                }
                self.findings.append(finding)
                return True, cve_name
            
            return False, cve_name
            
        except Exception:
            return False, cve_name

    def scan_site(self, url):
        """Scan a single site for all CVEs in parallel"""
        url = ensure_https(url)
        print(f"\n{Fore.CYAN}[*] Scanning {url}{Style.RESET_ALL}")
        
        # Check plugins first
        vulnerable_plugins = set()
        for cve_name, plugin_slug in self.cve_to_plugin.items():
            exists, version, is_vulnerable = self.plugin_checker.check_plugin(self.session, url, plugin_slug)
            
            if not exists:
                print(f"{Fore.YELLOW}[-] {url} - Plugin {plugin_slug} not found{Style.RESET_ALL}")
                continue
                
            if version:
                if is_vulnerable:
                    print(f"{Fore.GREEN}[+] {url} - {plugin_slug} version {version} is vulnerable{Style.RESET_ALL}")
                    vulnerable_plugins.add(cve_name)
                else:
                    print(f"{Fore.YELLOW}[-] {url} - {plugin_slug} version {version} is not vulnerable{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] {url} - {plugin_slug} version could not be determined{Style.RESET_ALL}")
        
        # Only scan CVEs for vulnerable plugins
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for cve_name, module in self.cve_modules.items():
                # Skip if CVE is plugin-specific and plugin is not vulnerable
                if cve_name in self.cve_to_plugin and cve_name not in vulnerable_plugins:
                    continue
                    
                futures.append(executor.submit(self.scan_cve, url, cve_name, module))
            
            for future in futures:
                is_vulnerable, cve_name = future.result()
                if is_vulnerable:
                    print(f"{Fore.GREEN}[+] {url} - Vulnerable to {cve_name}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}[-] {url} - Not vulnerable to {cve_name}{Style.RESET_ALL}")

    def save_findings(self):
        """Save findings to JSONL file"""
        reports_dir = ensure_reports_dir()
        report_file = reports_dir / 'findings.jsonl'
        
        with open(report_file, 'w') as f:
            for finding in self.findings:
                f.write(json.dumps(finding) + '\n')

def main():
    parser = argparse.ArgumentParser(description='WordPress Vulnerability Scanner')
    parser.add_argument('-f', '--file', required=True, help='File containing list of WordPress URLs')
    args = parser.parse_args()

    print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════╗")
    print(f"║                WordPress Vuln Scanner v1.0                ║")
    print(f"╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}")

    scanner = VulnScanner()

    try:
        with open(args.file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]

        print(f"\n{Fore.CYAN}[*] Starting scan for {len(urls)} URLs...{Style.RESET_ALL}")
        
        for url in urls:
            scanner.scan_site(url)

        scanner.save_findings()
        print(f"\n{Fore.GREEN}[+] Scan completed! Results saved in reports/findings.jsonl{Style.RESET_ALL}")

    except FileNotFoundError:
        print(f"{Fore.RED}[-] Error: File {args.file} not found{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main() 