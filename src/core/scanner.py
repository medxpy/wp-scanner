#!/usr/bin/env python3
"""
WordPress Vulnerability Scanner
Scans a list of WordPress sites for known plugin vulnerabilities using CVE payloads.
"""

import argparse
import json
import sys
import signal
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urljoin
import logging

import requests
import urllib3
from colorama import init, Fore, Style

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama and logging
init()
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)

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
    """
    Main scanner class for WordPress vulnerabilities.
    Handles plugin detection, CVE scanning, and reporting.
    """
    def __init__(self, verify_ssl=False, output_path=None):
        """
        Initialize the scanner.
        :param verify_ssl: Whether to verify SSL certificates for requests.
        :param output_path: Path to save the findings report.
        """
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.findings = []
        self.plugin_checker = PluginChecker()
        self.should_stop = False
        self.output_path = output_path
        
        # Set up signal handler
        signal.signal(signal.SIGINT, self.handle_interrupt)
        
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

    def handle_interrupt(self, signum, frame):
        """
        Handle keyboard interrupt (Ctrl+C) gracefully.
        Sets a flag to stop scanning after current operations complete.
        """
        if not self.should_stop:
            self.should_stop = True
            logging.warning(f"Stopping scan gracefully... Please wait for current operations to complete.")
        else:
            logging.error(f"Force stopping scan...")
            sys.exit(1)

    def scan_cve(self, url, cve_name, module):
        """
        Scan a single CVE against a URL.
        :param url: Target site URL.
        :param cve_name: CVE identifier.
        :param module: Payload module for the CVE.
        :return: (is_vulnerable, cve_name)
        """
        if self.should_stop:
            return False, cve_name
        try:
            payload = module.get_payload()
            full_url = urljoin(url, payload['path'])
            self.session.headers.update(get_random_headers())
            if 'headers' in payload:
                self.session.headers.update(payload['headers'])
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
        except requests.RequestException as e:
            logging.error(f"Request error for {url} - {cve_name}: {e}")
            return False, cve_name
        except Exception as e:
            logging.error(f"Unexpected error for {url} - {cve_name}: {e}")
            return False, cve_name

    def scan_site(self, url):
        """
        Scan a single site for all CVEs in parallel.
        Checks for vulnerable plugins, then runs CVE payloads.
        :param url: Target site URL.
        """
        if self.should_stop:
            return
        url = ensure_https(url)
        logging.info(f"[*] Scanning {url}")
        vulnerable_plugins = set()
        for cve_name, plugin_slug in self.cve_to_plugin.items():
            if self.should_stop:
                return
            try:
                exists, version, is_vulnerable = self.plugin_checker.check_plugin(self.session, url, plugin_slug)
            except requests.RequestException as e:
                logging.error(f"Request error while checking plugin {plugin_slug} on {url}: {e}")
                continue
            except Exception as e:
                logging.error(f"Unexpected error while checking plugin {plugin_slug} on {url}: {e}")
                continue
            if not exists:
                logging.warning(f"{url} - Plugin {plugin_slug} not found")
                continue
            if version:
                if is_vulnerable:
                    logging.info(f"{url} - {plugin_slug} version {version} is vulnerable")
                    vulnerable_plugins.add(cve_name)
                else:
                    logging.warning(f"{url} - {plugin_slug} version {version} is not vulnerable")
            else:
                logging.warning(f"{url} - {plugin_slug} version could not be determined")
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for cve_name, module in self.cve_modules.items():
                if self.should_stop:
                    break
                if cve_name in self.cve_to_plugin and cve_name not in vulnerable_plugins:
                    continue
                futures.append(executor.submit(self.scan_cve, url, cve_name, module))
            for future in futures:
                if self.should_stop:
                    break
                try:
                    is_vulnerable, cve_name = future.result()
                    if is_vulnerable:
                        logging.info(f"{url} - Vulnerable to {cve_name}")
                    else:
                        logging.warning(f"{url} - Not vulnerable to {cve_name}")
                except Exception as e:
                    logging.error(f"Error in CVE scan for {url}: {e}")

    def save_findings(self, append=False):
        """
        Save findings to a JSONL file.
        :param append: If True, append to the file; otherwise, overwrite.
        """
        if not self.findings:
            return
        reports_dir = ensure_reports_dir()
        report_file = Path(self.output_path) if self.output_path else (reports_dir / 'findings.jsonl')
        mode = 'a' if append else 'w'
        with open(report_file, mode) as f:
            for finding in self.findings:
                f.write(json.dumps(finding) + '\n')

def main():
    """
    Main entry point for the scanner CLI.
    Parses arguments, loads URLs, runs scans, and saves results.
    """
    parser = argparse.ArgumentParser(description='WordPress Vulnerability Scanner')
    parser.add_argument('-f', '--file', required=True, help='File containing list of WordPress URLs')
    parser.add_argument('-w', '--workers', type=int, default=5, help='Number of concurrent site scans (default: 5)')
    parser.add_argument('-o', '--output', help='Output file path (default: reports/findings.jsonl)')
    parser.add_argument('--verify-ssl', action='store_true', help='Enable SSL certificate verification')
    parser.add_argument('--append', action='store_true', help='Append to output file instead of overwriting')
    parser.add_argument('--summary', action='store_true', help='Print a summary of findings after scan')
    args = parser.parse_args()
    logging.info("╔══════════════════════════════════════════════════════════╗\n"
                 "║                WordPress Vuln Scanner v1.0                ║\n"
                 "╚══════════════════════════════════════════════════════════╝")
    scanner = VulnScanner(verify_ssl=args.verify_ssl, output_path=args.output)
    try:
        with open(args.file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        logging.info(f"[*] Starting scan for {len(urls)} URLs...")
        logging.info(f"[!] Press Ctrl+C to stop the scan gracefully")
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = [executor.submit(scanner.scan_site, url) for url in urls]
            for future in futures:
                if scanner.should_stop:
                    break
                future.result()
        scanner.save_findings(append=args.append)
        if args.summary:
            vuln_count = sum(1 for f in scanner.findings if f.get('cve'))
            unique_cves = set(f['cve'] for f in scanner.findings if f.get('cve'))
            logging.info(f"Summary: {vuln_count} vulnerabilities found across {len(unique_cves)} unique CVEs.")
        if scanner.should_stop:
            logging.warning('Scan stopped by user. Partial results saved in reports/findings.jsonl')
        else:
            logging.info('Scan completed! Results saved in reports/findings.jsonl')
    except FileNotFoundError:
        logging.error(f"File {args.file} not found.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()