#!/usr/bin/env python3

import argparse
import json
import sys
import signal
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin

import requests
import urllib3
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init()

from src.utils.helpers import (
    get_random_headers,
    ensure_https,
    get_timestamp,
    ensure_reports_dir
)

class CMSDetector:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.findings = []
        self.should_stop = False
        
        # Set up signal handler
        signal.signal(signal.SIGINT, self.handle_interrupt)
        
        # CMS signatures
        self.cms_signatures = {
            'wordpress': {
                'name': 'WordPress',
                'paths': [
                    '/wp-login.php',
                    '/wp-admin/',
                    '/wp-content/',
                    '/wp-includes/'
                ],
                'meta_tags': [
                    'wp-',
                    'wordpress'
                ]
            },
            'joomla': {
                'name': 'Joomla',
                'paths': [
                    '/administrator/',
                    '/components/',
                    '/modules/'
                ],
                'meta_tags': [
                    'joomla',
                    'Joomla!'
                ]
            },
            'drupal': {
                'name': 'Drupal',
                'paths': [
                    '/sites/default/',
                    '/modules/',
                    '/themes/'
                ],
                'meta_tags': [
                    'Drupal',
                    'drupal'
                ]
            }
        }

    def handle_interrupt(self, signum, frame):
        """Handle keyboard interrupt gracefully"""
        if not self.should_stop:
            self.should_stop = True
            print(f"\n{Fore.YELLOW}[!] Stopping scan gracefully... Please wait for current operations to complete.{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}[!] Force stopping scan...{Style.RESET_ALL}")
            sys.exit(1)

    def detect_cms(self, url):
        """Detect CMS and version for a single URL"""
        if self.should_stop:
            return

        url = ensure_https(url)
        print(f"\n{Fore.CYAN}[*] Analyzing {url}{Style.RESET_ALL}")
        
        detected_cms = []
        
        try:
            # Get main page
            response = self.session.get(
                url,
                headers=get_random_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Check meta tags
                meta_tags = soup.find_all('meta')
                for tag in meta_tags:
                    if self.should_stop:
                        return
                        
                    content = str(tag.get('content', '')).lower()
                    name = str(tag.get('name', '')).lower()
                    
                    for cms, info in self.cms_signatures.items():
                        for signature in info['meta_tags']:
                            if signature.lower() in content or signature.lower() in name:
                                if cms not in detected_cms:
                                    detected_cms.append(cms)
                
                # Check paths
                for cms, info in self.cms_signatures.items():
                    if self.should_stop:
                        return
                        
                    for path in info['paths']:
                        try:
                            test_url = urljoin(url, path)
                            response = self.session.get(
                                test_url,
                                headers=get_random_headers(),
                                timeout=5
                            )
                            if response.status_code in [200, 403]:  # 403 means path exists but access denied
                                if cms not in detected_cms:
                                    detected_cms.append(cms)
                        except:
                            continue
                
                # Try to get version
                for cms in detected_cms:
                    if self.should_stop:
                        return
                        
                    version = self.get_cms_version(url, cms, soup)
                    if version:
                        print(f"{Fore.GREEN}[+] {url} - Detected {self.cms_signatures[cms]['name']} version {version}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}[!] {url} - Detected {self.cms_signatures[cms]['name']} but version unknown{Style.RESET_ALL}")
                    
                    # Save finding
                    finding = {
                        "url": url,
                        "cms": self.cms_signatures[cms]['name'],
                        "version": version,
                        "timestamp": get_timestamp()
                    }
                    self.findings.append(finding)
            
            if not detected_cms:
                print(f"{Fore.YELLOW}[-] {url} - No CMS detected{Style.RESET_ALL}")
            
        except Exception as e:
            if not self.should_stop:  # Only print error if not stopping
                print(f"{Fore.RED}[-] {url} - Error: {str(e)}{Style.RESET_ALL}")

    def get_cms_version(self, url, cms, soup):
        """Get CMS version from various sources"""
        if self.should_stop:
            return None
            
        try:
            if cms == 'wordpress':
                # Try meta generator tag
                generator = soup.find('meta', {'name': 'generator'})
                if generator and 'WordPress' in generator.get('content', ''):
                    return generator['content'].split('WordPress ')[-1].strip()
                
                # Try readme.html
                try:
                    response = self.session.get(
                        urljoin(url, '/readme.html'),
                        headers=get_random_headers(),
                        timeout=5
                    )
                    if response.status_code == 200:
                        soup = BeautifulSoup(response.text, 'html.parser')
                        version_text = soup.find('h1').text
                        if 'WordPress' in version_text:
                            return version_text.split('WordPress ')[-1].strip()
                except:
                    pass
                
            elif cms == 'joomla':
                # Try meta generator tag
                generator = soup.find('meta', {'name': 'generator'})
                if generator and 'Joomla' in generator.get('content', ''):
                    return generator['content'].split('Joomla! ')[-1].strip()
                
            elif cms == 'drupal':
                # Try meta generator tag
                generator = soup.find('meta', {'name': 'generator'})
                if generator and 'Drupal' in generator.get('content', ''):
                    return generator['content'].split('Drupal ')[-1].strip()
                
        except:
            pass
        
        return None

    def save_findings(self):
        """Save findings to JSONL file"""
        if not self.findings:
            return
            
        reports_dir = ensure_reports_dir()
        report_file = reports_dir / 'cms_findings.jsonl'
        
        with open(report_file, 'w') as f:
            for finding in self.findings:
                f.write(json.dumps(finding) + '\n')

def main():
    parser = argparse.ArgumentParser(description='CMS Detection Tool')
    parser.add_argument('-f', '--file', required=True, help='File containing list of URLs')
    args = parser.parse_args()

    print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════╗")
    print(f"║                CMS Detector v1.0                      ║")
    print(f"╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}")

    detector = CMSDetector()

    try:
        with open(args.file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]

        print(f"\n{Fore.CYAN}[*] Starting CMS detection for {len(urls)} URLs...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Press Ctrl+C to stop the scan gracefully{Style.RESET_ALL}")
        
        for url in urls:
            if detector.should_stop:
                break
            detector.detect_cms(url)

        detector.save_findings()
        if detector.should_stop:
            print(f"\n{Fore.YELLOW}[!] Scan stopped by user. Partial results saved in reports/cms_findings.jsonl{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}[+] Detection completed! Results saved in reports/cms_findings.jsonl{Style.RESET_ALL}")

    except FileNotFoundError:
        print(f"{Fore.RED}[-] Error: File {args.file} not found{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main() 