#!/usr/bin/env python3

import requests
import argparse
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
import os
import json
from concurrent.futures import ThreadPoolExecutor
import sys
from urllib.parse import urlparse
import re
import hashlib
import urllib3
import warnings

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore')

# Initialize colorama
init()

class CMSDetector:
    def __init__(self):
        self.cms_signatures = {
            "WordPress": {
                "paths": [
                    "/wp-content/",
                    "/wp-includes/",
                    "/wp-admin/"
                ],
                "files": [
                    "wp-login.php",
                    "wp-signup.php",
                    "readme.html",
                    "license.txt"
                ],
                "headers": [
                    "X-Pingback",
                    "Link:.*wp-json"
                ],
                "cookies": [
                    "wordpress_[0-9a-f]+",
                    "wp-settings-[0-9]+"
                ],
                "meta": {
                    "generator": "WordPress(?:\\s+[0-9\\.]+)?"
                },
                "html": [
                    "<link[^>]+wp-(?:content|includes)[^>]+>",
                    "<script[^>]+wp-includes[^>]+>"
                ],
                "js": [
                    "window\\.wp"
                ],
                "favicon_hash": True
            },
            "Laravel": {
                "paths": [
                    "/vendor/laravel/",
                    "/storage/logs/"
                ],
                "files": [
                    "artisan",
                    "composer.json"
                ],
                "headers": [
                    "X-Powered-By:.*Laravel"
                ],
                "cookies": [
                    "laravel_session"
                ],
                "meta": {
                    "generator": "Laravel"
                },
                "html": [],
                "js": []
            },
            "Joomla": {
                "paths": [
                    "/administrator/",
                    "/components/com_"
                ],
                "files": [
                    "configuration.php",
                    "templates/.*?templateDetails\\.xml"
                ],
                "headers": [
                    "X-Content-Encoded-By: Joomla",
                    "Set-Cookie: joomla_[0-9a-f]+"
                ],
                "cookies": [
                    "joomla_[0-9a-f]+"
                ],
                "meta": {
                    "generator": "Joomla!?(?:\\s+[0-9\\.]+)?"
                },
                "html": [
                    "<script[^>]+media=\"all\"[^>]+joomla[^>]+>"
                ],
                "js": []
            },
            "Drupal": {
                "paths": [
                    "/sites/default/",
                    "/misc/drupal.js"
                ],
                "files": [
                    "CHANGELOG\\.txt",
                    "core\\.modules/system/system\\.module"
                ],
                "headers": [
                    "X-Generator: Drupal(?:\\s+[0-9\\.]+)?"
                ],
                "cookies": [
                    "SESS[0-9a-z]+",
                    "Drupal.visitor.[0-9a-f]+"
                ],
                "meta": {
                    "generator": "Drupal(?:\\s+[0-9\\.]+)?"
                },
                "html": [],
                "js": [
                    "drupalSettings"
                ]
            },
            "PrestaShop": {
                "paths": [
                    "/modules/",
                    "/themes/.+?/assets/"
                ],
                "files": [
                    "config/settings\\.inc\\.php"
                ],
                "headers": [
                    "Set-Cookie: PrestaShop-"
                ],
                "cookies": [
                    "PrestaShop-[0-9a-f]+"
                ],
                "meta": {
                    "generator": "PrestaShop"
                },
                "html": [],
                "js": []
            },
            "Magento": {
                "paths": [
                    "/app/etc/",
                    "/skin/frontend/"
                ],
                "files": [
                    "app/etc/local\\.xml"
                ],
                "headers": [
                    "X-Magento-Cache-Debug:",
                    "X-Magento-Vary: "
                ],
                "cookies": [
                    "mage-cache-sessid"
                ],
                "meta": {
                    "generator": "Magento"
                },
                "html": [],
                "js": []
            },
            "Shopify": {
                "paths": [
                    "/cdn\\.shopify\\.com/"
                ],
                "files": [
                    "shopify\\.js"
                ],
                "headers": [
                    "X-ShopId:",
                    "Set-Cookie: _shopify_y"
                ],
                "cookies": [
                    "_orig_referrer",
                    "_secure_session_id"
                ],
                "meta": {
                    "generator": "Shopify"
                },
                "html": [],
                "js": [
                    "window\\.Shopify"
                ]
            },
            "WooCommerce": {
                "paths": [
                    "/wp-content/plugins/woocommerce/"
                ],
                "files": [
                    "woocommerce\\.php"
                ],
                "headers": [
                    "X-WC-Session:"
                ],
                "cookies": [
                    "woocommerce_[a-f0-9]+",
                    "wp_woocommerce_session_[a-f0-9]+"
                ],
                "meta": {
                    "generator": "WooCommerce"
                },
                "html": [],
                "js": []
            }
        }
        
        self.min_match_categories = 2
        self.results_dir = "CMS_REZ"
        self.create_results_directory()
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        })
        self.total_urls = 0
        self.processed_urls = 0

    def create_results_directory(self):
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)
            print(f"{Fore.GREEN}[+] Created directory: {self.results_dir}{Style.RESET_ALL}")

    def normalize_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url

    def check_patterns(self, content, patterns):
        if not patterns:
            return False
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns)

    def get_favicon_hash(self, url):
        try:
            favicon_url = f"{url.rstrip('/')}/favicon.ico"
            response = self.session.get(favicon_url, timeout=5)
            if response.status_code == 200:
                return hashlib.md5(response.content).hexdigest()
        except:
            pass
        return None

    def check_cms(self, url):
        try:
            url = self.normalize_url(url)
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            detected_cms = []
            
            for cms, signatures in self.cms_signatures.items():
                match_categories = 0
                
                # Check paths
                if self.check_patterns(response.text, signatures['paths']):
                    match_categories += 1
                
                # Check headers
                headers_str = str(response.headers)
                if self.check_patterns(headers_str, signatures['headers']):
                    match_categories += 1
                
                # Check cookies
                cookies_str = str(response.cookies)
                if self.check_patterns(cookies_str, signatures['cookies']):
                    match_categories += 1
                
                # Check meta tags
                meta_generator = soup.find('meta', attrs={'name': 'generator'})
                if meta_generator and 'content' in meta_generator.attrs:
                    if re.search(signatures['meta']['generator'], meta_generator['content'], re.IGNORECASE):
                        match_categories += 1
                
                # Check HTML patterns
                if self.check_patterns(response.text, signatures['html']):
                    match_categories += 1
                
                # Check JavaScript patterns
                if self.check_patterns(response.text, signatures['js']):
                    match_categories += 1
                
                # Check files
                for file in signatures['files']:
                    try:
                        file_url = f"{url.rstrip('/')}/{file}"
                        file_response = self.session.head(file_url, timeout=5)
                        if file_response.status_code == 200:
                            match_categories += 1
                            break
                    except:
                        continue

                # Check favicon hash if required
                if signatures.get('favicon_hash'):
                    favicon_hash = self.get_favicon_hash(url)
                    if favicon_hash:
                        match_categories += 1
                
                if match_categories >= self.min_match_categories:
                    detected_cms.append(cms)
            
            return list(set(detected_cms))  # Remove duplicates
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error checking {url}: {str(e)}{Style.RESET_ALL}")
            return []

    def save_results(self, url, detected_cms):
        if detected_cms:
            for cms in detected_cms:
                result_file = os.path.join(self.results_dir, f"{cms.lower()}.txt")
                with open(result_file, 'a') as f:
                    f.write(f"{url}\n")

    def process_url(self, url):
        detected_cms = self.check_cms(url)
        self.processed_urls += 1
        remaining = self.total_urls - self.processed_urls
        if detected_cms:
            print(f"\n{Fore.GREEN}[+] {url} - Detected: {', '.join(detected_cms)} - {remaining} sites remaining{Style.RESET_ALL}")
            self.save_results(url, detected_cms)
        else:
            print(f"\n{Fore.YELLOW}[-] {url} - No CMS detected - {remaining} sites remaining{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='CMS and Framework Detection Tool')
    parser.add_argument('-f', '--file', required=True, help='File containing list of URLs')
    args = parser.parse_args()

    print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════╗")
    print(f"║                CMS DETECTOR v1.0                          ║")
    print(f"╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}")

    detector = CMSDetector()

    try:
        with open(args.file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]

        detector.total_urls = len(urls)
        print(f"\n{Fore.CYAN}[*] Starting CMS detection for {len(urls)} URLs...{Style.RESET_ALL}")
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            executor.map(detector.process_url, urls)

        print(f"\n{Fore.GREEN}[+] Scan completed! Results saved in {detector.results_dir} directory{Style.RESET_ALL}")

    except FileNotFoundError:
        print(f"{Fore.RED}[-] Error: File {args.file} not found{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main() 