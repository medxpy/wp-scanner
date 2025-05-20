"""
Helper functions for the WordPress scanner
"""

import random
from datetime import datetime
from pathlib import Path

# List of user agents for randomization
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59'
]

def get_random_headers():
    """Generate random headers for requests"""
    return {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }

def ensure_https(url):
    """Ensure URL starts with https://"""
    if not url.startswith(('http://', 'https://')):
        return 'https://' + url
    return url

def get_timestamp():
    """Get current timestamp in ISO format"""
    return datetime.now().isoformat()

def ensure_reports_dir():
    """Ensure reports directory exists"""
    reports_dir = Path('reports')
    reports_dir.mkdir(exist_ok=True)
    return reports_dir 