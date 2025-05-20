"""
CVE-2023-6961: WordPress Plugin Directory Traversal
Description: Directory traversal vulnerability in WordPress plugin allowing unauthorized access to sensitive files
Severity: High
CVSS Score: 7.5
Affected Versions: Multiple WordPress plugins
Reference: https://wpscan.com/vulnerability/12345
"""

def get_payload():
    return {
        'path': '/wp-admin/admin-ajax.php',
        'method': 'POST',
        'headers': {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        'data': {
            'action': 'test_action',
            'nonce': 'test_nonce'
        }
    }

def check_response(response):
    return response.status_code == 200 and 'wp_die' not in response.text 