"""
Plugin Version Checker Module
Handles detection and version checking of WordPress plugins
"""

import re
from packaging import version

class PluginChecker:
    def __init__(self):
        self.vulnerable_plugins = {
            'wp-file-manager': {
                'name': 'WP File Manager',
                'vulnerable_versions': '<=6.8',
                'readme_path': '/wp-content/plugins/wp-file-manager/readme.txt',
                'php_path': '/wp-content/plugins/wp-file-manager/wp-file-manager.php',
                'cve': 'CVE-2020-25213'
            },
            'wp-statistics': {
                'name': 'WP Statistics',
                'vulnerable_versions': '<=13.1.5',
                'readme_path': '/wp-content/plugins/wp-statistics/readme.txt',
                'php_path': '/wp-content/plugins/wp-statistics/wp-statistics.php',
                'cve': 'CVE-2022-25148'
            },
            'wpdiscuz': {
                'name': 'wpDiscuz',
                'vulnerable_versions': '<=7.0.4',
                'readme_path': '/wp-content/plugins/wpdiscuz/readme.txt',
                'php_path': '/wp-content/plugins/wpdiscuz/wpdiscuz.php',
                'cve': 'CVE-2020-24186'
            },
            'wp-file-upload': {
                'name': 'WordPress File Upload',
                'vulnerable_versions': '<=4.24.12',
                'readme_path': '/wp-content/plugins/wp-file-upload/readme.txt',
                'php_path': '/wp-content/plugins/wp-file-upload/wp-file-upload.php',
                'cve': 'CVE-2024-11635'
            },
            'wp-time-capsule': {
                'name': 'Backup & Staging by WP Time Capsule',
                'vulnerable_versions': '<=1.21.16',
                'readme_path': '/wp-content/plugins/wp-time-capsule/readme.txt',
                'php_path': '/wp-content/plugins/wp-time-capsule/wp-time-capsule.php',
                'cve': 'CVE-2024-8856'
            },
            'smart-product-review': {
                'name': 'Smart Product Review',
                'vulnerable_versions': '<=1.0.4',
                'readme_path': '/wp-content/plugins/smart-product-review/readme.txt',
                'php_path': '/wp-content/plugins/smart-product-review/smart-product-review.php',
                'cve': 'CVE-2021-4455'
            }
        }

    def get_plugin_version(self, session, url, plugin_slug):
        """Get plugin version from readme.txt or PHP file"""
        plugin_info = self.vulnerable_plugins[plugin_slug]
        
        # Try readme.txt first
        readme_url = url + plugin_info['readme_path']
        try:
            response = session.get(readme_url, timeout=10)
            if response.status_code == 200:
                # Look for Stable tag
                stable_match = re.search(r'Stable tag:\s*([\d\.]+)', response.text)
                if stable_match:
                    return stable_match.group(1)
        except:
            pass

        # Try PHP file if readme.txt fails
        php_url = url + plugin_info['php_path']
        try:
            response = session.get(php_url, timeout=10)
            if response.status_code == 200:
                # Look for Version in PHP header
                version_match = re.search(r'Version:\s*([\d\.]+)', response.text)
                if version_match:
                    return version_match.group(1)
        except:
            pass

        return None

    def is_plugin_vulnerable(self, plugin_slug, version_str):
        """Check if plugin version is vulnerable"""
        if not version_str:
            return False

        plugin_info = self.vulnerable_plugins[plugin_slug]
        vulnerable_versions = plugin_info['vulnerable_versions']
        
        # Parse version string
        try:
            current_version = version.parse(version_str)
            if vulnerable_versions.startswith('<='):
                max_version = version.parse(vulnerable_versions[2:])
                return current_version <= max_version
            elif vulnerable_versions.startswith('<'):
                max_version = version.parse(vulnerable_versions[1:])
                return current_version < max_version
        except:
            return False

        return False

    def check_plugin(self, session, url, plugin_slug):
        """Check if plugin is present and vulnerable"""
        plugin_info = self.vulnerable_plugins[plugin_slug]
        
        # Check if plugin exists
        try:
            response = session.get(url + plugin_info['php_path'], timeout=10)
            if response.status_code != 200:
                return False, None, None
        except:
            return False, None, None

        # Get version
        version_str = self.get_plugin_version(session, url, plugin_slug)
        if not version_str:
            return True, None, None  # Plugin exists but version unknown

        # Check if vulnerable
        is_vulnerable = self.is_plugin_vulnerable(plugin_slug, version_str)
        return True, version_str, is_vulnerable 