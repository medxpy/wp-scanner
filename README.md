# WordPress Security Scanner

A comprehensive security scanner for WordPress sites that combines CMS detection, plugin vulnerability scanning, and security assessment.

## Features

- **CMS Detection**: Identifies WordPress installations and their versions
- **Plugin Vulnerability Scanner**: Detects vulnerable plugins and their versions
- **CVE Testing**: Tests for known vulnerabilities in WordPress core and plugins
- **Parallel Scanning**: Efficient scanning of multiple sites
- **Detailed Reporting**: JSONL output with evidence and timestamps

## Project Structure

```
wordpress-scanner/
├── src/
│   ├── core/
│   │   ├── __init__.py
│   │   ├── scanner.py        # Main scanner class
│   │   └── plugin_checker.py # Plugin version detection
│   ├── payloads/
│   │   ├── __init__.py
│   │   ├── cve_2024_2194.py
│   │   ├── cve_2023_6961.py
│   │   └── ...              # Other CVE payloads
│   └── utils/
│       ├── __init__.py
│       └── helpers.py       # Helper functions
├── reports/                 # Scan results directory
├── tests/                   # Test files
├── requirements.txt         # Python dependencies
├── wp_scanner.py           # Entry point script
└── README.md               # This file
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/wordpress-scanner.git
cd wordpress-scanner
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Create a text file with target URLs (one per line):
```bash
echo "example.com" > targets.txt
```

2. Run the scanner:
```bash
python wp_scanner.py -f targets.txt
```

3. View results:
```bash
cat reports/findings.jsonl
```

## Output Format

The scanner generates two types of output:

1. **Console Output**: Real-time scanning progress and findings
   - Green [+] for vulnerabilities found
   - Yellow [-] for non-vulnerable checks
   - Red [-] for errors

2. **JSONL Report**: Detailed findings in `reports/findings.jsonl`
   ```json
   {
     "url": "https://example.com",
     "cve": "CVE-2024-2194",
     "evidence": {
       "status_code": 200,
       "response_length": 1234,
       "response_sample": "...",
       "response_time": 0.5
     },
     "timestamp": "2024-03-14T12:00:00Z"
   }
   ```

## Supported Vulnerabilities

- WordPress Core CVEs
- Plugin-specific vulnerabilities:
  - WP File Manager
  - WP Statistics
  - wpDiscuz
  - WordPress File Upload
  - WP Time Capsule
  - Smart Product Review

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add your payload or enhancement
4. Submit a pull request

## License

MIT License - See LICENSE file for details

## Disclaimer

This tool is for educational and security research purposes only. Always obtain proper authorization before scanning any website. 