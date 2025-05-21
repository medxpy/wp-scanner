#!/usr/bin/env python3

import argparse
import json
import sys
import signal
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from colorama import init, Fore, Style
import wappalyzer
from src.utils.helpers import ensure_https, get_timestamp, ensure_reports_dir

# Initialize colorama and logging
init()
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)

class TechDetector:
    def __init__(self, max_workers=5, output_path=None):
        self.should_stop = False
        self.findings = []
        self.max_workers = max_workers
        self.output_path = output_path or (ensure_reports_dir() / 'tech_findings.jsonl')
        signal.signal(signal.SIGINT, self.handle_interrupt)

    def handle_interrupt(self, signum, frame):
        if not self.should_stop:
            self.should_stop = True
            logging.warning('Stopping scan gracefully... Please wait for current operations to complete.')
        else:
            logging.error('Force stopping scan...')
            sys.exit(1)

    def detect_technologies(self, url):
        """Detect technologies and versions using wappalyzer-next."""
        url = ensure_https(url)
        if self.should_stop:
            return None
        try:
            results = wappalyzer.analyze(url)
            tech_versions = {}
            for tech, info in results.get(url, {}).items():
                version = info.get("version", "").strip()
                tech_versions[tech] = version if version else None
            logging.info(f"{Fore.CYAN}{url}{Style.RESET_ALL} - Detected: {tech_versions}")
            return {
                "url": url,
                "technologies": tech_versions,
                "timestamp": get_timestamp()
            }
        except Exception as e:
            logging.error(f"{Fore.RED}{url} - Wappalyzer error: {str(e)}{Style.RESET_ALL}")
            return {
                "url": url,
                "error": str(e),
                "timestamp": get_timestamp()
            }

    def scan_urls(self, urls):
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_url = {executor.submit(self.detect_technologies, url): url for url in urls}
            for future in as_completed(future_to_url):
                if self.should_stop:
                    break
                result = future.result()
                if result:
                    self.findings.append(result)

    def save_findings(self):
        if not self.findings:
            return
        with open(self.output_path, 'w', encoding='utf-8') as f:
            for finding in self.findings:
                f.write(json.dumps(finding) + '\n')
        logging.info(f"Results saved in {self.output_path}")

def main():
    parser = argparse.ArgumentParser(description='Technology Detector using Wappalyzer')
    parser.add_argument('-f', '--file', required=True, help='File containing list of URLs')
    parser.add_argument('-o', '--output', help='Output file path (default: reports/tech_findings.jsonl)')
    parser.add_argument('-w', '--workers', type=int, default=5, help='Number of concurrent workers (default: 5)')
    args = parser.parse_args()

    logging.info(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════╗\n"
                 f"║                Technology Detector v1.0                ║\n"
                 f"╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}")

    try:
        with open(args.file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
        if not urls:
            logging.error('No URLs found in the input file.')
            sys.exit(1)
        detector = TechDetector(max_workers=args.workers, output_path=args.output)
        logging.info(f"[*] Starting technology detection for {len(urls)} URLs...")
        logging.info(f"[!] Press Ctrl+C to stop the scan gracefully")
        detector.scan_urls(urls)
        detector.save_findings()
        if detector.should_stop:
            logging.warning('Scan stopped by user. Partial results saved.')
        else:
            logging.info('Detection completed!')
    except FileNotFoundError:
        logging.error(f"File {args.file} not found.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()