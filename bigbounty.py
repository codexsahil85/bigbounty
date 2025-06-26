#!/usr/bin/env python3
"""
Advanced Bug Hunter - Multi-Vulnerability Scanner (v3.1)
Automated detection for IDOR, RCE, SSRF, SSTI, SQLi, XSS with enhanced portability
License: MIT
"""

import asyncio
import aiohttp
import argparse
import sys
import json
import yaml
import logging
import random
import re
import urllib.parse
from datetime import datetime
from tqdm.asyncio import tqdm
import platform
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

class Colors:
    RED = '\033[91m' if platform.system() != 'Windows' else ''
    GREEN = '\033[92m' if platform.system() != 'Windows' else ''
    YELLOW = '\033[93m' if platform.system() != 'Windows' else ''
    BLUE = '\033[94m' if platform.system() != 'Windows' else ''
    PURPLE = '\033[95m' if platform.system() != 'Windows' else ''
    CYAN = '\033[96m' if platform.system() != 'Windows' else ''
    WHITE = '\033[97m' if platform.system() != 'Windows' else ''
    BOLD = '\033[1m' if platform.system() != 'Windows' else ''
    END = '\033[0m' if platform.system() != 'Windows' else ''

class AdvancedBugHunter:
    def __init__(self, config_file='config.yaml', threads=10, timeout=10, rate_limit=10, verbose=False):
        self.threads = threads
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.verbose = verbose
        self.vulnerabilities = []
        self.semaphore = asyncio.Semaphore(rate_limit)
        self.load_config(config_file)
        self.setup_logging()

    def load_config(self, config_file):
        """Load configuration from YAML file"""
        default_config = {
            'headers': {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            'sqli_payloads': [
                "' OR '1'='1",
                "' OR '1'='1'--",
                "' OR SLEEP(5)--"
            ],
            'sqli_errors': [
                r"mysql_fetch_array",
                r"ORA-\d+",
                r"SQLSTATE\["
            ],
            'idor_patterns': [
                r'/user/(\d+)',
                r'id=(\d+)'
            ],
            'ssrf_payloads': [
                "http://127.0.0.1",
                "http://localhost"
            ],
            'ssrf_indicators': [
                "root:x:",
                "localhost"
            ],
            'ssti_payloads': [
                "{{7*7}}",
                "${7*7}"
            ],
            'ssti_indicators': [
                "49",
                "jinja2"
            ],
            'rce_payloads': [
                "; id",
                "$(id)"
            ],
            'rce_indicators': [
                r"uid=\d+\(.*?\)",
                "root:"
            ],
            'xss_payloads': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>"
            ],
            'common_params': [
                "id", "user", "query"
            ]
        }
        
        try:
            with open(config_file, 'r') as f:
                self.config = yaml.safe_load(f) or default_config
        except FileNotFoundError:
            self.config = default_config
            with open(config_file, 'w') as f:
                yaml.dump(default_config, f)
            self.log(f"Generated default config: {config_file}", "INFO")

    def setup_logging(self):
        """Setup logging configuration"""
        log_level = logging.DEBUG if self.verbose else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('bug_hunter.log')
            ]
        )
        self.logger = logging.getLogger(__name__)

    def log(self, message, level="INFO"):
        colors = {
            "INFO": Colors.BLUE,
            "SUCCESS": Colors.GREEN,
            "WARNING": Colors.YELLOW,
            "ERROR": Colors.RED,
            "CRITICAL": Colors.PURPLE
        }
        color = colors.get(level, Colors.WHITE)
        self.logger.log(getattr(logging, level), f"{color}{message}{Colors.END}")

    def save_vulnerability(self, vuln_type, url, payload, evidence="", severity="Medium"):
        vuln = {
            "type": vuln_type,
            "url": url,
            "payload": payload,
            "evidence": evidence,
            "severity": severity,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self.vulnerabilities.append(vuln)
        self.log(f"🚨 {vuln_type} FOUND: {url}", "CRITICAL")

    async def make_request(self, session, url, params=None):
        """Make async HTTP request with rate limiting"""
        async with self.semaphore:
            try:
                async with session.get(url, params=params, timeout=self.timeout) as response:
                    return await response.text(), response.status
            except Exception as e:
                self.log(f"Request error: {str(e)}", "ERROR")
                return "", 0

    async def scan_sql_injection(self, session, url, params=None):
        """Async SQL Injection Scanner"""
        if not params:
            return
        
        async def test_payload(param, payload):
            test_params = params.copy()
            test_params[param] = payload
            start_time = datetime.now()
            text, status = await self.make_request(session, url, test_params)
            response_time = (datetime.now() - start_time).total_seconds()
            
            if response_time > 4:
                self.save_vulnerability(
                    "Time-based SQL Injection",
                    f"{url}?{param}={urllib.parse.quote(payload)}",
                    payload,
                    f"Response time: {response_time:.2f}s",
                    "High"
                )
            
            for pattern in self.config['sqli_errors']:
                if re.search(pattern, text, re.IGNORECASE):
                    self.save_vulnerability(
                        "Error-based SQL Injection",
                        f"{url}?{param}={urllib.parse.quote(payload)}",
                        payload,
                        f"Error pattern: {pattern}",
                        "High"
                    )
                    break

        tasks = [test_payload(param, payload) for param in params for payload in self.config['sqli_payloads']]
        for future in tqdm.as_completed(tasks, desc="SQLi Scan", disable=not self.verbose):
            await future

    async def scan_idor(self, session, url):
        """Async IDOR Scanner"""
        for pattern in self.config['idor_patterns']:
            matches = re.findall(pattern, url)
            if not matches:
                continue
                
            original_id = matches[0]
            test_ids = [str(int(original_id) + 1), str(int(original_id) - 1), "1"]
            
            original_text, original_status = await self.make_request(session, url)
            original_length = len(original_text)
            
            async def test_id(test_id):
                test_url = re.sub(pattern, lambda m: m.group(0).replace(original_id, test_id), url)
                text, status = await self.make_request(session, test_url)
                
                if status == 200 and original_status == 200 and abs(len(text) - original_length) > 100:
                    self.save_vulnerability(
                        "IDOR",
                        test_url,
                        f"ID: {original_id} -> {test_id}",
                        f"Length diff: {abs(len(text) - original_length)}",
                        "High"
                    )
            
            tasks = [test_id(test_id) for test_id in test_ids]
            for future in tqdm.as_completed(tasks, desc="IDOR Scan", disable=not self.verbose):
                await future

    async def scan_ssrf(self, session, url, params=None):
        """Async SSRF Scanner"""
        if not params:
            return
            
        async def test_payload(param, payload):
            test_params = params.copy()
            test_params[param] = payload
            text, _ = await self.make_request(session, url, test_params)
            
            for indicator in self.config['ssrf_indicators']:
                if indicator in text:
                    self.save_vulnerability(
                        "SSRF",
                        f"{url}?{param}={urllib.parse.quote(payload)}",
                        payload,
                        f"Response contains: {indicator}",
                        "High"
                    )
                    break
        
        tasks = [test_payload(param, payload) for param in params for payload in self.config['ssrf_payloads']]
        for future in tqdm.as_completed(tasks, desc="SSRF Scan", disable=not self.verbose):
            await future

    async def scan_ssti(self, session, url, params=None):
        """Async SSTI Scanner"""
        if not params:
            return
            
        async def test_payload(param, payload):
            test_params = params.copy()
            test_params[param] = payload
            text, _ = await self.make_request(session, url, test_params)
            
            for indicator in self.config['ssti_indicators']:
                if indicator in text:
                    self.save_vulnerability(
                        "SSTI",
                        f"{url}?{param}={urllib.parse.quote(payload)}",
                        payload,
                        f"Response contains: {indicator}",
                        "Critical"
                    )
                    break
        
        tasks = [test_payload(param, payload) for param in params for payload in self.config['ssti_payloads']]
        for future in tqdm.as_completed(tasks, desc="SSTI Scan", disable=not self.verbose):
            await future

    async def scan_rce(self, session, url, params=None):
        """Async RCE Scanner"""
        if not params:
            return
            
        async def test_payload(param, payload):
            test_params = params.copy()
            test_params[param] = payload
            start_time = datetime.now()
            text, _ = await self.make_request(session, url, test_params)
            response_time = (datetime.now() - start_time).total_seconds()
            
            if "sleep" in payload and response_time > 4:
                self.save_vulnerability(
                    "Time-based RCE",
                    f"{url}?{param}={urllib.parse.quote(payload)}",
                    payload,
                    f"Response time: {response_time:.2f}s",
                    "Critical"
                )
            
            for pattern in self.config['rce_indicators']:
                if re.search(pattern, text, re.IGNORECASE):
                    self.save_vulnerability(
                        "RCE",
                        f"{url}?{param}={urllib.parse.quote(payload)}",
                        payload,
                        f"Command output: {pattern}",
                        "Critical"
                    )
                    break
        
        tasks = [test_payload(param, payload) for param in params for payload in self.config['rce_payloads']]
        for future in tqdm.as_completed(tasks, desc="RCE Scan", disable=not self.verbose):
            await future

    async def scan_xss(self, session, url, params=None):
        """Async XSS Scanner"""
        if not params:
            return
            
        async def test_payload(param, payload):
            test_params = params.copy()
            test_params[param] = payload
            text, _ = await self.make_request(session, url, test_params)
            
            if payload in text or urllib.parse.unquote(payload) in text:
                self.save_vulnerability(
                    "Reflected XSS",
                    f"{url}?{param}={urllib.parse.quote(payload)}",
                    payload,
                    "Payload reflected in response",
                    "Medium"
                )
        
        tasks = [test_payload(param, payload) for param in params for payload in self.config['xss_payloads']]
        for future in tqdm.as_completed(tasks, desc="XSS Scan", disable=not self.verbose):
            await future

    async def discover_parameters(self, session, url):
        """Discover valid parameters"""
        valid_params = []
        baseline_text, baseline_status = await self.make_request(session, url)
        baseline_length = len(baseline_text)
        
        async def test_param(param):
            test_url = f"{url}?{param}=test"
            text, status = await self.make_request(session, test_url)
            
            if status != baseline_status or abs(len(text) - baseline_length) > 10:
                valid_params.append(param)
                self.log(f"Found parameter: {param}", "SUCCESS")
        
        tasks = [test_param(param) for param in self.config['common_params']]
        for future in tqdm.as_completed(tasks, desc="Parameter Discovery", disable=not self.verbose):
            await future
            
        return valid_params

    async def scan_target(self, session, url, scan_types=None):
        """Main async scanning function"""
        self.log(f"Scanning: {url}", "INFO")
        
        params = await self.discover_parameters(session, url)
        param_dict = {param: "test" for param in params}
        
        scans = {
            'sqli': self.scan_sql_injection,
            'ssrf': self.scan_ssrf,
            'ssti': self.scan_ssti,
            'rce': self.scan_rce,
            'xss': self.scan_xss,
            'idor': self.scan_idor
        }
        
        tasks = []
        for scan_type, scan_func in scans.items():
            if scan_types is None or scan_type in scan_types:
                tasks.append(scan_func(session, url, param_dict if scan_type != 'idor' else None))
        
        await asyncio.gather(*tasks)

    async def scan_multiple_targets(self, urls, scan_types=None):
        """Scan multiple targets concurrently"""
        async with aiohttp.ClientSession(headers=self.config['headers']) as session:
            tasks = [self.scan_target(session, url, scan_types) for url in urls]
            for future in tqdm.as_completed(tasks, desc="Scanning Targets", disable=not self.verbose):
                await future

    def generate_report(self, output_file=None, output_format='json'):
        """Generate vulnerability report in specified format"""
        if not self.vulnerabilities:
            self.log("No vulnerabilities found!", "INFO")
            return
            
        report = {
            "scan_summary": {
                "total_vulnerabilities": len(self.vulnerabilities),
                "critical": len([v for v in self.vulnerabilities if v["severity"] == "Critical"]),
                "high": len([v for v in self.vulnerabilities if v["severity"] == "High"]),
                "medium": len([v for v in self.vulnerabilities if v["severity"] == "Medium"]),
                "low": len([v for v in self.vulnerabilities if v["severity"] == "Low"])
            },
            "vulnerabilities": self.vulnerabilities
        }
        
        if output_file:
            if output_format == 'json':
                with open(output_file, 'w') as f:
                    json.dump(report, f, indent=2)
            elif output_format == 'yaml':
                with open(output_file, 'w') as f:
                    yaml.dump(report, f, default_flow_style=False)
            elif output_format == 'txt':
                with open(output_file, 'w') as f:
                    f.write("=== Advanced Bug Hunter Report ===\n")
                    f.write(f"Total Vulnerabilities: {report['scan_summary']['total_vulnerabilities']}\n")
                    f.write(f"Critical: {report['scan_summary']['critical']}\n")
                    f.write(f"High: {report['scan_summary']['high']}\n")
                    f.write(f"Medium: {report['scan_summary']['medium']}\n")
                    f.write(f"Low: {report['scan_summary']['low']}\n\n")
                    for vuln in report['vulnerabilities']:
                        f.write(f"Type: {vuln['type']}\n")
                        f.write(f"URL: {vuln['url']}\n")
                        f.write(f"Payload: {vuln['payload']}\n")
                        f.write(f"Evidence: {vuln['evidence']}\n")
                        f.write(f"Severity: {vuln['severity']}\n")
                        f.write(f"Timestamp: {vuln['timestamp']}\n")
                        f.write("-" * 50 + "\n")
            self.log(f"Report saved to: {output_file}", "SUCCESS")
        else:
            print(json.dumps(report, indent=2))

async def main():
    parser = argparse.ArgumentParser(
        description="Advanced Bug Hunter - Multi-Vulnerability Scanner (v3.1)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Single URL: python bug_hunter.py -u http://example.com -o report.json
  URL list: python bug_hunter.py -l urls.txt -o report.yaml --format yaml
  Specific scans: python bug_hunter.py -u http://example.com --scans sqli,xss
"""
    )
    parser.add_argument('-u', '--url', help='Single URL to scan')
    parser.add_argument('-l', '--list', help='File containing list of URLs')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-o', '--output', help='Output file for report')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--rate-limit', type=int, default=10, help='Requests per second (default: 10)')
    parser.add_argument('--config', default='config.yaml', help='Configuration file (default: config.yaml)')
    parser.add_argument('--format', choices=['json', 'yaml', 'txt'], default='json', help='Output format (default: json)')
    parser.add_argument('--scans', help='Comma-separated list of scans to run (sqli,ssrf,ssti,rce,xss,idor)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    if not args.url and not args.list:
        parser.print_help()
        sys.exit(1)
    
    scan_types = args.scans.split(',') if args.scans else None
    if scan_types:
        valid_scans = {'sqli', 'ssrf', 'ssti', 'rce', 'xss', 'idor'}
        if not all(scan in valid_scans for scan in scan_types):
            print(f"Error: Invalid scan types. Choose from: {', '.join(valid_scans)}")
            sys.exit(1)
    
    scanner = AdvancedBugHunter(
        config_file=args.config,
        threads=args.threads,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        verbose=args.verbose
    )
    
    print(f"""
{Colors.CYAN}
╔══════════════════════════════════════════════════════════════════╗
║                    ADVANCED BUG HUNTER v3.1                     ║
║         Enhanced Multi-Vulnerability Scanner                    ║
║              IDOR | RCE | SSRF | SSTI | SQLi | XSS              ║
║                   License: MIT                                 ║
╚══════════════════════════════════════════════════════════════════╝
{Colors.END}
    """)
    
    try:
        if args.url:
            async with aiohttp.ClientSession(headers=scanner.config['headers']) as session:
                await scanner.scan_target(session, args.url, scan_types)
        elif args.list:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            await scanner.scan_multiple_targets(urls, scan_types)
        
        scanner.generate_report(args.output, args.format)
        
    except KeyboardInterrupt:
        scanner.log("Scan interrupted by user", "WARNING")
    except Exception as e:
        scanner.log(f"Error: {str(e)}", "ERROR")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
