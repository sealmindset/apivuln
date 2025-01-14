import argparse
import requests
import jwt
import time
import json
import yaml
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
from requests.exceptions import RequestException

class APIVulnerabilityScanner:
    def __init__(self, api_spec, base_url, proxy=None, token=None, output_format="json", output_file="report"):
        self.api_spec = api_spec
        self.base_url = base_url
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.token = token
        self.headers = {"Authorization": f"Bearer {token}"} if token else {}
        self.output_format = output_format
        self.output_file = output_file
        self.results = []

    def load_spec(self):
        """Load Swagger/OpenAPI specification."""
        try:
            with open(self.api_spec, "r") as f:
                if self.api_spec.endswith(".yml") or self.api_spec.endswith(".yaml"):
                    self.spec = yaml.safe_load(f)
                elif self.api_spec.endswith(".json"):
                    self.spec = json.load(f)
                else:
                    raise ValueError("Unsupported file format. Use .yml, .yaml, or .json.")
        except Exception as e:
            raise ValueError(f"Failed to load API spec: {e}")

    def scan_endpoints(self):
        """Scan endpoints defined in the API spec."""
        paths = self.spec.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                full_url = urljoin(self.base_url, path)
                self.test_endpoint(full_url, method.upper(), details)

    def test_endpoint(self, url, method, details):
        """Test a single endpoint for vulnerabilities."""
        params = details.get("parameters", [])
        print(f"Testing {method} {url}...")
        # Define test cases for vulnerabilities
        self.test_sql_injection(url, method, params)
        self.test_bola(url, method, params)
        self.test_mass_assignment(url, method, params)
        self.test_debug_endpoint(url, method)
        self.test_rate_limiting(url, method)
        self.test_jwt_bypass()

    def test_sql_injection(self, url, method, params):
        """Test for SQL Injection."""
        payloads = ["' OR 1=1 --", "' UNION SELECT NULL--", "' AND SLEEP(5) --"]
        for payload in payloads:
            data = {param["name"]: payload for param in params if param["in"] == "query"}
            try:
                response = self.make_request(method, url, params=data)
                if "error" in response.text.lower() or response.status_code == 500:
                    self.add_result(url, method, "SQL Injection", f"Payload: {payload}", "High", "Sanitize and validate user inputs.")
            except RequestException:
                continue

    def test_bola(self, url, method, params):
        """Test for Broken Object Level Authorization."""
        for param in params:
            if "id" in param["name"]:  # Assume 'id' is a sensitive identifier
                modified_url = url.replace("{id}", "1")
                try:
                    response = self.make_request(method, modified_url)
                    if response.status_code == 200:  # Assuming unauthorized data is returned
                        self.add_result(modified_url, method, "Broken Object Level Authorization", "Accessed unauthorized data.", "High", "Enforce object-level authorization checks.")
                except RequestException:
                    continue

    def test_mass_assignment(self, url, method, params):
        """Test for Mass Assignment."""
        payload = {"is_admin": True}
        try:
            response = self.make_request(method, url, json=payload)
            if response.status_code == 200 and "is_admin" in response.text:
                self.add_result(url, method, "Mass Assignment", "Processed unauthorized field: is_admin.", "High", "Use a whitelist of allowed fields.")
        except RequestException:
            pass

    def test_debug_endpoint(self, url, method):
        """Test for Excessive Data Exposure through Debug Endpoints."""
        if "/debug" in url or "/status" in url or "/config" in url:
            try:
                response = self.make_request(method, url)
                if response.status_code == 200 and "debug" in response.text.lower():
                    self.add_result(url, method, "Excessive Data Exposure", "Debug endpoint exposed sensitive information.", "Medium", "Disable debug endpoints in production.")
            except RequestException:
                pass

    def test_rate_limiting(self, url, method):
        """Test for Lack of Resources & Rate Limiting."""
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(self.make_request, method, url) for _ in range(20)]
            responses = [future.result() for future in futures if future.done()]
            if len(responses) == 20:  # Assume no throttling or rate limiting
                self.add_result(url, method, "Lack of Rate Limiting", "API does not enforce rate limiting.", "Medium", "Implement rate limiting and throttling.")

    def test_jwt_bypass(self):
        """Test for JWT Authentication Bypass."""
        if self.token:
            weak_keys = ["secret", "123456", "password"]
            for key in weak_keys:
                try:
                    fake_token = jwt.encode({"user": "test"}, key, algorithm="HS256")
                    self.headers["Authorization"] = f"Bearer {fake_token}"
                    response = self.make_request("GET", self.base_url)
                    if response.status_code == 200:
                        self.add_result(self.base_url, "GET", "JWT Authentication Bypass", f"Weak key: {key}", "High", "Use strong signing keys.")
                except Exception:
                    continue

    def make_request(self, method, url, params=None, json=None):
        """Make an HTTP request."""
        return requests.request(method, url, headers=self.headers, proxies=self.proxy, params=params, json=json, timeout=5)

    def add_result(self, url, method, issue, result, severity, recommendation):
        """Add a result to the report."""
        self.results.append({
            "endpoint": url,
            "method": method,
            "issue": issue,
            "result": result,
            "severity": severity,
            "recommendation": recommendation,
        })

    def generate_report(self):
        """Generate the report in the specified format."""
        if self.output_format == "json":
            with open(f"{self.output_file}.json", "w") as f:
                json.dump(self.results, f, indent=4)
        elif self.output_format == "csv":
            import csv
            with open(f"{self.output_file}.csv", "w") as f:
                writer = csv.DictWriter(f, fieldnames=self.results[0].keys())
                writer.writeheader()
                writer.writerows(self.results)
        elif self.output_format == "html":
            with open(f"{self.output_file}.html", "w") as f:
                f.write("<html><head><title>API Vulnerability Report</title></head><body>")
                f.write("<h1>API Vulnerability Report</h1><table border='1'>")
                f.write("<tr><th>Endpoint</th><th>Method</th><th>Issue</th><th>Result</th><th>Severity</th><th>Recommendation</th></tr>")
                for result in self.results:
                    f.write(f"<tr><td>{result['endpoint']}</td><td>{result['method']}</td><td>{result['issue']}</td><td>{result['result']}</td><td>{result['severity']}</td><td>{result['recommendation']}</td></tr>")
                f.write("</table></body></html>")
        print(f"Report generated: {self.output_file}.{self.output_format}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="API Vulnerability Scanner")
    parser.add_argument("--input", "-i", required=True, help="Swagger/OpenAPI spec file (YAML/JSON).")
    parser.add_argument("--url", "-u", required=True, help="Base URL of the API.")
    parser.add_argument("--proxy", "-p", help="Proxy URL for requests.")
    parser.add_argument("--token", "-t", help="Bearer token for authentication.")
    parser.add_argument("--format", "-f", choices=["json", "csv", "html"], default="json", help="Report format.")
    parser.add_argument("--output", "-o", default="report", help="Output file name (without extension).")

    args = parser.parse_args()
    scanner = APIVulnerabilityScanner(args.input, args.url, args.proxy, args.token, args.format, args.output)
    scanner.load_spec()
    scanner.scan_endpoints()
    scanner.generate_report()
