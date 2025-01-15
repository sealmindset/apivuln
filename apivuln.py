#!/usr/bin/env python3
"""
API Vulnerability Scanner - OWASP API Security Top 10 (2023 Edition)
Revised to expand SQL injection tests to:
- Query parameters
- JSON body parameters
- Path parameters

Additional adjustments to Broken Object Level Authorization (BOLA)
to also replace {id} in path parameters.
"""

import argparse
import json
import yaml
import requests
import jwt
import re
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
from requests.exceptions import RequestException


class APIVulnerabilityScanner:
    """
    Scans API endpoints (from a Swagger/OpenAPI spec) for vulnerabilities
    identified in the OWASP API Security Top 10 (2023).
    """
    def __init__(self, spec_file, base_url, proxy=None, token=None,
                 output_format="json", output_file="report"):
        self.spec_file = spec_file
        self.base_url = base_url
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.token = token
        self.headers = {"Authorization": f"Bearer {token}"} if token else {}
        self.output_format = output_format
        self.output_file = output_file

        # Will store any discovered vulnerabilities
        self.results = []

    def load_spec(self):
        """Load the OpenAPI/Swagger specification from file."""
        try:
            with open(self.spec_file, "r") as f:
                if self.spec_file.endswith(".yml") or self.spec_file.endswith(".yaml"):
                    self.spec = yaml.safe_load(f)
                elif self.spec_file.endswith(".json"):
                    self.spec = json.load(f)
                else:
                    raise ValueError("Unsupported file format. Use .yml, .yaml, or .json.")
        except Exception as e:
            raise ValueError(f"Failed to load API spec: {e}")

    def scan_endpoints(self):
        """Enumerate and test each path in the spec."""
        paths = self.spec.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                method = method.upper()
                url = urljoin(self.base_url, path)
                print(f"[*] Testing {method} {url}")
                self.test_endpoint(url, method, path, details)

    def test_endpoint(self, url, method, path_str, details):
        """
        Calls each OWASP API Top 10 (2023) test method in turn.
        - path_str is the raw path (e.g., '/users/{id}'), which helps with path param injection.
        - details is the operation spec from the OpenAPI file.
        """
        # 1) Broken Object Level Authorization (BOLA)
        self.test_broken_object_level_auth(url, method, path_str, details)

        # 2) Broken Authentication
        self.test_broken_authentication(url, method)

        # 3) Broken Object Property Level Authorization (NEW in 2023)
        self.test_broken_object_property_auth(url, method, details)

        # 4) Unrestricted Resource Consumption (expanded from “Lack of Resources & Rate Limiting”)
        self.test_unrestricted_resource_consumption(url, method)

        # 5) Broken Function Level Authorization
        self.test_broken_function_level_auth(url, method)

        # 6) Server Side Request Forgery (SSRF) - NEW in 2023
        self.test_ssrf(url, method)

        # 7) Security Misconfiguration
        self.test_security_misconfiguration(url, method)

        # 8) Lack of Protection from Automated Threats (expanded in 2023)
        self.test_lack_automated_threat_protection(url, method)

        # 9) Improper Inventory Management (formerly “Improper Assets Management”)
        self.test_improper_inventory_management(url, method)

        # 10) Unsafe Consumption of APIs (NEW in 2023)
        self.test_unsafe_consumption(url, method)

        # Extra: Revised SQL Injection coverage
        self.test_sql_injection(url, method, path_str, details)

        # Extra: JWT Bypass
        self.test_jwt_bypass()

    # ---------------------------------------------------------------------
    # 1. Broken Object Level Authorization (BOLA)
    # ---------------------------------------------------------------------
    def test_broken_object_level_auth(self, url, method, path_str, details):
        """
        Attempt to manipulate an 'id' or object identifier in both:
        - Path param replacement (e.g., /users/{id})
        - Query parameters (if declared in the spec)
        """
        params = details.get("parameters", [])

        # A) Path-based ID Replacement
        if "{" in path_str and "}" in path_str:
            # Check if path_str has something like {id}, {userId}, etc.
            # We'll replace any {whatever} with "1"
            # WARNING: if multiple path params exist, do them one at a time for thoroughness
            # For simplicity, we do a single replacement for demonstration.
            forced_param_url = re.sub(r"\{[^}]+\}", "1", url)
            try:
                resp = self.make_request(method, forced_param_url)
                if resp.status_code == 200:
                    self.add_result(
                        forced_param_url, method, "Broken Object Level Authorization",
                        "Endpoint returned 200 after forcibly replacing path param with '1'.",
                        "High",
                        "Validate that the authenticated user is authorized for this object."
                    )
            except RequestException:
                pass

        # B) Query-based ID Replacement
        for p in params:
            if p.get("in") == "query" and "id" in p.get("name", "").lower():
                try:
                    # If there's an 'id' param, forcibly set it
                    forced_data = {p["name"]: "1"}
                    resp = self.make_request(method, url, params=forced_data)
                    if resp.status_code == 200:
                        self.add_result(
                            url, method, "Broken Object Level Authorization",
                            f"Query param {p['name']}=1 returned 200 (potential BOLA).",
                            "High",
                            "Ensure ownership checks on the requested object."
                        )
                except RequestException:
                    pass

    # ---------------------------------------------------------------------
    # 2. Broken Authentication
    # ---------------------------------------------------------------------
    def test_broken_authentication(self, url, method):
        original_headers = dict(self.headers)

        # Attempt with no token
        self.headers.pop("Authorization", None)
        try:
            resp = self.make_request(method, url)
            if resp.status_code == 200:
                self.add_result(
                    url, method, "Broken Authentication",
                    "Endpoint returned 200 with no authentication token.",
                    "High",
                    "Require valid authentication for this endpoint."
                )
        except RequestException:
            pass

        # Attempt with invalid token
        self.headers["Authorization"] = "Bearer invalid_token"
        try:
            resp = self.make_request(method, url)
            if resp.status_code == 200:
                self.add_result(
                    url, method, "Broken Authentication",
                    "Endpoint returned 200 with an invalid token.",
                    "High",
                    "Properly validate bearer tokens."
                )
        except RequestException:
            pass

        self.headers = original_headers

    # ---------------------------------------------------------------------
    # 3. Broken Object Property Level Authorization (2023)
    # ---------------------------------------------------------------------
    def test_broken_object_property_auth(self, url, method, details):
        """
        Tests whether a user can manipulate object properties that belong to another user.
        """
        # Only relevant if the endpoint might accept JSON data
        if method in ("POST", "PUT", "PATCH") and details.get("requestBody"):
            # Attempt overriding a property like "user_id"
            payload = {
                "user_id": "1",   # Suppose the current user shouldn't be able to set this
                "email": "attacker@example.com"
            }
            try:
                resp = self.make_request(method, url, json=payload)
                if resp.status_code == 200 and "attacker@example.com" in resp.text:
                    self.add_result(
                        url, method, "Broken Object Property Level Authorization",
                        "Successfully updated another user's property (email/user_id).",
                        "High",
                        "Implement property-level access checks in the server logic."
                    )
            except RequestException:
                pass

    # ---------------------------------------------------------------------
    # 4. Unrestricted Resource Consumption (2023)
    # ---------------------------------------------------------------------
    def test_unrestricted_resource_consumption(self, url, method):
        # Concurrency / rate limiting check
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self.make_request, method, url) for _ in range(20)]
            responses = []
            for f in futures:
                try:
                    r = f.result()
                    responses.append(r)
                except:
                    pass

        success_count = sum(1 for r in responses if r and r.status_code == 200)
        if success_count == 20:
            self.add_result(
                url, method, "Unrestricted Resource Consumption",
                "No sign of throttling or rate limiting after 20 concurrent requests.",
                "Medium",
                "Implement resource quotas or throttling to prevent DoS or abuse."
            )

        # Large payload test (for POST or PUT)
        if method in ("POST", "PUT"):
            large_payload = {"data": "A" * 1000000}  # ~1 MB of data
            try:
                start_time = time.time()
                resp = self.make_request(method, url, json=large_payload)
                duration = time.time() - start_time
                # If server returns 200 and didn't reject or limit large content
                if resp.status_code == 200 and duration > 2:
                    self.add_result(
                        url, method, "Unrestricted Resource Consumption",
                        "Server accepted ~1MB payload with no restriction or significant delay.",
                        "Medium",
                        "Enforce max request sizes and resource usage quotas."
                    )
            except RequestException:
                pass

    # ---------------------------------------------------------------------
    # 5. Broken Function Level Authorization
    # ---------------------------------------------------------------------
    def test_broken_function_level_auth(self, url, method):
        if any(kw in url.lower() for kw in ["/admin", "/manage", "/root", "/super"]):
            original_headers = dict(self.headers)
            self.headers["Authorization"] = "Bearer normal_user_token"  # Fake normal token
            try:
                resp = self.make_request(method, url)
                if resp.status_code == 200:
                    self.add_result(
                        url, method, "Broken Function Level Authorization",
                        "Privileged endpoint returned 200 with a non-privileged token.",
                        "High",
                        "Check role-based or function-level authorization on server side."
                    )
            except RequestException:
                pass
            self.headers = original_headers

    # ---------------------------------------------------------------------
    # 6. Server Side Request Forgery (SSRF) - NEW in 2023
    # ---------------------------------------------------------------------
    def test_ssrf(self, url, method):
        # Check for known param names that might accept a URL
        if method in ("GET", "POST"):
            possible_params = ["url", "endpoint", "target", "link"]
            for param in possible_params:
                try:
                    data = {param: "http://127.0.0.1:80"}
                    # For GET, put in query; for POST/PUT, put in body
                    if method == "GET":
                        resp = self.make_request(method, url, params=data)
                    else:
                        resp = self.make_request(method, url, json=data)

                    # If response suggests connection attempt or error
                    if resp.status_code == 500 or "refused" in resp.text.lower():
                        self.add_result(
                            url, method, "Server Side Request Forgery (SSRF)",
                            f"Possible SSRF with param '{param}' to 127.0.0.1:80.",
                            "High",
                            "Validate or restrict external resource fetching within the API."
                        )
                except RequestException:
                    pass

    # ---------------------------------------------------------------------
    # 7. Security Misconfiguration
    # ---------------------------------------------------------------------
    def test_security_misconfiguration(self, url, method):
        try:
            resp = self.make_request(method, url)
            server_hdr = resp.headers.get("Server", "")
            powered_by = resp.headers.get("X-Powered-By", "")

            if server_hdr and server_hdr.lower() != "":
                self.add_result(
                    url, method, "Security Misconfiguration",
                    f"Server header reveals info: {server_hdr}",
                    "Low",
                    "Hide or mask server version info in responses."
                )
            if powered_by:
                self.add_result(
                    url, method, "Security Misconfiguration",
                    f"X-Powered-By header found: {powered_by}",
                    "Low",
                    "Hide or mask framework version info in responses."
                )

        except RequestException:
            pass

    # ---------------------------------------------------------------------
    # 8. Lack of Protection from Automated Threats (2023)
    # ---------------------------------------------------------------------
    def test_lack_automated_threat_protection(self, url, method):
        # Basic repeated request test
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(self.make_request, method, url) for _ in range(15)]
            responses = []
            for f in futures:
                try:
                    r = f.result()
                    responses.append(r)
                except:
                    pass

        if all(r and r.status_code == 200 for r in responses):
            self.add_result(
                url, method, "Lack of Protection from Automated Threats",
                "No sign of anti-bot or anti-automation after 15 requests.",
                "Medium",
                "Implement CAPTCHAs, IP-based blocking, or anomaly detection."
            )

    # ---------------------------------------------------------------------
    # 9. Improper Inventory Management (2023)
    # ---------------------------------------------------------------------
    def test_improper_inventory_management(self, url, method):
        # Looks for dev or older version endpoints
        keywords = ["/v1", "/v2", "/beta", "/old", "/debug", "/test", "/backup"]
        if any(kw in url.lower() for kw in keywords):
            self.add_result(
                url, method, "Improper Inventory Management",
                "Potential dev/test/old endpoint found in production.",
                "Medium",
                "Remove or restrict outdated and unused endpoints."
            )

    # ---------------------------------------------------------------------
    # 10. Unsafe Consumption of APIs (2023)
    # ---------------------------------------------------------------------
    def test_unsafe_consumption(self, url, method):
        try:
            resp = self.make_request(method, url)
            # Very naive check for external references
            if "http://" in resp.text or "https://" in resp.text:
                self.add_result(
                    url, method, "Unsafe Consumption of APIs",
                    "Response includes external domain references (heuristic).",
                    "Low",
                    "Validate or secure all external API calls or references."
                )
        except RequestException:
            pass

    # ---------------------------------------------------------------------
    # Extra: Revised SQL Injection Coverage
    # ---------------------------------------------------------------------
    def test_sql_injection(self, url, method, path_str, details):
        """
        Expands coverage to:
        - Query parameters
        - JSON body (if requestBody is expected)
        - Path parameters (if {something} is present)
        """
        sqli_payloads = [
            "' OR 1=1 --",
            "' UNION SELECT NULL--",
            "' OR sleep(2) --"
        ]

        # 1) Query param injection
        params = details.get("parameters", [])
        query_data = {}
        # We'll inject just the first payload for demonstration in each param
        for p in params:
            if p.get("in") == "query":
                query_data[p["name"]] = sqli_payloads[0]  # e.g. ' OR 1=1 --
        if query_data:
            try:
                resp = self.make_request(method, url, params=query_data)
                if self.is_sqli_response(resp):
                    self.add_result(
                        url, method, "Injection (SQLi)",
                        f"Potential SQL injection with query param: {sqli_payloads[0]}",
                        "High",
                        "Use parameterized queries and sanitize user input."
                    )
            except RequestException:
                pass

        # 2) JSON body injection
        # Check if requestBody is specified
        if details.get("requestBody") and method in ("POST", "PUT", "PATCH"):
            # We guess some common fields for demonstration:
            body_payload = {
                "username": sqli_payloads[1],
                "password": "Pass123"
            }
            try:
                resp = self.make_request(method, url, json=body_payload)
                if self.is_sqli_response(resp):
                    self.add_result(
                        url, method, "Injection (SQLi)",
                        f"Potential SQL injection in JSON body (username): {sqli_payloads[1]}",
                        "High",
                        "Use parameterized queries and sanitize user input."
                    )
            except RequestException:
                pass

        # 3) Path parameter injection
        # If something like /users/{id} is present
        # We'll replace each {param} with an sqli payload in turn
        path_params = re.findall(r"\{([^}]+)\}", path_str)
        if path_params:
            for param_name in path_params:
                for payload in sqli_payloads:
                    # Replace {param_name} in the original path with the payload
                    test_url = url.replace(f"{{{param_name}}}", payload)
                    try:
                        resp = self.make_request(method, test_url)
                        if self.is_sqli_response(resp):
                            self.add_result(
                                test_url, method, "Injection (SQLi)",
                                f"Potential SQL injection by replacing path param '{param_name}' with: {payload}",
                                "High",
                                "Use parameterized queries and sanitize user input in path parameters."
                            )
                    except RequestException:
                        pass

    def is_sqli_response(self, resp):
        """
        Heuristic to check if a response indicates a potential SQL injection:
        - HTTP 500
        - Contains "sql", "syntax", "database error", etc. in the body
        """
        if not resp:
            return False
        if resp.status_code == 500:
            return True
        body_lower = resp.text.lower()
        return any(
            keyword in body_lower
            for keyword in ["sql", "syntax", "database error", "sql error"]
        )

    # ---------------------------------------------------------------------
    # Extra: JWT Bypass
    # ---------------------------------------------------------------------
    def test_jwt_bypass(self):
        if self.token:
            weak_keys = ["secret", "123456", "password"]
            original_headers = dict(self.headers)

            for key in weak_keys:
                try:
                    forged_token = jwt.encode({"user": "fake"}, key, algorithm="HS256")
                    self.headers["Authorization"] = f"Bearer {forged_token}"
                    resp = self.make_request("GET", self.base_url)
                    if resp and resp.status_code == 200:
                        self.add_result(
                            self.base_url, "GET", "JWT Authentication Bypass",
                            f"Endpoint accepted forged token (weak key: '{key}')",
                            "High",
                            "Use strong, unique signing keys and verify signatures properly."
                        )
                except Exception:
                    pass

            self.headers = original_headers

    # ---------------------------------------------------------------------
    # HTTP Request Helper
    # ---------------------------------------------------------------------
    def make_request(self, method, url, params=None, json=None):
        """
        Makes a generic HTTP request, returning the response.
        """
        return requests.request(
            method=method,
            url=url,
            headers=self.headers,
            proxies=self.proxy,
            params=params,
            json=json,
            timeout=5,
            allow_redirects=True
        )

    def add_result(self, endpoint, method, issue, result, severity, recommendation):
        """
        Stores a single vulnerability discovery in self.results.
        """
        finding = {
            "endpoint": endpoint,
            "method": method,
            "issue": issue,
            "result": result,
            "severity": severity,
            "recommendation": recommendation,
        }
        # Avoid duplicates with a naive check
        if finding not in self.results:
            self.results.append(finding)

    def generate_report(self):
        """
        Save the final findings in the requested format.
        """
        if not self.results:
            print("\nNo findings detected or no endpoints tested.\n")
            return

        if self.output_format == "json":
            out_file = f"{self.output_file}.json"
            with open(out_file, "w") as f:
                json.dump(self.results, f, indent=4)
            print(f"\nReport written to: {out_file}")

        elif self.output_format == "csv":
            import csv
            out_file = f"{self.output_file}.csv"
            with open(out_file, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=self.results[0].keys())
                writer.writeheader()
                writer.writerows(self.results)
            print(f"\nReport written to: {out_file}")

        elif self.output_format == "html":
            out_file = f"{self.output_file}.html"
            with open(out_file, "w") as f:
                f.write("<html><head><title>API Vulnerability Report</title></head><body>")
                f.write("<h1>API Vulnerability Report</h1>")
                f.write("<table border='1'><tr>")
                headers = list(self.results[0].keys())
                for header in headers:
                    f.write(f"<th>{header}</th>")
                f.write("</tr>")
                for row in self.results:
                    f.write("<tr>")
                    for header in headers:
                        f.write(f"<td>{row[header]}</td>")
                    f.write("</tr>")
                f.write("</table></body></html>")
            print(f"\nReport written to: {out_file}")

def main():
    parser = argparse.ArgumentParser(
        description="OWASP API Security Top 10 Scanner (2023) - Revised for Broader SQLi Testing"
    )
    parser.add_argument(
        "--input", "-i", required=True,
        help="Swagger/OpenAPI specification file (YAML/JSON)."
    )
    parser.add_argument(
        "--url", "-u", required=True,
        help="Base URL of the target API."
    )
    parser.add_argument(
        "--proxy", "-p",
        help="Optional proxy (e.g. http://127.0.0.1:8080)."
    )
    parser.add_argument(
        "--token", "-t",
        help="Bearer token for authentication (optional)."
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "csv", "html"],
        default="json",
        help="Report output format (default: json)."
    )
    parser.add_argument(
        "--output", "-o",
        default="report",
        help="Output file name (without extension). (default: report)"
    )

    args = parser.parse_args()

    scanner = APIVulnerabilityScanner(
        spec_file=args.input,
        base_url=args.url,
        proxy=args.proxy,
        token=args.token,
        output_format=args.format,
        output_file=args.output
    )

    scanner.load_spec()
    scanner.scan_endpoints()
    scanner.generate_report()

if __name__ == "__main__":
    main()
