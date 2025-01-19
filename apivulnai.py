#!/usr/bin/env python3
"""
<<<<<<< HEAD
API Vulnerability Scanner - OWASP API Security Top 10 (2023 Edition)
Enhanced verbosity with full request/response logs and updated OpenAI API integration.
Includes additional security tests.
=======
API Vulnerability Scanner - OWASP API Security Top 10 (2023)
Integrated with OpenAI's new interface in openai>=1.0.0

Key Revisions:
- Uses openai.chat.completions.create(...) for calls to GPT models.
- Accesses response via completion["choices"][0]["message"]["content"].
- Removes references to .completions[0].
>>>>>>> 2576abf4f1b4550ab08cb9fe38f7bf1cb07b90d8
"""

import argparse
import json
import yaml
import requests
<<<<<<< HEAD
import re
import os
import base64
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
from requests.exceptions import RequestException
import openai

class APIVulnerabilityScanner:
    """
    Scans API endpoints (from a Swagger/OpenAPI spec) for vulnerabilities identified in
    the OWASP API Security Top 10 (2023) with full request/response logs and updated OpenAI API integration.
    Includes additional security tests.
    """
    def __init__(self, spec_file=None, base_url=None, proxy=None, token=None,
                 output_format="json", output_file="report"):
=======
import jwt
import re
import time
import openai  # Must be openai>=1.0.0
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
from requests.exceptions import RequestException


class APIVulnerabilityScanner:
    """
    Scans API endpoints for OWASP API Top 10 vulnerabilities.
    If openai_analysis is enabled, each test's HTTP response is also
    sent to OpenAI with a custom prompt for a deeper AI-based review.
    """
    def __init__(
        self,
        spec_file=None,
        base_url=None,
        proxy=None,
        token=None,
        output_format="json",
        output_file="report",
        openai_api_key=None,
        openai_analysis=False
    ):
>>>>>>> 2576abf4f1b4550ab08cb9fe38f7bf1cb07b90d8
        self.spec_file = spec_file
        self.base_url = base_url
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.token = token
        self.headers = {"Authorization": f"Bearer {token}"} if token else {}
        self.output_format = output_format
        self.output_file = output_file

<<<<<<< HEAD
        # OpenAI API key
        openai.api_key = os.getenv("OPENAI_API_KEY")

        # Store discovered vulnerabilities
        self.results = []

        # Define all test methods
        self.test_methods = [
            self.test_broken_object_level_auth,
            self.test_broken_authentication,
            self.test_excessive_data_exposure,
            self.test_lack_of_resources_and_rate_limiting,
            self.test_broken_function_level_authorization,
            self.test_mass_assignment,
            self.test_security_misconfiguration,
            self.test_injection,
            self.test_sql_injection,
            self.test_improper_assets_management,
            self.test_insufficient_logging_and_monitoring,
            # Additional Tests
            self.test_secure_transmission,
            self.test_xss,
            self.test_insecure_direct_object_references,
            self.test_graphql_and_websocket_security,
            self.test_file_upload_security,
            self.test_caching_mechanisms,
            self.test_xxe_protection,
            self.test_content_security_policy,
            self.test_api_versioning_security,
            self.test_brute_force_attack_mitigation,
            self.test_unauthorized_data_manipulation,
            self.test_replay_attack_prevention,
            self.test_unauthorized_password_change,
            self.test_excessive_data_exposure_debug_endpoint,
            self.test_user_password_enumeration,
            self.test_regex_dos,
            self.test_jwt_authentication_bypass
        ]

    def log(self, message):
        """Log messages to the console."""
        print(f"[LOG] {message}")

    def load_spec(self):
        """Load the OpenAPI/Swagger specification."""
=======
        # OpenAI configuration
        self.openai_api_key = openai_api_key
        self.openai_analysis = openai_analysis
        if openai_api_key:
            openai.api_key = openai_api_key

        # Will store any discovered vulnerabilities (including AI analysis)
        self.results = []

    def load_spec(self):
        """Load the OpenAPI/Swagger specification from file."""
>>>>>>> 2576abf4f1b4550ab08cb9fe38f7bf1cb07b90d8
        if not self.spec_file:
            raise ValueError("No specification file provided.")
        try:
            with open(self.spec_file, "r") as f:
                if self.spec_file.endswith(".yml") or self.spec_file.endswith(".yaml"):
                    self.spec = yaml.safe_load(f)
                elif self.spec_file.endswith(".json"):
                    self.spec = json.load(f)
                else:
                    raise ValueError("Unsupported file format. Use .yml, .yaml, or .json.")
<<<<<<< HEAD
            self.log("Successfully loaded the OpenAPI/Swagger specification.")
=======
>>>>>>> 2576abf4f1b4550ab08cb9fe38f7bf1cb07b90d8
        except Exception as e:
            raise ValueError(f"Failed to load API spec: {e}")

    def scan_endpoints(self):
<<<<<<< HEAD
        """Enumerate and test paths in the API spec using concurrency."""
        self.log("Starting to scan API endpoints.")
        paths = self.spec.get("paths", {})
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for path, methods in paths.items():
                for method, details in methods.items():
                    method = method.upper()
                    url = urljoin(self.base_url, path)
                    self.log(f"Testing {method} {url}")
                    futures.append(executor.submit(self.test_endpoint, url, method, path, details))
            # Handle results or exceptions
            for future in futures:
                try:
                    future.result()
                except Exception as e:
                    self.log(f"Error during endpoint testing: {e}")

    def test_endpoint(self, url, method, path_str, details):
        """Test an endpoint for vulnerabilities by iterating over all test methods."""
        for test_method in self.test_methods:
            test_name = test_method.__name__
            self.log(f"Running {test_name} on {method} {url}")
            try:
                test_method(url, method, path_str, details)
            except Exception as e:
                self.log(f"Error in {test_name} for {method} {url}: {e}")

    # Existing Test Methods

    def test_broken_object_level_auth(self, url, method, path_str, details):
        """Test for Broken Object Level Authorization."""
        if "{" in path_str and "}" in path_str:
            forced_param_url = re.sub(r"\{[^}]+\}", "1", url)
            try:
                resp = self.make_request(method, forced_param_url)
                if resp and resp.status_code == 200:
                    self.add_result(forced_param_url, method, "Broken Object Level Authorization",
                                   "Endpoint returned 200 after forcibly replacing path parameter.",
                                   "High", "Validate user ownership.", resp)
            except RequestException:
                pass

    def test_broken_authentication(self, url, method, path_str=None, details=None):
        """Test for Broken Authentication."""
        original_headers = dict(self.headers)
=======
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
        Calls each test method for vulnerabilities. Add/modify as needed.
        Here we just show 2 examples for brevity: Broken Authentication, SQLi.
        """
        # Example: Broken Authentication
        self.test_broken_authentication(url, method)

        # Example: SQL Injection
        self.test_sql_injection(url, method, path_str, details)

        # Add other tests, e.g. self.test_mass_assignment(url, method, details), etc.

    # ---------------------------------------------------------------------
    # 1) Broken Authentication Example
    # ---------------------------------------------------------------------
    def test_broken_authentication(self, url, method):
        original_headers = dict(self.headers)

        # Attempt with no token
>>>>>>> 2576abf4f1b4550ab08cb9fe38f7bf1cb07b90d8
        self.headers.pop("Authorization", None)
        try:
            resp = self.make_request(method, url)
            if resp and resp.status_code == 200:
<<<<<<< HEAD
                self.add_result(url, method, "Broken Authentication",
                               "Endpoint returned 200 without authentication.", "High",
                               "Ensure authentication is enforced.", resp)
        finally:
            self.headers = original_headers

    def test_excessive_data_exposure(self, url, method, path_str, details):
        """Test for Excessive Data Exposure."""
        # Send a request and check if sensitive data is exposed in the response
        resp = self.make_request(method, url)
        if resp and resp.status_code == 200:
            sensitive_keywords = ['password', 'secret', 'token', 'apikey', 'creditcard']
            for keyword in sensitive_keywords:
                if keyword in resp.text.lower():
                    self.add_result(url, method, "Excessive Data Exposure",
                                   f"Response contains sensitive keyword: {keyword}",
                                   "Medium", "Limit data exposure to necessary fields.", resp)
                    break

    def test_lack_of_resources_and_rate_limiting(self, url, method, path_str, details):
        """Test for Lack of Resources & Rate Limiting."""
        # Attempt to send multiple rapid requests to check rate limiting
        try:
            for _ in range(10):
                resp = self.make_request(method, url)
                if resp and resp.status_code == 429:
                    return  # Rate limiting is in place
            # If no rate limiting detected
            self.add_result(url, method, "Lack of Resources & Rate Limiting",
                           "No rate limiting detected on the endpoint.", "Low",
                           "Implement rate limiting to protect against DoS attacks.", resp=None)
        except RequestException:
            pass

    def test_broken_function_level_authorization(self, url, method, path_str, details):
        """Test for Broken Function Level Authorization."""
        # Attempt to access admin functionalities without admin privileges
        admin_url = url.replace(self.base_url, self.base_url + "/admin")
        resp = self.make_request(method, admin_url)
        if resp and resp.status_code == 200:
            self.add_result(admin_url, method, "Broken Function Level Authorization",
                           "Admin functionality accessible without proper authorization.", "High",
                           "Enforce proper authorization checks for all function levels.", resp)

    def test_mass_assignment(self, url, method, path_str, details):
        """Test for Mass Assignment."""
        # Send additional unexpected parameters in the request body
        if method in ["POST", "PUT", "PATCH"]:
            payload = {"unexpected_field": "unexpected_value"}
            resp = self.make_request(method, url, json=payload)
            if resp and resp.status_code in [200, 201]:
                self.add_result(url, method, "Mass Assignment",
                               "Endpoint accepted unexpected parameters without validation.", "Medium",
                               "Validate and sanitize all input parameters.", resp)

    def test_security_misconfiguration(self, url, method, path_str, details):
        """Test for Security Misconfiguration."""
        # Check for exposed sensitive files or directories
        common_paths = ["/.git", "/config.php", "/backup.zip"]
        for path in common_paths:
            test_url = urljoin(self.base_url, path)
            resp = self.make_request("GET", test_url)
            if resp and resp.status_code == 200:
                self.add_result(test_url, "GET", "Security Misconfiguration",
                               f"Sensitive file or directory accessible: {path}", "High",
                               "Ensure sensitive files and directories are not publicly accessible.", resp)

    def test_injection(self, url, method, path_str, details):
        """Test for Injection vulnerabilities."""
        # Attempt SQL injection
        injection_payload = "' OR '1'='1"
        if "{" in path_str and "}" in path_str:
            injection_url = re.sub(r"\{[^}]+\}", injection_payload, url)
            resp = self.make_request(method, injection_url)
            if resp and "error" not in resp.text.lower() and resp.status_code == 200:
                self.add_result(injection_url, method, "Injection",
                               "Potential injection vulnerability detected.", "High",
                               "Sanitize and validate all inputs to prevent injection attacks.", resp)

    def test_sql_injection(self, url, method, path_str, details):
        """Test for SQL Injection."""
        self.log("Testing SQL Injection.")
        sql_payload = "'; DROP TABLE users; --"
        injection_point = self.get_injection_point(url, path_str)
        if injection_point:
            vulnerable_url = injection_point.replace("{{injection}}", sql_payload)
            resp = self.make_request(method, vulnerable_url)
            if resp and ("error" in resp.text.lower() or "syntax" in resp.text.lower()):
                self.add_result(vulnerable_url, method, "SQL Injection",
                               "Endpoint may be vulnerable to SQL Injection attacks; error messages detected.",
                               "High", "Use parameterized queries and input validation to prevent SQL Injection.", resp)

    def test_improper_assets_management(self, url, method, path_str, details):
        """Test for Improper Assets Management."""
        # Check for deprecated API versions
        deprecated_versions = ["/v1/", "/v2/"]
        for version in deprecated_versions:
            deprecated_url = url.replace("/v3/", version)
            resp = self.make_request(method, deprecated_url)
            if resp and resp.status_code == 200:
                self.add_result(deprecated_url, method, "Improper Assets Management",
                               f"Deprecated API version accessible: {version}", "Low",
                               "Deprecate and properly manage old API versions.", resp)

    def test_insufficient_logging_and_monitoring(self, url, method, path_str, details):
        """Test for Insufficient Logging & Monitoring."""
        # Trigger a known error and check if it's logged
        error_url = url + "/invalidendpoint"
        resp = self.make_request(method, error_url)
        if resp and resp.status_code == 404:
            # Assuming that a 404 should be logged; since we can't access server logs, we note the need
            self.add_result(error_url, method, "Insufficient Logging & Monitoring",
                           "Potential lack of logging for invalid endpoints.", "Medium",
                           "Implement comprehensive logging and monitoring for all API activities.", resp)

    # Additional Test Methods

    def test_secure_transmission(self, url, method, path_str, details):
        """Test for Secure Transmission (HTTPS)."""
        self.log("Testing Secure Transmission (HTTPS).")
        if not url.startswith("https://"):
            self.add_result(url, method, "Secure Transmission (HTTPS)",
                           "Endpoint does not use HTTPS for secure data transmission.",
                           "High", "Ensure all API endpoints enforce HTTPS to protect data in transit.", resp=None)

    def test_xss(self, url, method, path_str, details):
        """Test for Cross-Site Scripting (XSS)."""
        self.log("Testing Cross-Site Scripting (XSS).")
        xss_payload = "<script>alert('XSS')</script>"
        injection_point = self.get_injection_point(url, path_str)
        if injection_point:
            vulnerable_url = injection_point.replace("{{injection}}", xss_payload)
            resp = self.make_request(method, vulnerable_url)
            if resp and xss_payload in resp.text:
                self.add_result(vulnerable_url, method, "Cross-Site Scripting (XSS)",
                               "Endpoint reflected XSS payload in the response.",
                               "High", "Sanitize and encode all user inputs to prevent XSS attacks.", resp)

    def test_insecure_direct_object_references(self, url, method, path_str, details):
        """Test for Insecure Direct Object References (IDOR)."""
        self.log("Testing Insecure Direct Object References (IDOR).")
        if "{" in path_str and "}" in path_str:
            # Attempt to access another user's resource by incrementing the ID
            original_id = re.search(r"\{([^}]+)\}", path_str).group(1)
            try:
                numeric_id = int("1")
                id_incremented = numeric_id + 1
                idor_url = re.sub(r"\{[^}]+\}", str(id_incremented), url)
                resp = self.make_request(method, idor_url)
                if resp and resp.status_code == 200:
                    self.add_result(idor_url, method, "Insecure Direct Object References (IDOR)",
                                   "Accessed resource with modified object ID.",
                                   "High", "Implement proper authorization checks to prevent IDOR.", resp)
            except ValueError:
                self.log("Non-numeric ID detected; IDOR test may not be applicable.")

    def test_graphql_and_websocket_security(self, url, method, path_str, details):
        """Test for GraphQL and WebSocket Security."""
        self.log("Testing GraphQL and WebSocket Security.")
        if '/graphql' in url.lower():
            # Basic GraphQL introspection query
            graphql_query = {"query": "{ __schema { types { name } } }"}
            resp = self.make_request(method, url, json=graphql_query)
            if resp and "error" in resp.text.lower():
                self.add_result(url, method, "GraphQL Security",
                               "GraphQL introspection query exposed errors.",
                               "Medium", "Disable introspection in production or secure it appropriately.", resp)
        if '/ws' in url.lower():
            # WebSocket security is beyond simple HTTP requests; note the need for specialized testing
            self.log("WebSocket endpoints require specialized testing tools.")

    def test_file_upload_security(self, url, method, path_str, details):
        """Test for File Upload Security."""
        self.log("Testing File Upload Security.")
        if method in ["POST", "PUT", "PATCH"]:
            files = {'file': ('test.exe', b'Executable content', 'application/octet-stream')}
            resp = self.make_request(method, url, files=files)
            if resp and resp.status_code == 200:
                self.add_result(url, method, "File Upload Security",
                               "Endpoint accepted potentially malicious file upload without validation.",
                               "High", "Implement file type and content validation on uploads.", resp)

    def test_caching_mechanisms(self, url, method, path_str, details):
        """Test for Caching Mechanisms."""
        self.log("Testing Caching Mechanisms.")
        resp = self.make_request(method, url, headers={"Cache-Control": "no-cache"})
        if resp:
            cache_control = resp.headers.get("Cache-Control", "")
            if "no-store" not in cache_control and "no-cache" not in cache_control:
                self.add_result(url, method, "Caching Mechanisms",
                               "Sensitive data may be cached due to improper Cache-Control headers.",
                               "Medium", "Set appropriate Cache-Control headers to manage caching behavior.", resp)

    def test_xxe_protection(self, url, method, path_str, details):
        """Test for XML External Entity (XXE) Protection."""
        self.log("Testing XML External Entity (XXE) Protection.")
        if 'xml' in (details.get('consumes') or []):
            xxe_payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>"""
            resp = self.make_request(method, url, data=xxe_payload, headers={"Content-Type": "application/xml"})
            if resp and "root:x" in resp.text.lower():
                self.add_result(url, method, "XML External Entity (XXE) Protection",
                               "Endpoint vulnerable to XXE attacks; sensitive files accessible.",
                               "High", "Disable external entity processing and validate XML inputs.", resp)

    def test_content_security_policy(self, url, method, path_str, details):
        """Test for Content Security Policy (CSP)."""
        self.log("Testing Content Security Policy (CSP).")
        resp = self.make_request(method, url)
        if resp:
            csp = resp.headers.get("Content-Security-Policy", "")
            if not csp:
                self.add_result(url, method, "Content Security Policy (CSP)",
                               "CSP header not present, increasing risk of XSS attacks.",
                               "Medium", "Implement a robust Content Security Policy to mitigate XSS risks.", resp)

    def test_api_versioning_security(self, url, method, path_str, details):
        """Test for API Versioning Security."""
        self.log("Testing API Versioning Security.")
        deprecated_versions = ["/v1/", "/v2/"]
        for version in deprecated_versions:
            deprecated_url = url.replace("/v3/", version)
            resp = self.make_request(method, deprecated_url)
            if resp and resp.status_code == 200:
                self.add_result(deprecated_url, method, "API Versioning Security",
                               f"Deprecated API version accessible: {version}",
                               "Low", "Deprecate and properly manage old API versions.", resp)

    def test_brute_force_attack_mitigation(self, url, method, path_str, details):
        """Test for Brute-Force Attack Mitigation."""
        self.log("Testing Brute-Force Attack Mitigation.")
        if "/login" in url.lower() or "/auth" in url.lower():
            payload = {"username": "testuser", "password": "wrongpassword"}
            blocked = False
            for _ in range(10):
                resp = self.make_request(method, url, json=payload)
                if resp and resp.status_code == 429:
                    blocked = True
                    break
            if not blocked:
                self.add_result(url, method, "Brute-Force Attack Mitigation",
                               "No rate limiting or account lockout after multiple failed login attempts.",
                               "High", "Implement rate limiting and account lockout mechanisms to prevent brute-force attacks.", resp=None)

    def test_unauthorized_data_manipulation(self, url, method, path_str, details):
        """Test for Unauthorized Data Manipulation Protection."""
        self.log("Testing Unauthorized Data Manipulation Protection.")
        if method in ["PUT", "PATCH"]:
            payload = {"unauthorized_field": "malicious_value"}
            resp = self.make_request(method, url, json=payload)
            if resp and resp.status_code in [200, 201]:
                self.add_result(url, method, "Unauthorized Data Manipulation",
                               "Endpoint accepted unauthorized data manipulation without proper validation.",
                               "High", "Validate and restrict data fields to prevent unauthorized manipulation.", resp)

    def test_replay_attack_prevention(self, url, method, path_str, details):
        """Test for Replay Attack Prevention."""
        self.log("Testing Replay Attack Prevention.")
        # This is a simplified simulation as actual replay attacks require token handling
        if "Authorization" in self.headers:
            token = self.headers["Authorization"]
            resp1 = self.make_request(method, url)
            resp2 = self.make_request(method, url)
            if resp1 and resp2 and resp1.text == resp2.text:
                # Assuming that identical responses might indicate replay vulnerability
                self.add_result(url, method, "Replay Attack Prevention",
                               "Potential vulnerability to replay attacks; identical responses received for repeated requests.",
                               "Medium", "Implement nonce or timestamp mechanisms to prevent replay attacks.", resp2)

    def test_unauthorized_password_change(self, url, method, path_str, details):
        """Test for Unauthorized Password Change."""
        self.log("Testing Unauthorized Password Change.")
        if "/change-password" in url.lower():
            payload = {"password": "NewPassword123!"}
            resp = self.make_request(method, url, json=payload)
            if resp and resp.status_code == 200:
                self.add_result(url, method, "Unauthorized Password Change",
                               "Password change endpoint accessible without proper authorization.",
                               "High", "Ensure that password change operations require proper authentication and authorization.", resp)

    def test_excessive_data_exposure_debug_endpoint(self, url, method, path_str, details):
        """Test for Excessive Data Exposure through debug endpoint."""
        self.log("Testing Excessive Data Exposure through debug endpoint.")
        debug_url = urljoin(self.base_url, "/debug")
        resp = self.make_request(method, debug_url)
        if resp and resp.status_code == 200:
            sensitive_info_patterns = [r"DEBUG", r"stack trace", r"error", r"password"]
            for pattern in sensitive_info_patterns:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    self.add_result(debug_url, method, "Excessive Data Exposure through Debug Endpoint",
                                   f"Debug endpoint exposed sensitive information: {pattern}",
                                   "High", "Disable debug endpoints in production environments.", resp)
                    break

    def test_user_password_enumeration(self, url, method, path_str, details):
        """Test for User and Password Enumeration."""
        self.log("Testing User and Password Enumeration.")
        if "/login" in url.lower():
            payload_valid = {"username": "validuser", "password": "validpassword"}
            payload_invalid = {"username": "validuser", "password": "invalidpassword"}
            resp_valid = self.make_request(method, url, json=payload_valid)
            resp_invalid = self.make_request(method, url, json=payload_invalid)
            if resp_valid and resp_invalid:
                if resp_valid.status_code == resp_invalid.status_code and resp_valid.text == resp_invalid.text:
                    self.add_result(url, method, "User and Password Enumeration",
                                   "Login responses do not differentiate between valid and invalid credentials.",
                                   "Medium", "Provide generic error messages to prevent enumeration attacks.", resp_invalid)

    def test_regex_dos(self, url, method, path_str, details):
        """Test for Regex Denial of Service (RegexDOS)."""
        self.log("Testing Regex Denial of Service (RegexDOS).")
        # This is a theoretical test as actual RegexDOS requires specific vulnerable regex patterns
        # Here, we simulate by sending a long input that could trigger vulnerable regex
        malicious_input = "A" * 10000  # Very long input
        injection_point = self.get_injection_point(url, path_str)
        if injection_point:
            vulnerable_url = injection_point.replace("{{injection}}", malicious_input)
            resp = self.make_request(method, vulnerable_url)
            if resp and resp.elapsed.total_seconds() > 5:
                self.add_result(vulnerable_url, method, "Regex Denial of Service (RegexDOS)",
                               "Endpoint may be vulnerable to RegexDOS; slow response detected.",
                               "High", "Optimize regex patterns and implement input size limitations to prevent DOS attacks.", resp)

    def test_jwt_authentication_bypass(self, url, method, path_str, details):
        """Test for JWT Authentication Bypass via Weak Signing Key."""
        self.log("Testing JWT Authentication Bypass via Weak Signing Key.")
        if "Authorization" in self.headers:
            try:
                # Decode JWT without verification to get header
                token = self.headers["Authorization"].split()[1]
                header_b64 = token.split('.')[0]
                # Add padding if necessary
                padding = '=' * (-len(header_b64) % 4)
                header_bytes = base64.urlsafe_b64decode(header_b64 + padding)
                header = json.loads(header_bytes)
                if header.get("alg") in ["none", "HS256"]:
                    self.add_result(url, method, "JWT Authentication Bypass",
                                   f"JWT uses weak or insecure signing algorithm: {header.get('alg')}",
                                   "High", "Use strong signing algorithms like RS256 and enforce token verification.", resp=None)
            except Exception as e:
                self.log(f"Failed to decode JWT: {e}")

    # Helper Methods

    def get_injection_point(self, url, path_str):
        """Identify injection points in the URL path."""
        if "{" in path_str and "}" in path_str:
            return re.sub(r"\{[^}]+\}", "{{injection}}", url)
        return None

    def make_request(self, method, url, params=None, json=None, data=None, files=None, headers=None):
        """Send an HTTP request and return the response."""
        self.log(f"Sending {method} request to {url}")
        if params:
            self.log(f"Request parameters: {json.dumps(params, indent=2)}")
        if json:
            self.log(f"Request body: {json.dumps(json, indent=2)}")
        if data:
            self.log(f"Request body: {data}")
        if files:
            self.log(f"Uploading files: {files}")
        try:
            merged_headers = self.headers.copy()
            if headers:
                merged_headers.update(headers)
            response = requests.request(method, url, headers=merged_headers, proxies=self.proxy,
                                        params=params, json=json, data=data, files=files, timeout=10, allow_redirects=True)
            self.log(f"Received response with status code {response.status_code}.")
            self.log(f"Response body: {resp_truncated(response.text)}")
            return response
        except RequestException as e:
            self.log(f"Request to {url} failed: {e}")
            return None

    def send_to_openai(self, response):
        """Send the API response to OpenAI GPT-4 for analysis."""
        self.log("Preparing to send response to OpenAI for analysis.")
        if not response:
            self.log("No response available to send to OpenAI.")
            return "No response available to send to OpenAI."

        prompt = (
            "Analyze the following API response for potential security risks based on the OWASP API Security Top 10:\n\n"
            f"Status Code: {response.status_code}\n"
            f"Headers: {json.dumps(dict(response.headers), indent=2)}\n"
            f"Response Body: {response.text}\n\n"
            "Provide a concise summary of potential risks and any observations."
        )

        try:
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {openai.api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "gpt-4",
                    "messages": [
                        {"role": "system", "content": "You are a cybersecurity expert."},
                        {"role": "user", "content": prompt}
                    ]
                }
            )
            if response.status_code == 200:
                feedback = response.json()["choices"][0]["message"]["content"]
                self.log(f"OpenAI GPT-4 response: {feedback}")
                return feedback
            else:
                self.log(f"OpenAI API error: {response.status_code} - {response.text}")
                return f"OpenAI API error: {response.status_code}"
        except Exception as e:
            self.log(f"Failed to communicate with OpenAI: {e}")
            return f"Error communicating with OpenAI: {e}"

    def add_result(self, endpoint, method, issue, result, severity, recommendation, resp=None):
        """Store a vulnerability discovery result."""
        snippet = resp.text if resp else "No response body"
        openai_feedback = self.send_to_openai(resp) if resp else "No feedback from OpenAI."
        self.results.append({
=======
                # If openai_analysis is enabled, do AI-based analysis
                ai_notes = self.ai_analysis_if_enabled(resp, "BrokenAuth")
                self.add_result(
                    url, method,
                    "Broken Authentication",
                    "Endpoint returned 200 with no token.",
                    "High",
                    "Require valid authentication.",
                    resp,
                    ai_notes=ai_notes
                )
        except RequestException:
            pass

        # Attempt with invalid token
        self.headers["Authorization"] = "Bearer invalid_token"
        try:
            resp = self.make_request(method, url)
            if resp and resp.status_code == 200:
                ai_notes = self.ai_analysis_if_enabled(resp, "BrokenAuth")
                self.add_result(
                    url, method,
                    "Broken Authentication",
                    "Endpoint returned 200 with an invalid token.",
                    "High",
                    "Properly validate bearer tokens.",
                    resp,
                    ai_notes=ai_notes
                )
        except RequestException:
            pass

        self.headers = original_headers

    # ---------------------------------------------------------------------
    # 2) SQL Injection Example
    # ---------------------------------------------------------------------
    def test_sql_injection(self, url, method, path_str, details):
        sqli_payloads = ["' OR 1=1 --", "' UNION SELECT NULL--"]
        params = details.get("parameters", [])

        # Check query parameters
        query_data = {}
        for p in params:
            if p.get("in") == "query":
                query_data[p["name"]] = sqli_payloads[0]

        if query_data:
            try:
                resp = self.make_request(method, url, params=query_data)
                if self.is_sqli_response(resp):
                    ai_notes = self.ai_analysis_if_enabled(resp, "SQLi")
                    self.add_result(
                        url, method,
                        "Injection (SQLi)",
                        f"Payload {sqli_payloads[0]} triggered a suspicious response.",
                        "High",
                        "Use parameterized queries.",
                        resp,
                        ai_notes=ai_notes
                    )
            except RequestException:
                pass

    # Basic heuristic for SQLi
    def is_sqli_response(self, resp):
        if not resp:
            return False
        if resp.status_code == 500:
            return True
        lower_body = resp.text.lower()
        return any(kw in lower_body for kw in ["sql", "syntax", "database error", "sql error"])

    # ---------------------------------------------------------------------
    # OpenAI Integration (for openai>=1.0.0)
    # ---------------------------------------------------------------------
    def ai_analysis_if_enabled(self, resp, test_label="General"):
        """If openai_analysis is True, send partial HTTP response to OpenAI for analysis."""
        if not self.openai_analysis or not self.openai_api_key:
            return None

        # Truncate the response text to avoid huge data
        response_text = resp.text[:2000]

        system_prompt = (
            "You are a security expert specialized in analyzing HTTP responses. "
            "Identify potential vulnerabilities, misconfigurations, or exploits."
        )
        user_prompt = (
            f"This response is from a test labeled '{test_label}'.\n\n"
            f"Partial HTTP response:\n{response_text}\n\n"
            "Please identify any potential vulnerabilities or security concerns you see."
        )

        try:
            # Note the updated usage for openai>=1.0.0
            completion = openai.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                max_tokens=200,
                temperature=0.3,
            )

            # Access the content from "choices" not from "completions"
            answer = completion["choices"][0]["message"]["content"].strip()
            return answer
        except Exception as e:
            return f"[OpenAI Error: {e}]"

    # ---------------------------------------------------------------------
    # Request / Reporting Helpers
    # ---------------------------------------------------------------------
    def make_request(self, method, url, params=None, json=None):
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

    def add_result(self, endpoint, method, issue, result, severity,
                   recommendation, resp, ai_notes=None):
        """Add a vulnerability discovery. Store AI analysis if present."""
        snippet = resp.text[:300].replace("\n", "\\n") if resp else ""
        status_code = resp.status_code if resp else None
        finding = {
>>>>>>> 2576abf4f1b4550ab08cb9fe38f7bf1cb07b90d8
            "endpoint": endpoint,
            "method": method,
            "issue": issue,
            "result": result,
            "severity": severity,
            "recommendation": recommendation,
<<<<<<< HEAD
            "response_snippet": snippet,
            "openai_feedback": openai_feedback
        })

    def generate_report(self):
        """Generate and save the vulnerability report."""
        self.log("Generating the vulnerability report.")
        if self.output_format == "json":
            with open(f"{self.output_file}.json", "w") as f:
                json.dump(self.results, f, indent=4)
            self.log(f"Report saved as {self.output_file}.json")
        elif self.output_format == "html":
            with open(f"{self.output_file}.html", "w") as f:
                f.write("<html><body><h1>API Vulnerability Report</h1><table border='1'>")
                f.write("<tr><th>Endpoint</th><th>Method</th><th>Issue</th>"
                        "<th>Result</th><th>Severity</th><th>Recommendation</th><th>OpenAI Feedback</th></tr>")
                for res in self.results:
                    f.write(f"<tr><td>{res['endpoint']}</td><td>{res['method']}</td>"
                            f"<td>{res['issue']}</td><td>{res['result']}</td>"
                            f"<td>{res['severity']}</td><td>{res['recommendation']}</td>"
                            f"<td>{res['openai_feedback']}</td></tr>")
                f.write("</table></body></html>")
            self.log(f"Report saved as {self.output_file}.html")

def resp_truncated(text, limit=500):
    """Truncate response text for logging."""
    return text if len(text) <= limit else text[:limit] + "..."

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="API Vulnerability Scanner with OWASP Top 10 and Additional Tests")
    parser.add_argument("-i", "--input", required=True, help="Path to OpenAPI spec file")
    parser.add_argument("-u", "--url", required=True, help="Base URL of the API")
    parser.add_argument("-o", "--output", default="report", help="Output report file name")
    parser.add_argument("-f", "--format", choices=["json", "html"], default="json",
                        help="Output report format (default: json)")
    parser.add_argument("-t", "--token", help="Bearer token for API authentication", required=False)
    parser.add_argument("-p", "--proxy", help="Proxy server URL", required=False)
    return parser.parse_args()

def main():
    args = parse_args()
    scanner = APIVulnerabilityScanner(spec_file=args.input, base_url=args.url,
                                      proxy=args.proxy, token=args.token,
                                      output_format=args.format,
                                      output_file=args.output)
    scanner.load_spec()
    scanner.scan_endpoints()
    scanner.generate_report()
=======
            "status_code": status_code,
            "body_snippet": snippet
        }
        if ai_notes:
            finding["ai_analysis"] = ai_notes

        # Avoid duplicates (naive check)
        if finding not in self.results:
            self.results.append(finding)

    def generate_report(self):
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
                fieldnames = self.results[0].keys()
                writer = csv.DictWriter(f, fieldnames=fieldnames)
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
                        val = str(row[header]).replace("<", "&lt;").replace(">", "&gt;")
                        f.write(f"<td>{val}</td>")
                    f.write("</tr>")
                f.write("</table></body></html>")
            print(f"\nReport written to: {out_file}")


def parse_args():
    parser = argparse.ArgumentParser(description="API Security Scanner with optional OpenAI analysis.")
    parser.add_argument("--input", "-i", help="OpenAPI/Swagger file (YAML/JSON).")
    parser.add_argument("--url", "-u", help="Base URL of the API.")
    parser.add_argument("--proxy", "-p", help="Proxy URL (optional).")
    parser.add_argument("--token", "-t", help="Bearer token (optional).")
    parser.add_argument("--format", "-f", choices=["json", "csv", "html"], default="json",
                        help="Report format (default: json).")
    parser.add_argument("--output", "-o", default="report",
                        help="Output file name (without extension) (default: report).")
    parser.add_argument("--openai-api-key", help="OpenAI API key if you want to enable AI-based analysis.")
    parser.add_argument("--openai-analysis", action="store_true",
                        help="Enable calls to OpenAI for each test response analysis.")
    return parser.parse_args()


def main():
    args = parse_args()

    scanner = APIVulnerabilityScanner(
        spec_file=args.input,
        base_url=args.url,
        proxy=args.proxy,
        token=args.token,
        output_format=args.format,
        output_file=args.output,
        openai_api_key=args.openai_api_key,
        openai_analysis=args.openai_analysis
    )

    # If the user provided an input spec and base url, run the scan
    if args.input and args.url:
        scanner.load_spec()
        scanner.scan_endpoints()
        scanner.generate_report()
    else:
        print("No input file or URL specified. Provide --input and --url or see --help.")

>>>>>>> 2576abf4f1b4550ab08cb9fe38f7bf1cb07b90d8

if __name__ == "__main__":
    main()
