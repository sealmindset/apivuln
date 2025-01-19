#!/usr/bin/env python3
"""
API Vulnerability Scanner - OWASP API Security Top 10 (2023 Edition)
Enhanced verbosity with full request/response logs and updated OpenAI API integration.
Includes additional security tests and detailed report with request headers and methods.
"""

import argparse
import json
import yaml
import requests
import re
import os
import base64
import random
import time
import html
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
                 output_format="json", output_file="report", randomize=False, offai=False):
        self.spec_file = spec_file
        self.base_url = base_url
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.token = token
        self.headers = {"Authorization": f"Bearer {token}"} if token else {}
        self.output_format = output_format
        self.output_file = output_file
        self.randomize = randomize  # Attribute for random delays
        self.offai = offai          # Attribute to control OpenAI integration

        # Initialize OpenAI API key only if OpenAI integration is enabled
        if not self.offai:
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
            self.test_jwt_authentication_bypass,
            # New Tests
            self.test_information_disclosure,
            self.test_insufficient_data_protection,
            self.test_insufficient_access_control
        ]

    def log(self, message):
        """Log messages to the console."""
        print(f"[LOG] {message}")

    def load_spec(self):
        """Load the OpenAPI/Swagger specification."""
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
            self.log("Successfully loaded the OpenAPI/Swagger specification.")
        except Exception as e:
            raise ValueError(f"Failed to load API spec: {e}")

    def scan_endpoints(self):
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

    # Existing and Updated Test Methods

    def test_broken_object_level_auth(self, url, method, path_str, details):
        """Test for Broken Object Level Authorization."""
        if "{" in path_str and "}" in path_str:
            forced_param_url = re.sub(r"\{[^}]+\}", "1", url)
            try:
                resp, request_body, request_headers = self.make_request(method, forced_param_url)
                if resp and resp.status_code == 200:
                    # Vulnerability detected
                    self.add_result(
                        endpoint=forced_param_url,
                        method=method,
                        issue="Broken Object Level Authorization",
                        result="Endpoint returned 200 after forcibly replacing path parameter.",
                        severity="High",
                        recommendation="Validate user ownership.",
                        req_method=method,
                        request_headers=request_headers,
                        request_body=request_body,
                        response_body=resp.text,
                        resp=resp,
                        vulnerability_found=True
                    )
                else:
                    # No vulnerability detected
                    self.add_result(
                        endpoint=forced_param_url,
                        method=method,
                        issue="Broken Object Level Authorization",
                        result=f"No broken object level authorization detected. Received status code {resp.status_code if resp else 'No Response'}.",
                        severity="None",
                        recommendation="Object level authorization mechanisms are functioning as expected.",
                        req_method=method,
                        request_headers=request_headers,
                        request_body=request_body,
                        response_body=resp.text if resp else "No response",
                        resp=resp,
                        vulnerability_found=False
                    )
            except RequestException:
                # Could not make the request; possibly not applicable
                self.log(f"Failed to test Broken Object Level Authorization for URL: {forced_param_url}")
                self.add_result(
                    endpoint=forced_param_url,
                    method=method,
                    issue="Broken Object Level Authorization",
                    result="Failed to make the request.",
                    severity="Medium",
                    recommendation="Ensure proper error handling and authorization checks.",
                    req_method=method,
                    request_headers={},
                    request_body="N/A",
                    response_body="N/A",
                    resp=None,
                    vulnerability_found=False
                )

    def test_broken_authentication(self, url, method, path_str=None, details=None):
        """Test for Broken Authentication."""
        self.log("Testing Broken Authentication.")
        original_headers = dict(self.headers)
        self.headers.pop("Authorization", None)
        try:
            resp, request_body, request_headers = self.make_request(method, url)
            if resp and resp.status_code == 200:
                # Vulnerability detected
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Broken Authentication",
                    result="Endpoint returned 200 without authentication.",
                    severity="High",
                    recommendation="Ensure authentication is enforced.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=True
                )
            else:
                # No vulnerability detected
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Broken Authentication",
                    result=f"No broken authentication detected. Received status code {resp.status_code if resp else 'No Response'}.",
                    severity="None",
                    recommendation="Authentication mechanisms are functioning as expected.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body=resp.text if resp else "No response",
                    resp=resp,
                    vulnerability_found=False
                )
        finally:
            self.headers = original_headers

    def test_excessive_data_exposure(self, url, method, path_str, details):
        """Test for Excessive Data Exposure."""
        # Send a request and check if sensitive data is exposed in the response
        resp, request_body, request_headers = self.make_request(method, url)
        if resp and resp.status_code == 200:
            sensitive_keywords = ['password', 'secret', 'token', 'apikey', 'creditcard']
            found_keyword = None
            for keyword in sensitive_keywords:
                if keyword in resp.text.lower():
                    found_keyword = keyword
                    break
            if found_keyword:
                # Vulnerability detected
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Excessive Data Exposure",
                    result=f"Response contains sensitive keyword: {found_keyword}",
                    severity="Medium",
                    recommendation="Limit data exposure to necessary fields.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=True
                )
            else:
                # No vulnerability detected
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Excessive Data Exposure",
                    result=f"No excessive data exposure detected. Received status code {resp.status_code}.",
                    severity="None",
                    recommendation="Data exposure is within acceptable limits.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=False
                )
        else:
            # Handle cases where response is not 200
            self.add_result(
                endpoint=url,
                method=method,
                issue="Excessive Data Exposure",
                result=f"Unexpected response status code {resp.status_code if resp else 'No Response'}.",
                severity="None",
                recommendation="Review data exposure mechanisms.",
                req_method=method,
                request_headers=request_headers,
                request_body=request_body,
                response_body=resp.text if resp else "No response",
                resp=resp,
                vulnerability_found=False
            )

    def test_lack_of_resources_and_rate_limiting(self, url, method, path_str, details):
        """Test for Lack of Resources & Rate Limiting."""
        # Attempt to send multiple rapid requests to check rate limiting
        try:
            rate_limit_triggered = False
            for i in range(10):
                resp, request_body, request_headers = self.make_request(method, url)
                if resp and resp.status_code == 429:
                    rate_limit_triggered = True
                    self.log(f"Rate limiting triggered on attempt {i+1}.")
                    break
            if rate_limit_triggered:
                # Rate limiting is in place
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Lack of Resources & Rate Limiting",
                    result=f"Rate limiting is in place after {i+1} rapid requests.",
                    severity="None",
                    recommendation="Rate limiting to protect against DoS attacks is functioning as expected.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=None,
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=False  # Not a vulnerability but a protective measure
                )
            else:
                # No rate limiting detected
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Lack of Resources & Rate Limiting",
                    result="No rate limiting detected after multiple rapid requests.",
                    severity="Low",
                    recommendation="Implement rate limiting to protect against DoS attacks.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=None,
                    response_body=resp.text if resp else "No response",
                    resp=resp,
                    vulnerability_found=False
                )
        except RequestException as e:
            self.log(f"Error during Lack of Resources & Rate Limiting test: {e}")
            self.add_result(
                endpoint=url,
                method=method,
                issue="Lack of Resources & Rate Limiting",
                result=f"Error during testing: {e}",
                severity="Low",
                recommendation="Implement rate limiting to protect against DoS attacks.",
                req_method=method,
                request_headers=request_headers,
                request_body=None,
                response_body=str(e),
                resp=None,
                vulnerability_found=False
            )

    def test_broken_function_level_authorization(self, url, method, path_str, details):
        """Test for Broken Function Level Authorization."""
        self.log("Testing Broken Function Level Authorization.")
        # Attempt to access admin functionalities without admin privileges
        admin_url = urljoin(self.base_url, "/admin")
        resp, request_body, request_headers = self.make_request(method, admin_url)
        if resp and resp.status_code == 200:
            # Vulnerability detected
            self.add_result(
                endpoint=admin_url,
                method=method,
                issue="Broken Function Level Authorization",
                result="Admin functionality accessible without proper authorization.",
                severity="High",
                recommendation="Enforce proper authorization checks for all function levels.",
                req_method=method,
                request_headers=request_headers,
                request_body=request_body,
                response_body=resp.text,
                resp=resp,
                vulnerability_found=True
            )
        else:
            # No vulnerability detected
            self.add_result(
                endpoint=admin_url,
                method=method,
                issue="Broken Function Level Authorization",
                result=f"No broken function level authorization detected. Received status code {resp.status_code if resp else 'No Response'}.",
                severity="None",
                recommendation="Authorization mechanisms are functioning as expected.",
                req_method=method,
                request_headers=request_headers,
                request_body=request_body,
                response_body=resp.text if resp else "No response",
                resp=resp,
                vulnerability_found=False
            )

    def test_mass_assignment(self, url, method, path_str, details):
        """Test for Mass Assignment."""
        # Send additional unexpected parameters in the request body
        if method in ["POST", "PUT", "PATCH"]:
            payload = {"unexpected_field": "unexpected_value"}
            resp, request_body, request_headers = self.make_request(method, url, json=payload)
            if resp and resp.status_code in [200, 201]:
                # Vulnerability detected
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Mass Assignment",
                    result="Endpoint accepted unexpected parameters without validation.",
                    severity="Medium",
                    recommendation="Validate and sanitize all input parameters.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=json.dumps(payload),
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=True
                )
            else:
                # No vulnerability detected
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Mass Assignment",
                    result=f"No mass assignment vulnerability detected. Received status code {resp.status_code if resp else 'No Response'}.",
                    severity="None",
                    recommendation="Mass assignment protections are functioning as expected.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=json.dumps(payload),
                    response_body=resp.text if resp else "No response",
                    resp=resp,
                    vulnerability_found=False
                )
        else:
            # Method not applicable for mass assignment
            self.add_result(
                endpoint=url,
                method=method,
                issue="Mass Assignment",
                result="Mass assignment test not applicable for this HTTP method.",
                severity="None",
                recommendation="Ensure mass assignment protections are in place where applicable.",
                req_method=method,
                request_headers=request_headers,
                request_body="N/A",
                response_body="N/A",
                resp=None,
                vulnerability_found=False
            )

    def test_security_misconfiguration(self, url, method, path_str, details):
        """Test for Security Misconfiguration."""
        self.log("Testing Security Misconfiguration.")
        # Check for exposed sensitive files or directories
        common_paths = ["/.git", "/config.php", "/backup.zip"]
        for path in common_paths:
            test_url = urljoin(self.base_url, path)
            resp, request_body, request_headers = self.make_request("GET", test_url)
            if resp and resp.status_code == 200:
                # Vulnerability detected
                self.add_result(
                    endpoint=test_url,
                    method="GET",
                    issue="Security Misconfiguration",
                    result=f"Sensitive file or directory accessible: {path}",
                    severity="High",
                    recommendation="Ensure sensitive files and directories are not publicly accessible.",
                    req_method="GET",
                    request_headers=request_headers,
                    request_body=None,
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=True
                )
            else:
                # No vulnerability detected for this path
                self.add_result(
                    endpoint=test_url,
                    method="GET",
                    issue="Security Misconfiguration",
                    result=f"No sensitive file or directory accessible at: {path}",
                    severity="None",
                    recommendation="Ensure sensitive files and directories are not publicly accessible.",
                    req_method="GET",
                    request_headers=request_headers,
                    request_body=None,
                    response_body=resp.text if resp else "No response",
                    resp=resp,
                    vulnerability_found=False
                )

    def test_injection(self, url, method, path_str, details):
        """Test for Injection vulnerabilities."""
        # Attempt SQL injection
        injection_payload = "' OR '1'='1"
        if "{" in path_str and "}" in path_str:
            injection_url = re.sub(r"\{[^}]+\}", injection_payload, url)
            resp, request_body, request_headers = self.make_request(method, injection_url)
            if resp:
                # Check for common SQL error indicators in the response
                error_indicators = [
                    "sql syntax",
                    "unrecognized token",
                    "sql error",
                    "syntax error",
                    "mysql_fetch",
                    "pdoexception",
                    "sqlstate",
                    "ORA-",
                    "Access denied for user",
                    "Warning: mysql_",
                    "fatal error"
                ]
                found_error = False
                for indicator in error_indicators:
                    if indicator.lower() in resp.text.lower():
                        found_error = True
                        break
                if found_error:
                    # Vulnerability detected
                    self.add_result(
                        endpoint=injection_url,
                        method=method,
                        issue="Injection",
                        result="Potential injection vulnerability detected.",
                        severity="High",
                        recommendation="Sanitize and validate all inputs to prevent injection attacks.",
                        req_method=method,
                        request_headers=request_headers,
                        request_body=request_body,
                        response_body=resp.text,
                        resp=resp,
                        vulnerability_found=True
                    )
                else:
                    # No vulnerability detected
                    self.add_result(
                        endpoint=injection_url,
                        method=method,
                        issue="Injection",
                        result=f"No injection vulnerability detected. Received status code {resp.status_code if resp else 'No Response'}.",
                        severity="None",
                        recommendation="Input sanitization mechanisms are functioning as expected.",
                        req_method=method,
                        request_headers=request_headers,
                        request_body=request_body,
                        response_body=resp.text if resp else "No response",
                        resp=resp,
                        vulnerability_found=False
                    )
        else:
            # Injection test not applicable
            self.add_result(
                endpoint=url,
                method=method,
                issue="Injection",
                result="Injection test not applicable for this endpoint.",
                severity="None",
                recommendation="Ensure input sanitization is in place where applicable.",
                req_method=method,
                request_headers={},
                request_body="N/A",
                response_body="N/A",
                resp=None,
                vulnerability_found=False
            )

    def test_sql_injection(self, url, method, path_str, details):
        """Test for SQL Injection using multiple common payloads."""
        self.log("Testing SQL Injection with multiple payloads.")
        sql_payloads = [
            "'",
            "' OR '1'='1",
            "' OR '1'='1' -- -",
            "' OR '1'='1' ({",
            "' OR '1'='1' /*",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL, NULL, NULL --",
            "' OR 1=1-- -",
            "' OR 'a'='a",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin') -- -",
            "' OR 1=1#"
        ]
        
        if "{" in path_str and "}" in path_str:
            for payload in sql_payloads:
                # Inject payload into the URL
                injection_url = re.sub(r"\{[^}]+\}", payload, url)
                self.log(f"Testing payload: {payload} on URL: {injection_url}")
                resp, request_body, request_headers = self.make_request(method, injection_url)
                if resp:
                    # Check for common SQL error indicators in the response
                    error_indicators = [
                        "sql syntax",
                        "unrecognized token",
                        "sql error",
                        "syntax error",
                        "mysql_fetch",
                        "pdoexception",
                        "sqlstate",
                        "ORA-",
                        "Access denied for user",
                        "Warning: mysql_",
                        "fatal error"
                    ]
                    found_error = False
                    for indicator in error_indicators:
                        if indicator.lower() in resp.text.lower():
                            found_error = True
                            break
                    if found_error:
                        # Vulnerability detected
                        self.add_result(
                            endpoint=injection_url,
                            method=method,
                            issue="SQL Injection",
                            result=f"SQL Injection vulnerability detected with payload: {payload}",
                            severity="High",
                            recommendation="Sanitize and validate all inputs to prevent SQL Injection attacks.",
                            req_method=method,
                            request_headers=request_headers,
                            request_body=json.dumps({"injected_payload": payload}),
                            response_body=resp.text,
                            resp=resp,
                            vulnerability_found=True
                        )
                    else:
                        # No vulnerability detected
                        self.add_result(
                            endpoint=injection_url,
                            method=method,
                            issue="SQL Injection",
                            result=f"No SQL Injection vulnerability detected with payload: {payload}. Received status code {resp.status_code}.",
                            severity="None",
                            recommendation="SQL Injection protections are functioning as expected.",
                            req_method=method,
                            request_headers=request_headers,
                            request_body=json.dumps({"injected_payload": payload}),
                            response_body=resp.text if resp else "No response",
                            resp=resp,
                            vulnerability_found=False
                        )
        else:
            # SQL Injection test not applicable
            self.add_result(
                endpoint=url,
                method=method,
                issue="SQL Injection",
                result="SQL Injection test not applicable for this endpoint.",
                severity="None",
                recommendation="Ensure SQL Injection protections are in place where applicable.",
                req_method=method,
                request_headers={},
                request_body="N/A",
                response_body="N/A",
                resp=None,
                vulnerability_found=False
            )

    def test_improper_assets_management(self, url, method, path_str, details):
        """Test for Improper Assets Management."""
        self.log("Testing Improper Assets Management.")
        # Check for deprecated API versions
        deprecated_versions = ["/v1/", "/v2/"]
        for version in deprecated_versions:
            deprecated_url = url.replace("/v3/", version)
            resp, request_body, request_headers = self.make_request(method, deprecated_url)
            if resp and resp.status_code == 200:
                # Vulnerability detected
                self.add_result(
                    endpoint=deprecated_url,
                    method=method,
                    issue="Improper Assets Management",
                    result=f"Deprecated API version accessible: {version}",
                    severity="Low",
                    recommendation="Deprecate and properly manage old API versions.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=True
                )
            else:
                # No vulnerability detected for this version
                self.add_result(
                    endpoint=deprecated_url,
                    method=method,
                    issue="Improper Assets Management",
                    result=f"No improper assets management detected for version: {version}. Received status code {resp.status_code if resp else 'No Response'}.",
                    severity="None",
                    recommendation="Deprecate and properly manage old API versions.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body=resp.text if resp else "No response",
                    resp=resp,
                    vulnerability_found=False
                )

    def test_insufficient_logging_and_monitoring(self, url, method, path_str, details):
        """Test for Insufficient Logging & Monitoring."""
        # Trigger a known error and check if it's logged
        self.log("Testing Insufficient Logging & Monitoring.")
        error_url = url + "/invalidendpoint"
        resp, request_body, request_headers = self.make_request(method, error_url)
        if resp and resp.status_code == 404:
            # Assuming that a 404 should be logged; since we can't access server logs, we note the need
            self.add_result(
                endpoint=error_url,
                method=method,
                issue="Insufficient Logging & Monitoring",
                result="Potential lack of logging for invalid endpoints.",
                severity="Medium",
                recommendation="Implement comprehensive logging and monitoring for all API activities.",
                req_method=method,
                request_headers=request_headers,
                request_body=request_body,
                response_body=resp.text,
                resp=resp,
                vulnerability_found=False
            )
        else:
            # Handle unexpected responses
            self.add_result(
                endpoint=error_url,
                method=method,
                issue="Insufficient Logging & Monitoring",
                result=f"Unexpected response for invalid endpoint. Received status code {resp.status_code if resp else 'No Response'}.",
                severity="None",
                recommendation="Ensure logging mechanisms capture all relevant events.",
                req_method=method,
                request_headers=request_headers,
                request_body=request_body,
                response_body=resp.text if resp else "No response",
                resp=resp,
                vulnerability_found=False
            )

    # Additional Test Methods

    def test_secure_transmission(self, url, method, path_str, details):
        """Test for Secure Transmission (HTTPS)."""
        self.log("Testing Secure Transmission (HTTPS).")
        if not url.startswith("https://"):
            # Vulnerability detected
            self.add_result(
                endpoint=url,
                method=method,
                issue="Secure Transmission (HTTPS)",
                result="Endpoint does not use HTTPS for secure data transmission.",
                severity="High",
                recommendation="Ensure all API endpoints enforce HTTPS to protect data in transit.",
                req_method=method,
                request_headers={},
                request_body=None,
                response_body=None,
                resp=None,
                vulnerability_found=True
            )
        else:
            # No vulnerability detected
            self.add_result(
                endpoint=url,
                method=method,
                issue="Secure Transmission (HTTPS)",
                result="Endpoint uses HTTPS for secure data transmission.",
                severity="None",
                recommendation="Secure transmission mechanisms are functioning as expected.",
                req_method=method,
                request_headers={},
                request_body=None,
                response_body=None,
                resp=None,
                vulnerability_found=False
            )

    def test_xss(self, url, method, path_str, details):
        """Test for Cross-Site Scripting (XSS)."""
        self.log("Testing Cross-Site Scripting (XSS).")
        xss_payload = "<script>alert('XSS')</script>"
        injection_point = self.get_injection_point(url, path_str)
        if injection_point:
            vulnerable_url = injection_point.replace("{{injection}}", xss_payload)
            resp, request_body, request_headers = self.make_request(method, vulnerable_url)
            if resp and xss_payload in resp.text:
                # Vulnerability detected
                self.add_result(
                    endpoint=vulnerable_url,
                    method=method,
                    issue="Cross-Site Scripting (XSS)",
                    result="Endpoint reflected XSS payload in the response.",
                    severity="High",
                    recommendation="Sanitize and encode all user inputs to prevent XSS attacks.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=True
                )
            else:
                # No vulnerability detected
                self.add_result(
                    endpoint=vulnerable_url,
                    method=method,
                    issue="Cross-Site Scripting (XSS)",
                    result=f"No XSS vulnerability detected with payload: {xss_payload}. Received status code {resp.status_code if resp else 'No Response'}.",
                    severity="None",
                    recommendation="Input sanitization mechanisms are functioning as expected.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body=resp.text if resp else "No response",
                    resp=resp,
                    vulnerability_found=False
                )
        else:
            # Injection point not found
            self.add_result(
                endpoint=url,
                method=method,
                issue="Cross-Site Scripting (XSS)",
                result="XSS test not applicable for this endpoint.",
                severity="None",
                recommendation="Ensure input sanitization is in place where applicable.",
                req_method=method,
                request_headers={},
                request_body="N/A",
                response_body="N/A",
                resp=None,
                vulnerability_found=False
            )

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
                resp, request_body, request_headers = self.make_request(method, idor_url)
                if resp and resp.status_code == 200:
                    # Vulnerability detected
                    self.add_result(
                        endpoint=idor_url,
                        method=method,
                        issue="Insecure Direct Object References (IDOR)",
                        result="Accessed resource with modified object ID.",
                        severity="High",
                        recommendation="Implement proper authorization checks to prevent IDOR.",
                        req_method=method,
                        request_headers=request_headers,
                        request_body=request_body,
                        response_body=resp.text,
                        resp=resp,
                        vulnerability_found=True
                    )
                else:
                    # No vulnerability detected
                    self.add_result(
                        endpoint=idor_url,
                        method=method,
                        issue="Insecure Direct Object References (IDOR)",
                        result=f"No IDOR vulnerability detected. Received status code {resp.status_code if resp else 'No Response'}.",
                        severity="None",
                        recommendation="Authorization checks are functioning as expected.",
                        req_method=method,
                        request_headers=request_headers,
                        request_body=request_body,
                        response_body=resp.text if resp else "No response",
                        resp=resp,
                        vulnerability_found=False
                    )
            except ValueError:
                self.log("Non-numeric ID detected; IDOR test may not be applicable.")
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Insecure Direct Object References (IDOR)",
                    result="Non-numeric ID detected; IDOR test not applicable.",
                    severity="None",
                    recommendation="Ensure authorization checks are in place where applicable.",
                    req_method=method,
                    request_headers={},
                    request_body="N/A",
                    response_body="N/A",
                    resp=None,
                    vulnerability_found=False
                )
        else:
            # IDOR test not applicable
            self.add_result(
                endpoint=url,
                method=method,
                issue="Insecure Direct Object References (IDOR)",
                result="IDOR test not applicable for this endpoint.",
                severity="None",
                recommendation="Ensure authorization checks are in place where applicable.",
                req_method=method,
                request_headers={},
                request_body="N/A",
                response_body="N/A",
                resp=None,
                vulnerability_found=False
            )

    def test_graphql_and_websocket_security(self, url, method, path_str, details):
        """Test for GraphQL and WebSocket Security."""
        self.log("Testing GraphQL and WebSocket Security.")
        if '/graphql' in url.lower():
            # Basic GraphQL introspection query
            graphql_query = {"query": "{ __schema { types { name } } }"}
            resp, request_body, request_headers = self.make_request(method, url, json=graphql_query)
            if resp and "error" in resp.text.lower():
                # Potential security issue detected
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="GraphQL Security",
                    result="GraphQL introspection query exposed errors.",
                    severity="Medium",
                    recommendation="Disable introspection in production or secure it appropriately.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=json.dumps(graphql_query),
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=True
                )
            else:
                # No vulnerability detected
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="GraphQL Security",
                    result=f"No GraphQL security vulnerabilities detected. Received status code {resp.status_code if resp else 'No Response'}.",
                    severity="None",
                    recommendation="GraphQL introspection is functioning as expected.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=json.dumps(graphql_query),
                    response_body=resp.text if resp else "No response",
                    resp=resp,
                    vulnerability_found=False
                )
        if '/ws' in url.lower():
            # WebSocket security is beyond simple HTTP requests; note the need for specialized testing
            self.log("WebSocket endpoints require specialized testing tools.")
            self.add_result(
                endpoint=url,
                method=method,
                issue="WebSocket Security",
                result="WebSocket security testing requires specialized tools.",
                severity="None",
                recommendation="Use appropriate tools to test WebSocket security.",
                req_method=method,
                request_headers={},
                request_body="N/A",
                response_body="N/A",
                resp=None,
                vulnerability_found=False
            )

    def test_file_upload_security(self, url, method, path_str, details):
        """Test for File Upload Security."""
        self.log("Testing File Upload Security.")
        if method in ["POST", "PUT", "PATCH"]:
            # Attempt to upload a potentially malicious file
            files = {'file': ('test.exe', b'Executable content', 'application/octet-stream')}
            resp, request_body, request_headers = self.make_request(method, url, files=files)
            if resp and resp.status_code == 200:
                # Vulnerability detected
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="File Upload Security",
                    result="Endpoint accepted potentially malicious file upload without validation.",
                    severity="High",
                    recommendation="Implement file type and content validation on uploads.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=f"Uploaded file: {list(files.keys())}",
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=True
                )
            else:
                # No vulnerability detected
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="File Upload Security",
                    result=f"No file upload vulnerability detected. Received status code {resp.status_code if resp else 'No Response'}.",
                    severity="None",
                    recommendation="File upload mechanisms are functioning as expected.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=f"Uploaded file: {list(files.keys())}",
                    response_body=resp.text if resp else "No response",
                    resp=resp,
                    vulnerability_found=False
                )
        else:
            # File upload not applicable for this method
            self.add_result(
                endpoint=url,
                method=method,
                issue="File Upload Security",
                result="File upload test not applicable for this HTTP method.",
                severity="None",
                recommendation="Ensure file upload protections are in place where applicable.",
                req_method=method,
                request_headers={},
                request_body="N/A",
                response_body="N/A",
                resp=None,
                vulnerability_found=False
            )

    def test_caching_mechanisms(self, url, method, path_str, details):
        """Test for Caching Mechanisms."""
        self.log("Testing Caching Mechanisms.")
        resp, request_body, request_headers = self.make_request(method, url, headers={"Cache-Control": "no-cache"})
        if resp:
            cache_control = resp.headers.get("Cache-Control", "")
            if "no-store" not in cache_control and "no-cache" not in cache_control:
                # Potential issue detected
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Caching Mechanisms",
                    result="Sensitive data may be cached due to improper Cache-Control headers.",
                    severity="Medium",
                    recommendation="Set appropriate Cache-Control headers to manage caching behavior.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=None,
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=True
                )
            else:
                # No vulnerability detected
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Caching Mechanisms",
                    result="Proper Cache-Control headers are present.",
                    severity="None",
                    recommendation="Ensure Cache-Control headers are correctly set.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=None,
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=False
                )
        else:
            # No response received
            self.add_result(
                endpoint=url,
                method=method,
                issue="Caching Mechanisms",
                result="No response received during caching mechanisms test.",
                severity="Medium",
                recommendation="Set appropriate Cache-Control headers to manage caching behavior.",
                req_method=method,
                request_headers=request_headers,
                request_body=None,
                response_body="No response",
                resp=None,
                vulnerability_found=False
            )

    def test_xxe_protection(self, url, method, path_str, details):
        """Test for XML External Entity (XXE) Protection."""
        self.log("Testing XML External Entity (XXE) Protection.")
        if 'xml' in (details.get('consumes') or []):
            xxe_payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>"""
            resp, request_body, request_headers = self.make_request(method, url, data=xxe_payload, headers={"Content-Type": "application/xml"})
            if resp and "root:x" in resp.text.lower():
                # Vulnerability detected
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="XML External Entity (XXE) Protection",
                    result="Endpoint vulnerable to XXE attacks; sensitive files accessible.",
                    severity="High",
                    recommendation="Disable external entity processing and validate XML inputs.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=xxe_payload,
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=True
                )
            else:
                # No vulnerability detected
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="XML External Entity (XXE) Protection",
                    result=f"No XXE vulnerability detected. Received status code {resp.status_code if resp else 'No Response'}.",
                    severity="None",
                    recommendation="XML external entity protections are functioning as expected.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=xxe_payload,
                    response_body=resp.text if resp else "No response",
                    resp=resp,
                    vulnerability_found=False
                )
        else:
            # XXE test not applicable
            self.add_result(
                endpoint=url,
                method=method,
                issue="XML External Entity (XXE) Protection",
                result="XXE test not applicable for this endpoint.",
                severity="None",
                recommendation="Ensure XML external entity protections are in place where applicable.",
                req_method=method,
                request_headers={},
                request_body="N/A",
                response_body="N/A",
                resp=None,
                vulnerability_found=False
            )

    def test_content_security_policy(self, url, method, path_str, details):
        """Test for Content Security Policy (CSP)."""
        self.log("Testing Content Security Policy (CSP).")
        resp, request_body, request_headers = self.make_request(method, url)
        if resp:
            csp = resp.headers.get("Content-Security-Policy", "")
            if not csp:
                # Vulnerability detected
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Content Security Policy (CSP)",
                    result="CSP header not present, increasing risk of XSS attacks.",
                    severity="Medium",
                    recommendation="Implement a robust Content Security Policy to mitigate XSS risks.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=True
                )
            else:
                # No vulnerability detected
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Content Security Policy (CSP)",
                    result="Content Security Policy headers are properly set.",
                    severity="None",
                    recommendation="Ensure CSP headers are correctly configured.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=False
                )
        else:
            # No response received
            self.add_result(
                endpoint=url,
                method=method,
                issue="Content Security Policy (CSP)",
                result="No response received during CSP test.",
                severity="Medium",
                recommendation="Implement a robust Content Security Policy to mitigate XSS risks.",
                req_method=method,
                request_headers=request_headers,
                request_body=request_body,
                response_body="No response",
                resp=None,
                vulnerability_found=False
            )

    def test_api_versioning_security(self, url, method, path_str, details):
        """Test for API Versioning Security."""
        self.log("Testing API Versioning Security.")
        deprecated_versions = ["/v1/", "/v2/"]
        for version in deprecated_versions:
            deprecated_url = url.replace("/v3/", version)
            resp, request_body, request_headers = self.make_request(method, deprecated_url)
            if resp and resp.status_code == 200:
                # Vulnerability detected
                self.add_result(
                    endpoint=deprecated_url,
                    method=method,
                    issue="API Versioning Security",
                    result=f"Deprecated API version accessible: {version}",
                    severity="Low",
                    recommendation="Deprecate and properly manage old API versions.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=True
                )
            else:
                # No vulnerability detected for this version
                self.add_result(
                    endpoint=deprecated_url,
                    method=method,
                    issue="API Versioning Security",
                    result=f"No improper assets management detected for version: {version}. Received status code {resp.status_code if resp else 'No Response'}.",
                    severity="None",
                    recommendation="Deprecate and properly manage old API versions.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body=resp.text if resp else "No response",
                    resp=resp,
                    vulnerability_found=False
                )

    def test_brute_force_attack_mitigation(self, url, method, path_str, details):
        """Test for Brute-Force Attack Mitigation."""
        self.log("Testing Brute-Force Attack Mitigation.")
        if "/login" in url.lower() or "/auth" in url.lower():
            payload = {"username": "testuser", "password": "wrongpassword"}
            blocked = False
            for i in range(10):
                resp, request_body, request_headers = self.make_request(method, url, json=payload)
                if resp and resp.status_code == 429:
                    blocked = True
                    self.log(f"Brute-force attack mitigation triggered on attempt {i+1}.")
                    break
            if blocked:
                # Proper mitigation in place
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Brute-Force Attack Mitigation",
                    result=f"Rate limiting or account lockout triggered after {i+1} failed attempts.",
                    severity="None",
                    recommendation="Brute-force attack mitigation mechanisms are functioning as expected.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=None,
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=False
                )
            else:
                # Vulnerability detected
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Brute-Force Attack Mitigation",
                    result="No rate limiting or account lockout after multiple failed login attempts.",
                    severity="High",
                    recommendation="Implement rate limiting and account lockout mechanisms to prevent brute-force attacks.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=None,
                    response_body=resp.text if resp else "No response",
                    resp=resp,
                    vulnerability_found=True
                )
        else:
            # Brute-force mitigation not applicable
            self.add_result(
                endpoint=url,
                method=method,
                issue="Brute-Force Attack Mitigation",
                result="Brute-force attack mitigation test not applicable for this endpoint.",
                severity="None",
                recommendation="Implement rate limiting and account lockout mechanisms where applicable.",
                req_method=method,
                request_headers=request_headers,
                request_body="N/A",
                response_body="N/A",
                resp=None,
                vulnerability_found=False
            )

    def test_unauthorized_data_manipulation(self, url, method, path_str, details):
        """Test for Unauthorized Data Manipulation Protection."""
        self.log("Testing Unauthorized Data Manipulation Protection.")
        if method in ["PUT", "PATCH"]:
            payload = {"unauthorized_field": "malicious_value"}
            resp, request_body, request_headers = self.make_request(method, url, json=payload)
            if resp and resp.status_code in [200, 201]:
                # Vulnerability detected
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Unauthorized Data Manipulation",
                    result="Endpoint accepted unauthorized data manipulation without proper validation.",
                    severity="High",
                    recommendation="Validate and restrict data fields to prevent unauthorized manipulation.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=json.dumps(payload),
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=True
                )
            else:
                # No vulnerability detected
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Unauthorized Data Manipulation",
                    result=f"No unauthorized data manipulation detected. Received status code {resp.status_code if resp else 'No Response'}.",
                    severity="None",
                    recommendation="Data manipulation protections are functioning as expected.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=json.dumps(payload),
                    response_body=resp.text if resp else "No response",
                    resp=resp,
                    vulnerability_found=False
                )
        else:
            # Unauthorized data manipulation not applicable
            self.add_result(
                endpoint=url,
                method=method,
                issue="Unauthorized Data Manipulation",
                result="Unauthorized data manipulation test not applicable for this HTTP method.",
                severity="None",
                recommendation="Ensure data manipulation protections are in place where applicable.",
                req_method=method,
                request_headers=request_headers,
                request_body="N/A",
                response_body="N/A",
                resp=None,
                vulnerability_found=False
            )

    def test_replay_attack_prevention(self, url, method, path_str, details):
        """Test for Replay Attack Prevention."""
        self.log("Testing Replay Attack Prevention.")
        # This is a simplified simulation as actual replay attacks require token handling
        if "Authorization" in self.headers:
            try:
                token = self.headers["Authorization"].split()[1]
                resp1, request_body1, request_headers1 = self.make_request(method, url)
                resp2, request_body2, request_headers2 = self.make_request(method, url)
                if resp1 and resp2 and resp1.text == resp2.text:
                    # Assuming that identical responses might indicate replay vulnerability
                    self.add_result(
                        endpoint=url,
                        method=method,
                        issue="Replay Attack Prevention",
                        result="Potential vulnerability to replay attacks; identical responses received for repeated requests.",
                        severity="Medium",
                        recommendation="Implement nonce or timestamp mechanisms to prevent replay attacks.",
                        req_method=method,
                        request_headers=request_headers2,
                        request_body=request_body2,
                        response_body=resp2.text,
                        resp=resp2,
                        vulnerability_found=True
                    )
                else:
                    # No vulnerability detected
                    self.add_result(
                        endpoint=url,
                        method=method,
                        issue="Replay Attack Prevention",
                        result=f"No replay attack vulnerability detected. Received different responses or status codes ({resp1.status_code if resp1 else 'No Response'}, {resp2.status_code if resp2 else 'No Response'}).",
                        severity="None",
                        recommendation="Replay attack protections are functioning as expected.",
                        req_method=method,
                        request_headers=request_headers2,
                        request_body=request_body2,
                        response_body=resp2.text if resp2 else "No response",
                        resp=resp2,
                        vulnerability_found=False
                    )
            except Exception as e:
                self.log(f"Failed to decode JWT or perform replay attack prevention test: {e}")
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Replay Attack Prevention",
                    result=f"Failed to perform replay attack prevention test: {e}",
                    severity="Medium",
                    recommendation="Implement nonce or timestamp mechanisms to prevent replay attacks.",
                    req_method=method,
                    request_headers={},
                    request_body="N/A",
                    response_body="N/A",
                    resp=None,
                    vulnerability_found=False
                )
        else:
            # Replay attack prevention not applicable
            self.add_result(
                endpoint=url,
                method=method,
                issue="Replay Attack Prevention",
                result="Replay attack prevention test not applicable due to missing Authorization header.",
                severity="None",
                recommendation="Implement replay attack protections where applicable.",
                req_method=method,
                request_headers={},
                request_body="N/A",
                response_body="N/A",
                resp=None,
                vulnerability_found=False
            )

    def test_unauthorized_password_change(self, url, method, path_str, details):
        """Test for Unauthorized Password Change."""
        self.log("Testing Unauthorized Password Change.")
        if "/change-password" in url.lower():
            payload = {"password": "NewPassword123!"}
            resp, request_body, request_headers = self.make_request(method, url, json=payload)
            if resp and resp.status_code == 200:
                # Vulnerability detected
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Unauthorized Password Change",
                    result="Password change endpoint accessible without proper authorization.",
                    severity="High",
                    recommendation="Ensure that password change operations require proper authentication and authorization.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=json.dumps(payload),
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=True
                )
            else:
                # No vulnerability detected
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Unauthorized Password Change",
                    result=f"No unauthorized password change detected. Received status code {resp.status_code if resp else 'No Response'}.",
                    severity="None",
                    recommendation="Password change operations require proper authentication and authorization.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=json.dumps(payload),
                    response_body=resp.text if resp else "No response",
                    resp=resp,
                    vulnerability_found=False
                )
        else:
            # Password change not applicable
            self.add_result(
                endpoint=url,
                method=method,
                issue="Unauthorized Password Change",
                result="Password change test not applicable for this endpoint.",
                severity="None",
                recommendation="Ensure password change operations require proper authentication and authorization.",
                req_method=method,
                request_headers={},
                request_body="N/A",
                response_body="N/A",
                resp=None,
                vulnerability_found=False
            )

    def test_excessive_data_exposure_debug_endpoint(self, url, method, path_str, details):
        """Test for Excessive Data Exposure through debug endpoint."""
        self.log("Testing Excessive Data Exposure through Debug Endpoint.")
        debug_url = urljoin(self.base_url, "/debug")
        resp, request_body, request_headers = self.make_request(method, debug_url)
        if resp and resp.status_code == 200:
            sensitive_info_patterns = [r"DEBUG", r"stack trace", r"error", r"password"]
            found_pattern = None
            for pattern in sensitive_info_patterns:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    found_pattern = pattern
                    break
            if found_pattern:
                # Vulnerability detected
                self.add_result(
                    endpoint=debug_url,
                    method=method,
                    issue="Excessive Data Exposure through Debug Endpoint",
                    result=f"Debug endpoint exposed sensitive information: {found_pattern}",
                    severity="High",
                    recommendation="Disable debug endpoints in production environments.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=True
                )
            else:
                # No vulnerability detected
                self.add_result(
                    endpoint=debug_url,
                    method=method,
                    issue="Excessive Data Exposure through Debug Endpoint",
                    result="No sensitive information exposed through debug endpoint.",
                    severity="None",
                    recommendation="Ensure debug endpoints do not expose sensitive information.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=False
                )
        else:
            # Debug endpoint not accessible or returned error
            self.add_result(
                endpoint=debug_url,
                method=method,
                issue="Excessive Data Exposure through Debug Endpoint",
                result=f"Debug endpoint not accessible or returned status code {resp.status_code if resp else 'No Response'}.",
                severity="None",
                recommendation="Ensure debug endpoints do not expose sensitive information.",
                req_method=method,
                request_headers=request_headers,
                request_body=request_body,
                response_body=resp.text if resp else "No response",
                resp=resp,
                vulnerability_found=False
            )

    def test_user_password_enumeration(self, url, method, path_str, details):
        """Test for User and Password Enumeration."""
        self.log("Testing User and Password Enumeration.")
        if "/login" in url.lower():
            payload_valid = {"username": "validuser", "password": "validpassword"}
            payload_invalid = {"username": "validuser", "password": "invalidpassword"}
            resp_valid, request_body_valid, request_headers_valid = self.make_request(method, url, json=payload_valid)
            resp_invalid, request_body_invalid, request_headers_invalid = self.make_request(method, url, json=payload_invalid)
            if resp_valid and resp_invalid:
                if resp_valid.status_code == resp_invalid.status_code and resp_valid.text == resp_invalid.text:
                    # Potential vulnerability detected
                    self.add_result(
                        endpoint=url,
                        method=method,
                        issue="User and Password Enumeration",
                        result="Login responses do not differentiate between valid and invalid credentials.",
                        severity="Medium",
                        recommendation="Provide generic error messages to prevent enumeration attacks.",
                        req_method=method,
                        request_headers=request_headers_invalid,
                        request_body=request_body_invalid,
                        response_body=resp_invalid.text,
                        resp=resp_invalid,
                        vulnerability_found=True
                    )
                else:
                    # No vulnerability detected
                    self.add_result(
                        endpoint=url,
                        method=method,
                        issue="User and Password Enumeration",
                        result="Login responses differentiate between valid and invalid credentials.",
                        severity="None",
                        recommendation="Ensure error messages do not reveal credential validity.",
                        req_method=method,
                        request_headers=request_headers_invalid,
                        request_body=request_body_invalid,
                        response_body=resp_invalid.text,
                        resp=resp_invalid,
                        vulnerability_found=False
                    )
            else:
                # Handle cases where responses are not received
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="User and Password Enumeration",
                    result="Failed to receive responses for login attempts.",
                    severity="Medium",
                    recommendation="Ensure authentication endpoints are operational and secure.",
                    req_method=method,
                    request_headers={},
                    request_body="N/A",
                    response_body="No response",
                    resp=None,
                    vulnerability_found=False
                )
        else:
            # User and Password Enumeration not applicable
            self.add_result(
                endpoint=url,
                method=method,
                issue="User and Password Enumeration",
                result="User and Password Enumeration test not applicable for this endpoint.",
                severity="None",
                recommendation="Ensure error messages do not reveal credential validity.",
                req_method=method,
                request_headers={},
                request_body="N/A",
                response_body="N/A",
                resp=None,
                vulnerability_found=False
            )

    def test_regex_dos(self, url, method, path_str, details):
        """Test for Regex Denial of Service (RegexDOS)."""
        self.log("Testing Regex Denial of Service (RegexDOS).")
        # This is a theoretical test as actual RegexDOS requires specific vulnerable regex patterns
        # Here, we simulate by sending a long input that could trigger vulnerable regex
        malicious_input = "A" * 10000  # Very long input
        injection_point = self.get_injection_point(url, path_str)
        if injection_point:
            vulnerable_url = injection_point.replace("{{injection}}", malicious_input)
            resp, request_body, request_headers = self.make_request(method, vulnerable_url)
            if resp and resp.elapsed.total_seconds() > 5:
                # Potential vulnerability detected
                self.add_result(
                    endpoint=vulnerable_url,
                    method=method,
                    issue="Regex Denial of Service (RegexDOS)",
                    result="Endpoint may be vulnerable to RegexDOS; slow response detected.",
                    severity="High",
                    recommendation="Optimize regex patterns and implement input size limitations to prevent DOS attacks.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=True
                )
            else:
                # No vulnerability detected
                self.add_result(
                    endpoint=vulnerable_url,
                    method=method,
                    issue="Regex Denial of Service (RegexDOS)",
                    result=f"No RegexDOS vulnerability detected. Response time was {resp.elapsed.total_seconds() if resp else 'No Response'} seconds.",
                    severity="None",
                    recommendation="Ensure regex patterns are optimized and input size limitations are in place.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body=resp.text if resp else "No response",
                    resp=resp,
                    vulnerability_found=False
                )
        else:
            # Injection point not found
            self.add_result(
                endpoint=url,
                method=method,
                issue="Regex Denial of Service (RegexDOS)",
                result="RegexDOS test not applicable for this endpoint.",
                severity="None",
                recommendation="Ensure regex patterns are optimized and input size limitations are in place.",
                req_method=method,
                request_headers={},
                request_body="N/A",
                response_body="N/A",
                resp=None,
                vulnerability_found=False
            )

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
                    # Vulnerability detected
                    self.add_result(
                        endpoint=url,
                        method=method,
                        issue="JWT Authentication Bypass",
                        result=f"JWT uses weak or insecure signing algorithm: {header.get('alg')}",
                        severity="High",
                        recommendation="Use strong signing algorithms like RS256 and enforce token verification.",
                        req_method=method,
                        request_headers=self.headers,
                        request_body=None,
                        response_body=None,
                        resp=None,
                        vulnerability_found=True
                    )
                else:
                    # No vulnerability detected
                    self.add_result(
                        endpoint=url,
                        method=method,
                        issue="JWT Authentication Bypass",
                        result=f"JWT signing algorithm is secure: {header.get('alg')}.",
                        severity="None",
                        recommendation="Ensure strong signing algorithms are used and tokens are properly verified.",
                        req_method=method,
                        request_headers=self.headers,
                        request_body=None,
                        response_body=None,
                        resp=None,
                        vulnerability_found=False
                    )
            except Exception as e:
                self.log(f"Failed to decode JWT: {e}")
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="JWT Authentication Bypass",
                    result=f"Failed to decode JWT: {e}",
                    severity="Medium",
                    recommendation="Ensure JWT tokens are properly structured and signed.",
                    req_method=method,
                    request_headers=self.headers,
                    request_body=None,
                    response_body="N/A",
                    resp=None,
                    vulnerability_found=False
                )
        else:
            # JWT Authentication Bypass not applicable
            self.add_result(
                endpoint=url,
                method=method,
                issue="JWT Authentication Bypass",
                result="JWT Authentication Bypass test not applicable due to missing Authorization header.",
                severity="None",
                recommendation="Ensure JWT tokens are properly structured and signed.",
                req_method=method,
                request_headers={},
                request_body="N/A",
                response_body="N/A",
                resp=None,
                vulnerability_found=False
            )

    # New Test Methods

    def test_information_disclosure(self, url, method, path_str, details):
        """Test for Information Disclosure via Server Header."""
        self.log("Testing Information Disclosure via Server Header.")
        resp, request_body, request_headers = self.make_request(method, url)
        if resp:
            server_header = resp.headers.get("Server", "")
            if server_header:
                # Check if Server header reveals technology and version
                if re.search(r"werkzeug", server_header, re.IGNORECASE) and re.search(r"python", server_header, re.IGNORECASE):
                    # Vulnerability detected
                    self.add_result(
                        endpoint=url,
                        method=method,
                        issue="Information Disclosure",
                        result="Server header reveals server technology and Python version.",
                        severity="Medium",
                        recommendation="Configure server to hide sensitive information in headers.",
                        req_method=method,
                        request_headers=request_headers,
                        request_body=request_body,
                        response_body=resp.text,
                        resp=resp,
                        vulnerability_found=True
                    )
                else:
                    # No vulnerability detected
                    self.add_result(
                        endpoint=url,
                        method=method,
                        issue="Information Disclosure",
                        result="Server header does not disclose sensitive information.",
                        severity="None",
                        recommendation="Ensure server headers do not reveal sensitive information.",
                        req_method=method,
                        request_headers=request_headers,
                        request_body=request_body,
                        response_body=resp.text,
                        resp=resp,
                        vulnerability_found=False
                    )
            else:
                # Server header not present
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Information Disclosure",
                    result="Server header not present.",
                    severity="Medium",
                    recommendation="Ensure server headers do not reveal sensitive information.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=False
                )
        else:
            # No response received
            self.add_result(
                endpoint=url,
                method=method,
                issue="Information Disclosure",
                result="No response received during Information Disclosure test.",
                severity="Medium",
                recommendation="Ensure server headers do not reveal sensitive information.",
                req_method=method,
                request_headers=request_headers,
                request_body=request_body,
                response_body="No response",
                resp=None,
                vulnerability_found=False
            )

    def test_insufficient_data_protection(self, url, method, path_str, details):
        """Test for Insufficient Data Protection."""
        self.log("Testing Insufficient Data Protection.")
        resp, request_body, request_headers = self.make_request(method, url)
        if resp:
            # Example check: usernames transmitted in plaintext
            if re.search(r"username\s*:\s*['\"]\w+['\"]", resp.text, re.IGNORECASE):
                # Vulnerability detected
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Insufficient Data Protection",
                    result="Usernames are transmitted in plaintext.",
                    severity="High",
                    recommendation="Anonymize, pseudonymize, or encrypt sensitive data in responses.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=True
                )
            else:
                # No vulnerability detected
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Insufficient Data Protection",
                    result="No sensitive data exposure detected in response.",
                    severity="None",
                    recommendation="Ensure sensitive data is properly protected.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=False
                )
        else:
            # No response received
            self.add_result(
                endpoint=url,
                method=method,
                issue="Insufficient Data Protection",
                result="No response received during Insufficient Data Protection test.",
                severity="High",
                recommendation="Ensure sensitive data is properly protected.",
                req_method=method,
                request_headers=request_headers,
                request_body=request_body,
                response_body="No response",
                resp=None,
                vulnerability_found=False
            )

    def test_insufficient_access_control(self, url, method, path_str, details):
        """Test for Insufficient Access Control."""
        self.log("Testing Insufficient Access Control.")
        # Attempt to access admin data without authorization
        admin_url = urljoin(self.base_url, "/admin/data")
        resp, request_body, request_headers = self.make_request(method, admin_url)
        if resp and resp.status_code == 200:
            # Vulnerability detected
            self.add_result(
                endpoint=admin_url,
                method=method,
                issue="Insufficient Access Control",
                result="Admin data accessible without proper authentication or authorization.",
                severity="High",
                recommendation="Ensure that all sensitive endpoints enforce strict authentication and authorization.",
                req_method=method,
                request_headers=request_headers,
                request_body=request_body,
                response_body=resp.text,
                resp=resp,
                vulnerability_found=True
            )
        else:
            # No vulnerability detected
            self.add_result(
                endpoint=admin_url,
                method=method,
                issue="Insufficient Access Control",
                result=f"No unauthorized access detected. Received status code {resp.status_code if resp else 'No Response'}.",
                severity="None",
                recommendation="Access control mechanisms are functioning as expected.",
                req_method=method,
                request_headers=request_headers,
                request_body=request_body,
                response_body=resp.text if resp else "No response",
                resp=resp,
                vulnerability_found=False
            )

    # Helper Methods

    def get_injection_point(self, url, path_str):
        """Identify injection points in the URL path."""
        if "{" in path_str and "}" in path_str:
            return re.sub(r"\{[^}]+\}", "{{injection}}", url)
        return None

    def make_request(self, method, url, params=None, json=None, data=None, files=None, headers=None):
        """Send an HTTP request and return the response, request body, and request headers."""
        if self.randomize:
            sleep_time = random.randint(1, 30)
            self.log(f"Sleeping for {sleep_time} seconds before making the request to {url}")
            time.sleep(sleep_time)

        self.log(f"Sending {method} request to {url}")
        request_body = None
        if params:
            self.log(f"Request parameters: {json.dumps(params, indent=2)}")
            request_body = json.dumps(params, indent=2)
        if json:
            self.log(f"Request body: {json.dumps(json, indent=2)}")
            request_body = json.dumps(json, indent=2)
        if data:
            self.log(f"Request body: {data}")
            request_body = data
        if files:
            self.log(f"Uploading files: {list(files.keys())}")
            request_body = f"Files: {list(files.keys())}"
        try:
            merged_headers = self.headers.copy()
            if headers:
                merged_headers.update(headers)
            response = requests.request(method, url, headers=merged_headers, proxies=self.proxy,
                                        params=params, json=json, data=data, files=files, timeout=10, allow_redirects=True)
            self.log(f"Received response with status code {response.status_code}.")
            self.log(f"Response body: {resp_truncated(response.text)}")
            return response, request_body, merged_headers
        except RequestException as e:
            self.log(f"Request to {url} failed: {e}")
            return None, request_body, {}

    def send_to_openai(self, response):
        """Send the API response to OpenAI GPT-4 for analysis with retry on 429 errors."""
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

        # Log the prompt being sent to OpenAI
        self.log(f"Sending to OpenAI prompt: {prompt}")

        payload = {
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": "You are a cybersecurity expert."},
                {"role": "user", "content": prompt}
            ]
        }

        max_retries = 5
        retries = 0

        while retries < max_retries:
            try:
                response_openai = requests.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {openai.api_key}",
                        "Content-Type": "application/json"
                    },
                    json=payload
                )
                if response_openai.status_code == 200:
                    feedback = response_openai.json()["choices"][0]["message"]["content"]
                    self.log(f"OpenAI GPT-4 response: {feedback}")
                    return feedback
                elif response_openai.status_code == 429:
                    retries += 1
                    retry_after = int(response_openai.headers.get("Retry-After", "1"))
                    wait_time = (2 ** retries) + random.uniform(0, 1)
                    self.log(f"OpenAI API rate limit exceeded. Retrying in {wait_time:.2f} seconds...")
                    time.sleep(wait_time)
                else:
                    self.log(f"OpenAI API error: {response_openai.status_code} - {response_openai.text}")
                    return f"OpenAI API error: {response_openai.status_code}"
            except requests.exceptions.RequestException as e:
                self.log(f"Failed to communicate with OpenAI: {e}")
                return f"Error communicating with OpenAI: {e}"

        self.log("Max retries exceeded for OpenAI API.")
        return "Max retries exceeded for OpenAI API."

    def add_result(self, endpoint, method, issue, result, severity, recommendation, req_method, request_headers, request_body, response_body, resp=None, vulnerability_found=False):
        """Store a vulnerability discovery result."""
        if not self.offai and vulnerability_found:
            openai_feedback = self.send_to_openai(resp) if resp else "No feedback from OpenAI."
        elif not self.offai:
            openai_feedback = "No vulnerability detected."
        else:
            openai_feedback = "OpenAI analysis disabled."

        # Ensure response_body_received is always a string
        if response_body is None:
            response_body = "N/A"
        elif not isinstance(response_body, str):
            response_body = str(response_body)
        else:
            # No escaping; log all content as-is
            pass

        # Convert headers dict to a formatted string without escaping
        headers_formatted = "\n".join([f"{key}: {value}" for key, value in request_headers.items()]) if request_headers else "N/A"
        self.results.append({
            "endpoint": endpoint,
            "method": method,
            "issue": issue,
            "result": result,
            "severity": severity,
            "recommendation": recommendation,
            "http_method": req_method,
            "request_headers_sent": headers_formatted,
            "request_body_sent": request_body if request_body else "N/A",
            "response_body_received": response_body,
            "vulnerability_found": "Yes" if vulnerability_found else "No",
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
                        "<th>Result</th><th>Severity</th><th>Recommendation</th>"
                        "<th>HTTP Method</th><th>Request Headers Sent</th><th>Request Body Sent</th>"
                        "<th>Response Body Received</th><th>Vulnerability Found</th><th>OpenAI Feedback</th></tr>")
                for res in self.results:
                    # Safeguard against NoneType
                    request_body = res['request_body_sent']
                    if not isinstance(request_body, str):
                        request_body = "N/A"

                    response_body = res['response_body_received']
                    if not isinstance(response_body, str):
                        response_body = "N/A"

                    f.write(f"<tr><td>{res['endpoint']}</td><td>{res['method']}</td>"
                            f"<td>{res['issue']}</td><td>{res['result']}</td>"
                            f"<td>{res['severity']}</td><td>{res['recommendation']}</td>"
                            f"<td>{res['http_method']}</td>"
                            f"<td><pre>{res['request_headers_sent']}</pre></td>"
                            f"<td><pre>{request_body}</pre></td>"
                            f"<td><pre>{response_body}</pre></td>"
                            f"<td>{res['vulnerability_found']}</td>"
                            f"<td>{html.escape(res['openai_feedback'])}</td></tr>")
                f.write("</table></body></html>")
            self.log(f"Report saved as {self.output_file}.html")

# Helper Functions

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
    parser.add_argument("--random", action="store_true", help="Enable random delays between requests to avoid rate limiting.")
    parser.add_argument("--offai", action="store_true", help="Disable sending data to OpenAI for analysis.")
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
        randomize=args.random,  # Pass the randomize flag
        offai=args.offai         # Pass the offai flag
    )
    scanner.load_spec()
    scanner.scan_endpoints()
    scanner.generate_report()

if __name__ == "__main__":
    main()
