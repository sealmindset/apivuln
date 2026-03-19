#!/usr/bin/env python3
"""
API Vulnerability Scanner - OWASP API Security (2023 Edition)
Enhanced with dynamic test case generation based on discovered sensitive information.
Includes additional security tests, OpenAI API integration for analysis, and comprehensive reporting.
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
import string
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
from requests.exceptions import RequestException
import openai

def resp_truncated(text, limit=500):
    return text if len(text) <= limit else text[:limit] + "..."

class APIVulnerabilityScanner:
    def __init__(
        self,
        spec_file=None,
        base_url=None,
        proxy=None,
        token=None,
        output_format="json",
        output_file="report",
        randomize=False,
        offai=False
    ):
        self.spec_file = spec_file
        self.base_url = base_url
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.token = token
        self.headers = (
            {"Authorization": f"Bearer {token}", "Accept": "application/json"}
            if token
            else {}
        )
        self.output_format = output_format
        self.output_file = output_file
        self.randomize = randomize
        self.offai = offai

        if not self.offai:
            openai.api_key = os.getenv("OPENAI_API_KEY")
            if not openai.api_key:
                raise ValueError(
                    "OpenAI API key not found. Please set the OPENAI_API_KEY environment variable."
                )

        self.results = []
        self.discovered_usernames = set()
        self.discovered_passwords = set()
        self.endpoints_with_placeholders = []
        self.global_session_counter = 0

        self.test_methods = [
            self.test_broken_object_level_auth,
            self.test_broken_authentication,
            self.test_broken_function_level_authorization,
            self.test_mass_assignment,
            self.test_insufficient_access_control,
            self.test_unauthorized_password_change,
            self.test_replay_attack_prevention,
            self.test_brute_force_attack_mitigation,
            self.test_excessive_data_exposure,
            self.test_excessive_data_exposure_debug_endpoint,
            self.test_improper_assets_management,
            self.test_insufficient_data_protection,
            self.test_user_password_enumeration_unique,
            self.test_caching_mechanisms,
            self.test_information_disclosure,
            self.test_injection,
            self.test_sql_injection,
            self.test_xss,
            self.test_server_side_template_injection,
            self.test_directory_traversal,
            self.test_deserialization_vulnerabilities,
            self.test_regex_dos,
            self.test_security_misconfiguration,
            self.test_xxe_protection,
            self.test_graphql,
            self.test_websocket,
            self.test_file_upload_security,
            self.test_secure_transmission,
            self.test_content_security_policy,
            self.test_api_versioning_security,
            self.test_fuzzing,
        ]

    def get_new_session_id(self):
        self.global_session_counter += 1
        return self.global_session_counter

    def log(self, message, session_id):
        """
        Logs the provided message both to the console (stdout)
        and to the log file, each prefixed with [LOG][<session_id>].
        """
        log_message = f"[LOG][{session_id}] {message}"
        print(log_message)  # Console
        log_file = f"{self.output_file}.log"
        try:
            with open(log_file, "a") as lf:
                lf.write(log_message + "\n")
        except Exception as e:
            print(f"[ERROR] Failed to write to log file: {e}")

    def load_spec(self):
        if not self.spec_file:
            raise ValueError("No specification file provided.")
        try:
            with open(self.spec_file, "r") as f:
                if self.spec_file.endswith(".yml") or self.spec_file.endswith(".yaml"):
                    self.spec = yaml.safe_load(f)
                elif self.spec_file.endswith(".json"):
                    self.spec = json.load(f)
                else:
                    raise ValueError(
                        "Unsupported file format. Use .yml, .yaml, or .json."
                    )
            sid = self.get_new_session_id()
            self.log("Successfully loaded the OpenAPI/Swagger specification.", sid)
            self.identify_endpoints_with_placeholders(sid)
        except Exception as e:
            raise ValueError(f"Failed to load API spec: {e}")

    def identify_endpoints_with_placeholders(self, session_id):
        self.log("Identifying endpoints with URL placeholders.", session_id)
        paths = self.spec.get("paths", {})
        for path, methods in paths.items():
            for method in methods:
                if "{" in path and "}" in path:
                    full_url = urljoin(self.base_url, path)
                    self.endpoints_with_placeholders.append(
                        {
                            "path": path,
                            "method": method.upper(),
                            "url_template": full_url,
                        }
                    )
        self.log(
            f"Found {len(self.endpoints_with_placeholders)} endpoints with placeholders.",
            session_id,
        )

    def scan_endpoints(self):
        sid = self.get_new_session_id()
        self.log("Starting to scan API endpoints.", sid)
        paths = self.spec.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                method = method.upper()
                url = urljoin(self.base_url, path)
                sub_sid = self.get_new_session_id()
                self.log(f"Testing {method} {url} sequentially.", sub_sid)
                try:
                    self.test_endpoint(url, method, path, details)
                except Exception as e:
                    self.log(f"Error during endpoint testing: {e}", sub_sid)

        self.perform_dynamic_tests()

    def test_endpoint(self, url, method, path_str, details):
        for test_method in self.test_methods:
            method_sid = self.get_new_session_id()
            self.log(
                f"Running {test_method.__name__} on {method} {url}",
                method_sid,
            )
            try:
                test_method(url, method, path_str, details, method_sid)
            except Exception as e:
                self.log(
                    f"Error in {test_method.__name__} for {method} {url}: {e}",
                    method_sid,
                )
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue=test_method.__name__,
                    result=f"Error during testing: {e}",
                    severity="Medium",
                    recommendation="Investigate and address the underlying issue causing this error.",
                    req_method=method,
                    request_headers={},
                    request_body="N/A",
                    response_body=str(e),
                    resp=None,
                    vulnerability_found=False,
                    session_id=method_sid,
                )

    def discover_endpoints(self, session_id):
        self.log("Discovering endpoints automatically.", session_id)
        common_paths = [
            "/api",
            "/auth",
            "/login",
            "/admin",
            "/data",
            "/v1",
            "/v2",
            "/users",
        ]
        discovered_endpoints = []
        for path in common_paths:
            url = urljoin(self.base_url, path)
            try:
                resp = requests.get(url, headers=self.headers, timeout=5)
                if resp.status_code == 200:
                    discovered_endpoints.append({"url": url, "method": "GET"})
                    self.log(f"Discovered endpoint: {url}", session_id)
            except Exception as e:
                self.log(f"Error probing {url}: {e}", session_id)
        self.log(
            f"Discovered {len(discovered_endpoints)} endpoints.", session_id
        )
        self.endpoints_with_placeholders.extend(discovered_endpoints)

    def test_broken_object_level_auth(self, url, method, path_str, details, session_id):
        if "{" in path_str and "}" in path_str:
            forced_param_url = re.sub(r"\{[^}]+\}", "1", url)
            another_id_url = re.sub(r"\{[^}]+\}", "2", url)
            resp_original, request_body, request_headers = self.make_request(
                method, forced_param_url, session_id=session_id
            )
            resp_other, _, _ = self.make_request(
                method, another_id_url, session_id=session_id
            )
            if resp_original and resp_other and resp_original.text != resp_other.text:
                self.add_result(
                    endpoint=another_id_url,
                    method=method,
                    issue="Broken Object Level Authorization",
                    result="Access to unauthorized object confirmed.",
                    severity="High",
                    recommendation="Enforce object-level access controls.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body=resp_other.text,
                    resp=resp_other,
                    vulnerability_found=True,
                    session_id=session_id,
                )

    def test_broken_authentication(
        self, url, method, path_str=None, details=None, session_id=None
    ):
        self.log("Testing Broken Authentication.", session_id)
        original_headers = dict(self.headers)
        self.headers.pop("Authorization", None)
        try:
            resp, request_body, request_headers = self.make_request(
                method, url, session_id=session_id
            )
            if resp and resp.status_code == 200:
                usernames = self.extract_usernames(resp.text, session_id)
                self.discovered_usernames.update(usernames)
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Broken Authentication",
                    result="Endpoint returned 200 without authentication.",
                    severity="High",
                    recommendation="Ensure authentication is enforced and endpoints are secured.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=True,
                    session_id=session_id,
                )
            else:
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
                    vulnerability_found=False,
                    session_id=session_id,
                )
        finally:
            self.headers = original_headers

    def test_excessive_data_exposure(self, url, method, path_str, details, session_id):
        resp, request_body, request_headers = self.make_request(
            method, url, session_id=session_id
        )
        if resp and resp.status_code == 200:
            sensitive_keywords = ["password", "secret", "token", "apikey", "creditcard"]
            found_keyword = None
            for keyword in sensitive_keywords:
                if keyword in resp.text.lower():
                    found_keyword = keyword
                    break
            if found_keyword:
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Excessive Data Exposure",
                    result=f"Response contains sensitive keyword: {found_keyword}",
                    severity="Medium",
                    recommendation="Limit data exposure to necessary fields and enforce proper filtering.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=True,
                    session_id=session_id,
                )
            else:
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
                    vulnerability_found=False,
                    session_id=session_id,
                )
        else:
            self.add_result(
                endpoint=url,
                method=method,
                issue="Excessive Data Exposure",
                result=f"Unexpected response status code {resp.status_code if resp else 'No Response'}.",
                severity="None",
                recommendation="Review data exposure mechanisms and ensure proper response handling.",
                req_method=method,
                request_headers=request_headers,
                request_body=request_body,
                response_body=resp.text if resp else "No response",
                resp=resp,
                vulnerability_found=False,
                session_id=session_id,
            )

    def test_lack_of_resources_and_rate_limiting(self, url, method, path_str, details, session_id):
        limit_triggered = False
        for i in range(20):
            resp, request_body, request_headers = self.make_request(
                method, url, session_id=session_id
            )
            if resp and resp.status_code == 429:
                limit_triggered = True
                break
        if limit_triggered:
            self.add_result(
                endpoint=url,
                method=method,
                issue="Lack of Resources & Rate Limiting",
                result=f"Rate limiting or account lockout triggered after {i+1} requests.",
                severity="None",
                recommendation="Rate limiting is functioning correctly.",
                req_method=method,
                request_headers=request_headers,
                request_body=None,
                response_body=resp.text,
                resp=resp,
                vulnerability_found=False,
                session_id=session_id,
            )
        else:
            self.add_result(
                endpoint=url,
                method=method,
                issue="Lack of Resources & Rate Limiting",
                result="No rate limiting detected after multiple requests.",
                severity="Medium",
                recommendation="Implement rate limiting to protect against DoS attacks.",
                req_method=method,
                request_headers=request_headers,
                request_body=None,
                response_body=resp.text if resp else "No response",
                resp=resp,
                vulnerability_found=True,
                session_id=session_id,
            )

    def test_excessive_data_exposure_debug_endpoint(
        self, url, method, path_str, details, session_id
    ):
        self.log("Testing Excessive Data Exposure through Debug Endpoint.", session_id)
        debug_url = urljoin(self.base_url, "/debug")
        resp, request_body, request_headers = self.make_request(
            method, debug_url, session_id=session_id
        )
        if resp and resp.status_code == 200:
            sensitive_info_patterns = [r"DEBUG", r"stack trace", r"error", r"password"]
            found_pattern = None
            for pattern in sensitive_info_patterns:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    found_pattern = pattern
                    break
            if found_pattern:
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
                    vulnerability_found=True,
                    session_id=session_id,
                )
            else:
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
                    vulnerability_found=False,
                    session_id=session_id,
                )
        else:
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
                vulnerability_found=False,
                session_id=session_id,
            )

    def test_broken_function_level_authorization(
        self, url, method, path_str, details, session_id
    ):
        self.log("Testing Broken Function Level Authorization.", session_id)
        admin_url = urljoin(self.base_url, "/admin")
        resp, request_body, request_headers = self.make_request(
            method, admin_url, session_id=session_id
        )
        if resp and resp.status_code == 200:
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
                vulnerability_found=True,
                session_id=session_id,
            )
        else:
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
                vulnerability_found=False,
                session_id=session_id,
            )

    def test_mass_assignment(self, url, method, path_str, details, session_id):
        self.log(f"Testing {method} {url} for mass assignment vulnerabilities.", session_id)
        try:
            # Generate payload
            payload = self.generate_payload(details, session_id)
            self.log(f"Generated payload: {payload}", session_id)

            # Make the request
            resp, request_body, request_headers = self.make_request(
                method=method,
                url=url,
                json_data=payload,
                session_id=session_id
            )

            # Handle the response
            if resp and resp.status_code == 200:
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Mass Assignment",
                    result="Mass assignment vulnerability detected.",
                    severity="High",
                    recommendation="Validate input fields on the server to prevent unauthorized assignments.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=True,
                    session_id=session_id,
                )
            else:
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Mass Assignment",
                    result="No mass assignment vulnerability detected.",
                    severity="None",
                    recommendation="Mass assignment protections appear to be functioning as expected.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body=resp.text if resp else "No response",
                    resp=resp,
                    vulnerability_found=False,
                    session_id=session_id,
                )
        except Exception as e:
            self.log(f"Error during mass assignment test: {e}", session_id)
            self.add_result(
                endpoint=url,
                method=method,
                issue="Mass Assignment",
                result=f"Error encountered: {e}",
                severity="Medium",
                recommendation="Investigate the error and ensure robust input validation.",
                req_method=method,
                request_headers=request_headers if "request_headers" in locals() else {},
                request_body=request_body if "request_body" in locals() else None,
                response_body="No response due to error",
                resp=None,
                vulnerability_found=False,
                session_id=session_id,
            )


    def test_insufficient_access_control(self, url, method, path_str, details, session_id):
        self.log("Testing Insufficient Access Control.", session_id)
        restricted_endpoints = [
            "/admin",
            "/admin/data",
            "/settings",
            "/config",
            "/user/roles",
        ]
        for endpoint in restricted_endpoints:
            restricted_url = urljoin(self.base_url, endpoint)
            resp, request_body, request_headers = self.make_request(
                method, restricted_url, session_id=session_id
            )
            if resp:
                if resp.status_code in [200, 201]:
                    self.add_result(
                        endpoint=restricted_url,
                        method=method,
                        issue="Insufficient Access Control",
                        result=f"Access to restricted endpoint {endpoint} granted without proper authorization.",
                        severity="High",
                        recommendation="Implement strict access controls to restrict unauthorized access to sensitive endpoints.",
                        req_method=method,
                        request_headers=request_headers,
                        request_body=request_body,
                        response_body=resp.text,
                        resp=resp,
                        vulnerability_found=True,
                        session_id=session_id,
                    )
                elif resp.status_code in [401, 403]:
                    self.add_result(
                        endpoint=restricted_url,
                        method=method,
                        issue="Insufficient Access Control",
                        result=f"Proper access control enforced for endpoint {endpoint}.",
                        severity="None",
                        recommendation="Access controls are functioning as expected.",
                        req_method=method,
                        request_headers=request_headers,
                        request_body=request_body,
                        response_body=resp.text,
                        resp=resp,
                        vulnerability_found=False,
                        session_id=session_id,
                    )
                else:
                    self.add_result(
                        endpoint=restricted_url,
                        method=method,
                        issue="Insufficient Access Control",
                        result=f"Unexpected response for endpoint {endpoint}. Status code: {resp.status_code}.",
                        severity="Medium",
                        recommendation="Review access control configurations for unexpected behaviors.",
                        req_method=method,
                        request_headers=request_headers,
                        request_body=request_body,
                        response_body=resp.text,
                        resp=resp,
                        vulnerability_found=False,
                        session_id=session_id,
                    )
            else:
                self.add_result(
                    endpoint=restricted_url,
                    method=method,
                    issue="Insufficient Access Control",
                    result=f"No response received when accessing restricted endpoint {endpoint}.",
                    severity="Medium",
                    recommendation="Ensure restricted endpoints are properly secured and accessible only to authorized users.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body="No response",
                    resp=None,
                    vulnerability_found=False,
                    session_id=session_id,
                )

    def test_security_misconfiguration(self, url, method, path_str, details, session_id):
        self.log("Testing Security Misconfiguration.", session_id)
        common_paths = ["/.git", "/config.php", "/backup.zip"]
        for path in common_paths:
            test_url = urljoin(self.base_url, path)
            resp, request_body, request_headers = self.make_request(
                "GET", test_url, session_id=session_id
            )
            if resp and resp.status_code == 200:
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
                    vulnerability_found=True,
                    session_id=session_id,
                )
            else:
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
                    vulnerability_found=False,
                    session_id=session_id,
                )

    def test_injection(self, url, method, path_str, details, session_id):
        injection_payload = "' OR '1'='1"
        if "{" in path_str and "}" in path_str:
            injection_url = re.sub(r"\{[^}]+\}", injection_payload, url)
            resp, request_body, request_headers = self.make_request(
                method, injection_url, session_id=session_id
            )
            if resp:
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
                    "fatal error",
                ]
                found_error = False
                for indicator in error_indicators:
                    if indicator.lower() in resp.text.lower():
                        found_error = True
                        break
                if found_error:
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
                        vulnerability_found=True,
                        session_id=session_id,
                    )
                else:
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
                        vulnerability_found=False,
                        session_id=session_id,
                    )
        else:
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
                vulnerability_found=False,
                session_id=session_id,
            )

    def test_sql_injection(self, url, method, path_str, details, session_id):
        sql_payloads = [
            "'",
            "' AND 1=1--",
            "' AND 1=2--",
            "' OR '1'='1",
            "' OR '1'='2",
            "'; DROP TABLE users--",
            "'; SELECT * FROM users--",
        ]
        if "{" in path_str and "}" in path_str:
            for payload in sql_payloads:
                injection_url = re.sub(r"\{[^}]+\}", payload, url)
                resp, request_body, request_headers = self.make_request(
                    method, injection_url, session_id=session_id
                )
                if resp and sql_payloads[0] in resp.text and sql_payloads[1] not in resp.text:
                    self.add_result(
                        endpoint=injection_url,
                        method=method,
                        issue="SQL Injection",
                        result="SQL injection vulnerability confirmed.",
                        severity="High",
                        recommendation="Sanitize and validate all user inputs to prevent SQL injection.",
                        req_method=method,
                        request_headers=request_headers,
                        request_body=request_body,
                        response_body=resp.text,
                        resp=resp,
                        vulnerability_found=True,
                        session_id=session_id,
                    )

    def test_improper_assets_management(self, url, method, path_str, details, session_id):
        """Test for improper assets management vulnerabilities."""
        self.log(f"Testing Improper Assets Management on {url}.", session_id)

        try:
            # Make the initial request
            resp1, request_body1, request_headers1 = self.make_request(
                method=method, url=url, session_id=session_id
            )
            self.log(f"Initial response: {resp1.text}", session_id)

            # Make a second request to observe behavior
            resp2, request_body2, request_headers2 = self.make_request(
                method=method, url=url, session_id=session_id
            )
            self.log(f"Second response: {resp2.text}", session_id)

            # Analyze responses
            if resp2 and resp2.status_code == 500:
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Improper Assets Management",
                    result=(
                        "Repeated calls to the endpoint resulted in a server-side error exposing "
                        "sensitive information, including a traceback and database details."
                    ),
                    severity="High",
                    recommendation=(
                        "Ensure endpoints are idempotent and errors do not expose sensitive details. "
                        "Implement proper error handling and logging."
                    ),
                    req_method=method,
                    request_headers=request_headers2,
                    request_body=request_body2,
                    response_body=resp2.text,
                    resp=resp2,
                    vulnerability_found=True,
                    session_id=session_id,
                )
            else:
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Improper Assets Management",
                    result="No improper assets management issues detected.",
                    severity="None",
                    recommendation="Ensure proper error handling and endpoint idempotency.",
                    req_method=method,
                    request_headers=request_headers1,
                    request_body=request_body1,
                    response_body=resp1.text,
                    resp=resp1,
                    vulnerability_found=False,
                    session_id=session_id,
                )
        except Exception as e:
            self.log(f"Error during improper assets management test: {e}", session_id)
            self.add_result(
                endpoint=url,
                method=method,
                issue="Improper Assets Management",
                result=f"Error encountered during test: {e}",
                severity="Medium",
                recommendation="Investigate the error and ensure robust endpoint handling.",
                req_method=method,
                request_headers=request_headers1 if "request_headers1" in locals() else {},
                request_body=request_body1 if "request_body1" in locals() else None,
                response_body="No response due to error",
                resp=None,
                vulnerability_found=False,
                session_id=session_id,
            )


    def test_insufficient_data_protection(self, url, method, path_str, details, session_id):
        self.log("Testing Insufficient Data Protection.", session_id)
        resp, request_body, request_headers = self.make_request(
            method, url, session_id=session_id
        )
        if resp:
            if re.search(r"username\s*[:=]\s*[\'\"]?(\w+)[\'\"]?", resp.text, re.IGNORECASE):
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
                    vulnerability_found=True,
                    session_id=session_id,
                )
            else:
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
                    vulnerability_found=False,
                    session_id=session_id,
                )
        else:
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
                vulnerability_found=False,
                session_id=session_id,
            )

    def test_unauthorized_password_change(self, url, method, path_str, details, session_id):
        self.log("Testing Unauthorized Password Change.", session_id)
        password_change_endpoints = [
            "/change-password",
            "/update-password",
            "/password/reset",
            "/password/change",
        ]
        if any(endpoint.lower() in path_str.lower() for endpoint in password_change_endpoints):
            self.log(f"Detected password change endpoint: {url}", session_id)
            payload = {"password": "NewPassword123!"}
            resp, request_body, request_headers = self.make_request(
                method, url, json_data=payload, session_id=session_id
            )
            if resp:
                if resp.status_code == 200 or resp.status_code == 204:
                    self.add_result(
                        endpoint=url,
                        method=method,
                        issue="Unauthorized Password Change",
                        result="Password change endpoint accessible without proper authentication or authorization.",
                        severity="High",
                        recommendation="Ensure that password change operations require proper authentication and authorization.",
                        req_method=method,
                        request_headers=request_headers,
                        request_body=json.dumps(payload),
                        response_body=resp.text,
                        resp=resp,
                        vulnerability_found=True,
                        session_id=session_id,
                    )
                elif resp.status_code in [401, 403]:
                    self.add_result(
                        endpoint=url,
                        method=method,
                        issue="Unauthorized Password Change",
                        result=f"Password change endpoint properly secured. Received status code {resp.status_code}.",
                        severity="None",
                        recommendation="Password change operations require proper authentication and authorization.",
                        req_method=method,
                        request_headers=request_headers,
                        request_body=json.dumps(payload),
                        response_body=resp.text,
                        resp=resp,
                        vulnerability_found=False,
                        session_id=session_id,
                    )
                else:
                    self.add_result(
                        endpoint=url,
                        method=method,
                        issue="Unauthorized Password Change",
                        result=f"Received unexpected status code {resp.status_code} when attempting unauthorized password change.",
                        severity="Medium",
                        recommendation="Review the authentication and authorization mechanisms for password change operations.",
                        req_method=method,
                        request_headers=request_headers,
                        request_body=json.dumps(payload),
                        response_body=resp.text,
                        resp=resp,
                        vulnerability_found=False,
                        session_id=session_id,
                    )
            else:
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Unauthorized Password Change",
                    result="No response received when attempting unauthorized password change.",
                    severity="Medium",
                    recommendation="Ensure password change endpoints are properly secured and operational.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=json.dumps(payload),
                    response_body="No response",
                    resp=None,
                    vulnerability_found=False,
                    session_id=session_id,
                )
        else:
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
                vulnerability_found=False,
                session_id=session_id,
            )

    def test_replay_attack_prevention(self, url, method, path_str, details, session_id):
        self.log("Testing Replay Attack Prevention.", session_id)
        if "Authorization" in self.headers:
            try:
                token = self.headers["Authorization"].split()[1]
                resp1, request_body1, request_headers1 = self.make_request(
                    method, url, session_id=session_id
                )
                resp2, request_body2, request_headers2 = self.make_request(
                    method, url, session_id=session_id
                )
                if resp1 and resp2:
                    if resp1.text == resp2.text and resp1.status_code == resp2.status_code:
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
                            vulnerability_found=True,
                            session_id=session_id,
                        )
                    else:
                        self.add_result(
                            endpoint=url,
                            method=method,
                            issue="Replay Attack Prevention",
                            result=f"No replay attack vulnerability detected. Received different responses or status codes ({resp1.status_code}, {resp2.status_code}).",
                            severity="None",
                            recommendation="Replay attack protections are functioning as expected.",
                            req_method=method,
                            request_headers=request_headers2,
                            request_body=request_body2,
                            response_body=resp2.text if resp2 else "No response",
                            resp=resp2,
                            vulnerability_found=False,
                            session_id=session_id,
                        )
                else:
                    self.add_result(
                        endpoint=url,
                        method=method,
                        issue="Replay Attack Prevention",
                        result="Failed to receive consistent responses for replay attack prevention test.",
                        severity="Medium",
                        recommendation="Ensure reliable response handling and implement replay attack protections.",
                        req_method=method,
                        request_headers={},
                        request_body="N/A",
                        response_body="Incomplete responses received.",
                        resp=None,
                        vulnerability_found=False,
                        session_id=session_id,
                    )
            except Exception as e:
                self.log(f"Error during Replay Attack Prevention test: {e}", session_id)
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Replay Attack Prevention",
                    result=f"Error during test execution: {e}",
                    severity="Medium",
                    recommendation="Implement nonce or timestamp mechanisms to prevent replay attacks.",
                    req_method=method,
                    request_headers={},
                    request_body="N/A",
                    response_body=str(e),
                    resp=None,
                    vulnerability_found=False,
                    session_id=session_id,
                )
        else:
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
                vulnerability_found=False,
                session_id=session_id,
            )

    def test_insufficient_logging_and_monitoring(self, url, method, path_str, details, session_id):
        self.log("Testing Insufficient Logging & Monitoring.", session_id)
        error_url = url + "/invalidendpoint"
        resp, request_body, request_headers = self.make_request(
            method, error_url, session_id=session_id
        )
        if resp and resp.status_code == 404:
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
                vulnerability_found=False,
                session_id=session_id,
            )
        else:
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
                vulnerability_found=False,
                session_id=session_id,
            )

    def test_secure_transmission(self, url, method, path_str, details, session_id):
        self.log("Testing Secure Transmission (HTTPS).", session_id)
        if not url.startswith("https://"):
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
                vulnerability_found=True,
                session_id=session_id,
            )
        else:
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
                vulnerability_found=False,
                session_id=session_id,
            )

    def test_xss(self, url, method, path_str, details, session_id):
        xss_payload = "<script>alert('XSS')</script>"
        injection_point = self.get_injection_point(url, path_str)
        if injection_point:
            vulnerable_url = injection_point.replace("{{injection}}", xss_payload)
            resp, request_body, request_headers = self.make_request(
                method, vulnerable_url, session_id=session_id
            )
            if resp and xss_payload in resp.text:
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
                    vulnerability_found=True,
                    session_id=session_id,
                )

    def test_insecure_direct_object_references(
        self, url, method, path_str, details, session_id
    ):
        self.log("Testing Insecure Direct Object References (IDOR).", session_id)
        if "{" in path_str and "}" in path_str:
            try:
                numeric_id = int("1")
                id_incremented = numeric_id + 1
                idor_url = re.sub(r"\{[^}]+\}", str(id_incremented), url)
                resp, request_body, request_headers = self.make_request(
                    method, idor_url, session_id=session_id
                )
                if resp and resp.status_code == 200:
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
                        vulnerability_found=True,
                        session_id=session_id,
                    )
                else:
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
                        vulnerability_found=False,
                        session_id=session_id,
                    )
            except ValueError:
                self.log("Non-numeric ID detected; IDOR test may not be applicable.", session_id)
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
                    vulnerability_found=False,
                    session_id=session_id,
                )
        else:
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
                vulnerability_found=False,
                session_id=session_id,
            )

    def test_graphql_and_websocket_security(self, url, method, path_str, details, session_id):
        self.log("Testing GraphQL and WebSocket Security.", session_id)
        if "/graphql" in url.lower():
            graphql_query = {"query": "{ __schema { types { name } } }"}
            resp, request_body, request_headers = self.make_request(
                method, url, json_data=graphql_query, session_id=session_id
            )
            if resp and "error" in resp.text.lower():
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
                    vulnerability_found=True,
                    session_id=session_id,
                )
            else:
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
                    vulnerability_found=False,
                    session_id=session_id,
                )
        if "/ws" in url.lower():
            self.log("WebSocket endpoints require specialized testing tools.", session_id)
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
                vulnerability_found=False,
                session_id=session_id,
            )

    def test_graphql(self, url, method, path_str, details, session_id):
        graphql_query = {"query": "{ __schema { types { name } } }"}
        try:
            self.log(f"Testing GraphQL endpoint: {url}", session_id)
            resp, request_body, request_headers = self.make_request(
                method, url, json_data=graphql_query, session_id=session_id
            )
            if resp and resp.status_code == 200 and "__schema" in resp.json():
                self.add_result(
                    endpoint=url,
                    method="POST",
                    issue="GraphQL Introspection",
                    result="GraphQL introspection query exposed schema information.",
                    severity="Medium",
                    recommendation="Disable introspection queries in production environments.",
                    req_method="POST",
                    request_headers=request_headers,
                    request_body=json.dumps(graphql_query),
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=True,
                    session_id=session_id,
                )
        except Exception as e:
            self.log(f"Error testing GraphQL endpoint {url}: {e}", session_id)

    def test_websocket(self, url, method, path_str, details, session_id):
        self.log(f"Testing WebSocket endpoint: {url}", session_id)
        try:
            import websocket
            ws = websocket.create_connection(url)
            ws.send("Test message")
            response = ws.recv()
            self.log(f"WebSocket response: {response}", session_id)
            ws.close()
        except Exception as e:
            self.log(f"Error testing WebSocket {url}: {e}", session_id)

    def test_file_upload_security(self, url, method, path_str, details, session_id):
        self.log("Testing File Upload Security.", session_id)
        request_headers = {}
        request_body = ""
        try:
            if method.upper() in ["POST", "PUT", "PATCH"]:
                files = {
                    "file": (
                        "test.exe",
                        b"Executable content",
                        "application/octet-stream",
                    )
                }
                resp, request_body, request_headers = self.make_request(
                    method, url, files=files, session_id=session_id
                )
                if resp and resp.status_code == 200:
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
                        vulnerability_found=True,
                        session_id=session_id,
                    )
                else:
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
                        vulnerability_found=False,
                        session_id=session_id,
                    )
            else:
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="File Upload Security",
                    result="File upload test not applicable for this HTTP method.",
                    severity="None",
                    recommendation="Ensure file upload protections are in place where applicable.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body="N/A",
                    response_body="N/A",
                    resp=None,
                    vulnerability_found=False,
                    session_id=session_id,
                )
        except Exception as e:
            self.log(f"Error during File Upload Security test: {e}", session_id)
            self.add_result(
                endpoint=url,
                method=method,
                issue="File Upload Security",
                result=f"Error during test execution: {e}",
                severity="Medium",
                recommendation="Implement file type and content validation on uploads.",
                req_method=method,
                request_headers=request_headers,
                request_body=request_body if request_body else "N/A",
                response_body=str(e),
                resp=None,
                vulnerability_found=False,
                session_id=session_id,
            )

    def test_caching_mechanisms(self, url, method, path_str, details, session_id):
        self.log("Testing Caching Mechanisms.", session_id)
        resp, request_body, request_headers = self.make_request(
            method, url, headers={"Cache-Control": "no-cache"}, session_id=session_id
        )
        if resp:
            cache_control = resp.headers.get("Cache-Control", "")
            if "no-store" not in cache_control and "no-cache" not in cache_control:
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
                    vulnerability_found=True,
                    session_id=session_id,
                )
            else:
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
                    vulnerability_found=False,
                    session_id=session_id,
                )
        else:
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
                vulnerability_found=False,
                session_id=session_id,
            )

    def test_information_disclosure(self, url, method, path_str, details, session_id):
        self.log("Testing Information Disclosure via Server Header.", session_id)
        request_headers = {}
        request_body = ""
        try:
            resp, request_body, request_headers = self.make_request(
                method, url, session_id=session_id
            )
            if resp:
                server_header = resp.headers.get("Server", "")
                # Always add the entire response body to the report for completeness
                if server_header:
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
                        response_body=resp.text,  # store entire body
                        resp=resp,
                        vulnerability_found=False,
                        session_id=session_id,
                    )
                else:
                    self.add_result(
                        endpoint=url,
                        method=method,
                        issue="Information Disclosure",
                        result="Server header not present.",
                        severity="Low",
                        recommendation="Ensure server headers do not reveal sensitive information.",
                        req_method=method,
                        request_headers=request_headers,
                        request_body=request_body,
                        response_body=resp.text,  # store entire body
                        resp=resp,
                        vulnerability_found=False,
                        session_id=session_id,
                    )
            else:
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Information Disclosure",
                    result="No response received during Information Disclosure test.",
                    severity="Low",
                    recommendation="Ensure server headers do not reveal sensitive information.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body="No response",
                    resp=None,
                    vulnerability_found=False,
                    session_id=session_id,
                )
        except Exception as e:
            self.log(f"Error during Information Disclosure test: {e}", session_id)
            self.add_result(
                endpoint=url,
                method=method,
                issue="Information Disclosure",
                result=f"Error during test execution: {e}",
                severity="Medium",
                recommendation="Ensure server headers do not reveal sensitive information.",
                req_method=method,
                request_headers=request_headers,
                request_body=request_body,
                response_body=str(e),
                resp=None,
                vulnerability_found=False,
                session_id=session_id,
            )

    def test_xxe_protection(self, url, method, path_str, details, session_id):
        self.log("Testing XML External Entity (XXE) Protection.", session_id)
        request_headers = {}
        request_body = ""
        try:
            if "xml" in (details.get("consumes") or []):
                xxe_payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>"""
                resp, request_body, request_headers = self.make_request(
                    method,
                    url,
                    data=xxe_payload,
                    headers={"Content-Type": "application/xml"},
                    session_id=session_id,
                )
                if resp and "root:x" in resp.text.lower():
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
                        vulnerability_found=True,
                        session_id=session_id,
                    )
                else:
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
                        vulnerability_found=False,
                        session_id=session_id,
                    )
            else:
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="XML External Entity (XXE) Protection",
                    result="XXE test not applicable for this endpoint.",
                    severity="None",
                    recommendation="Ensure XML external entity protections are in place where applicable.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body="N/A",
                    response_body="N/A",
                    resp=None,
                    vulnerability_found=False,
                    session_id=session_id,
                )
        except Exception as e:
            self.log(f"Error during XXE Protection test: {e}", session_id)
            self.add_result(
                endpoint=url,
                method=method,
                issue="XML External Entity (XXE) Protection",
                result=f"Error during test execution: {e}",
                severity="Medium",
                recommendation="Disable external entity processing and validate XML inputs.",
                req_method=method,
                request_headers=request_headers,
                request_body=request_body if request_body else "N/A",
                response_body=str(e),
                resp=None,
                vulnerability_found=False,
                session_id=session_id,
            )

    def test_content_security_policy(self, url, method, path_str, details, session_id):
        self.log("Testing Content Security Policy (CSP).", session_id)
        resp, request_body, request_headers = self.make_request(
            method, url, session_id=session_id
        )
        if resp:
            csp = resp.headers.get("Content-Security-Policy", "")
            if not csp:
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
                    vulnerability_found=True,
                    session_id=session_id,
                )
            else:
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
                    vulnerability_found=False,
                    session_id=session_id,
                )
        else:
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
                vulnerability_found=False,
                session_id=session_id,
            )

    def test_api_versioning_security(self, url, method, path_str, details, session_id):
        self.log("Testing API Versioning Security.", session_id)
        deprecated_versions = ["/v1/", "/v2/"]
        for version in deprecated_versions:
            deprecated_url = url.replace("/v3/", version)
            resp, request_body, request_headers = self.make_request(
                method, deprecated_url, session_id=session_id
            )
            if resp and resp.status_code == 200:
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
                    vulnerability_found=True,
                    session_id=session_id,
                )
            else:
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
                    vulnerability_found=False,
                    session_id=session_id,
                )

    def test_brute_force_attack_mitigation(self, url, method, path_str, details, session_id):
        self.log("Testing Brute-Force Attack Mitigation.", session_id)
        request_headers = {}
        request_body = ""
        try:
            if "/login" in url.lower() or "/auth" in url.lower():
                payload = {"username": "testuser", "password": "wrongpassword"}
                blocked = False
                for i in range(10):
                    resp, request_body, request_headers = self.make_request(
                        method, url, json_data=payload, session_id=session_id
                    )
                    if resp and resp.status_code == 429:
                        blocked = True
                        self.log(f"Brute-force attack mitigation triggered on attempt {i+1}.", session_id)
                        break
                if blocked:
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
                        vulnerability_found=False,
                        session_id=session_id,
                    )
                else:
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
                        vulnerability_found=True,
                        session_id=session_id,
                    )
            else:
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
                    vulnerability_found=False,
                    session_id=session_id,
                )
        except Exception as e:
            self.log(f"Error during Brute-Force Attack Mitigation test: {e}", session_id)
            self.add_result(
                endpoint=url,
                method=method,
                issue="Brute-Force Attack Mitigation",
                result=f"Error during test execution: {e}",
                severity="Medium",
                recommendation="Implement rate limiting and account lockout mechanisms to prevent brute-force attacks.",
                req_method=method,
                request_headers=request_headers,
                request_body=request_body if request_body else "N/A",
                response_body=str(e),
                resp=None,
                vulnerability_found=False,
                session_id=session_id,
            )

    def generate_report(self):
        rid = self.get_new_session_id()
        self.log("Generating the vulnerability report.", rid)
        if self.output_format == "json":
            with open(f"{self.output_file}.json", "w") as f:
                json.dump(self.results, f, indent=4)
            self.log(f"Report saved as {self.output_file}.json", rid)
        elif self.output_format == "html":
            with open(f"{self.output_file}.html", "w") as f:
                f.write("<html><body><h1>API Vulnerability Report</h1><table border='1'>")
                f.write(
                    "<tr><th>Endpoint</th><th>Method</th><th>Issue</th>"
                    "<th>Result</th><th>Severity</th><th>Recommendation</th>"
                    "<th>HTTP Method</th><th>Request Headers Sent</th><th>Request Body Sent</th>"
                    "<th>Response Body Received</th><th>Vulnerability Found</th><th>OpenAI Feedback</th></tr>"
                )
                for res in self.results:
                    request_body = res["request_body_sent"]
                    if not isinstance(request_body, str):
                        request_body = "N/A"
                    response_body = res["response_body_received"]
                    if not isinstance(response_body, str):
                        response_body = "N/A"
                    # Escape the response body so that HTML doesn't break the table
                    escaped_response_body = html.escape(response_body)

                    f.write(
                        f"<tr><td>{res['endpoint']}</td><td>{res['method']}</td>"
                        f"<td>{res['issue']}</td><td>{res['result']}</td>"
                        f"<td>{res['severity']}</td><td>{res['recommendation']}</td>"
                        f"<td>{res['http_method']}</td>"
                        f"<td><pre>{html.escape(res['request_headers_sent'])}</pre></td>"
                        f"<td><pre>{html.escape(request_body)}</pre></td>"
                        f"<td><pre>{escaped_response_body}</pre></td>"
                        f"<td>{res['vulnerability_found']}</td>"
                        f"<td>{html.escape(res['openai_feedback'])}</td></tr>"
                    )
                f.write("</table>")
                if not self.offai:
                    psid = self.get_new_session_id()
                    self.log(
                        "Performing post-scan analysis with OpenAI to suggest additional test cases.",
                        psid,
                    )
                    report_summary = (
                        f"Total Vulnerabilities Found: "
                        f"{sum(1 for r in self.results if r['vulnerability_found'] == 'Yes')}\n"
                        f"Vulnerabilities by Severity:\n"
                        f"High: {sum(1 for r in self.results if r['severity'] == 'High')}\n"
                        f"Medium: {sum(1 for r in self.results if r['severity'] == 'Medium')}\n"
                        f"Low: {sum(1 for r in self.results if r['severity'] == 'Low')}\n"
                    )
                    additional_analysis = self.send_to_openai(
                        report_summary, purpose="Post-Scan Comprehensive Analysis", sid=psid
                    )
                    if additional_analysis:
                        f.write(
                            f"<h2>Post-Scan OpenAI Analysis</h2><pre>{html.escape(additional_analysis)}</pre>"
                        )
                        self.log(
                            f"Additional analysis appended to {self.output_file}.html",
                            psid,
                        )
            self.log(f"Report saved as {self.output_file}.html", rid)
        else:
            self.log("Unsupported report format specified.", rid)

    def test_user_password_enumeration_unique(
        self, url, method, path_str, details, session_id
    ):
        self.log("Testing User and Password Enumeration.", session_id)
        if "/login" in url.lower():
            payload_valid = {"username": "validuser", "password": "validpassword"}
            payload_invalid = {"username": "validuser", "password": "invalidpassword"}
            resp_valid, request_body_valid, request_headers_valid = self.make_request(
                method, url, json_data=payload_valid, session_id=session_id
            )
            resp_invalid, request_body_invalid, request_headers_invalid = self.make_request(
                method, url, json_data=payload_invalid, session_id=session_id
            )
            if resp_valid and resp_invalid:
                if (
                    resp_valid.status_code == resp_invalid.status_code
                    and resp_valid.text == resp_invalid.text
                ):
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
                        vulnerability_found=True,
                        session_id=session_id,
                    )
                else:
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
                        vulnerability_found=False,
                        session_id=session_id,
                    )
            else:
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
                    vulnerability_found=False,
                    session_id=session_id,
                )
        else:
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
                vulnerability_found=False,
                session_id=session_id,
            )

    def test_server_side_template_injection(
        self, url, method, path_str, details, session_id
    ):
        self.log("Testing Server-Side Template Injection (SSTI).", session_id)
        ssti_payload = "{{7*7}}"
        injection_point = self.get_injection_point(url, path_str)
        if injection_point:
            vulnerable_url = injection_point.replace("{{injection}}", ssti_payload)
            resp, request_body, request_headers = self.make_request(
                method, vulnerable_url, session_id=session_id
            )
            if resp and "49" in resp.text:
                self.add_result(
                    endpoint=vulnerable_url,
                    method=method,
                    issue="Server-Side Template Injection (SSTI)",
                    result="Endpoint reflected SSTI payload result in the response.",
                    severity="High",
                    recommendation="Sanitize and encode all user inputs to prevent SSTI attacks.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=True,
                    session_id=session_id,
                )
            else:
                self.add_result(
                    endpoint=vulnerable_url,
                    method=method,
                    issue="Server-Side Template Injection (SSTI)",
                    result=f"No SSTI vulnerability detected with payload: {ssti_payload}. Received status code {resp.status_code if resp else 'No Response'}.",
                    severity="None",
                    recommendation="Input sanitization mechanisms are functioning as expected.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=request_body,
                    response_body=resp.text if resp else "No response",
                    resp=resp,
                    vulnerability_found=False,
                    session_id=session_id,
                )
        else:
            self.add_result(
                endpoint=url,
                method=method,
                issue="Server-Side Template Injection (SSTI)",
                result="SSTI test not applicable for this endpoint.",
                severity="None",
                recommendation="Ensure input sanitization is in place where applicable.",
                req_method=method,
                request_headers={},
                request_body="N/A",
                response_body="N/A",
                resp=None,
                vulnerability_found=False,
                session_id=session_id,
            )

    def test_directory_traversal(self, url, method, path_str, details, session_id):
        self.log("Testing Directory Traversal.", session_id)
        request_headers = {}
        request_body = ""
        try:
            traversal_payload = "../../../../etc/passwd"
            if "{" in path_str and "}" in path_str:
                traversal_url = re.sub(r"\{[^}]+\}", traversal_payload, url)
                resp, request_body, request_headers = self.make_request(
                    method, traversal_url, session_id=session_id
                )
                if resp and "root:" in resp.text:
                    self.add_result(
                        endpoint=traversal_url,
                        method=method,
                        issue="Directory Traversal",
                        result="Endpoint accessible system files through directory traversal.",
                        severity="High",
                        recommendation="Implement proper path validation and restrict file access.",
                        req_method=method,
                        request_headers=request_headers,
                        request_body=request_body,
                        response_body=resp.text,
                        resp=resp,
                        vulnerability_found=True,
                        session_id=session_id,
                    )
                else:
                    self.add_result(
                        endpoint=traversal_url,
                        method=method,
                        issue="Directory Traversal",
                        result=f"No directory traversal vulnerability detected with payload: {traversal_payload}. Received status code {resp.status_code if resp else 'No Response'}.",
                        severity="None",
                        recommendation="Ensure proper path validation and restrict file access.",
                        req_method=method,
                        request_headers=request_headers,
                        request_body=request_body,
                        response_body=resp.text if resp else "No response",
                        resp=resp,
                        vulnerability_found=False,
                        session_id=session_id,
                    )
            else:
                self.add_result(
                    endpoint=url,
                    method=method,
                    issue="Directory Traversal",
                    result="Directory Traversal test not applicable for this endpoint.",
                    severity="None",
                    recommendation="Ensure proper path validation and restrict file access.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body="N/A",
                    response_body="N/A",
                    resp=None,
                    vulnerability_found=False,
                    session_id=session_id,
                )
        except Exception as e:
            self.log(f"Error during Directory Traversal test: {e}", session_id)
            self.add_result(
                endpoint=url,
                method=method,
                issue="Directory Traversal",
                result=f"Error during test execution: {e}",
                severity="Medium",
                recommendation="Ensure proper path validation and restrict file access.",
                req_method=method,
                request_headers=request_headers,
                request_body=request_body if request_body else "N/A",
                response_body=str(e),
                resp=None,
                vulnerability_found=False,
                session_id=session_id,
            )

    def test_deserialization_vulnerabilities(self, url, method, path_str, details, session_id):
        self.log("Testing Deserialization Vulnerabilities.", session_id)
        deserialization_payload = '{"__class__": "malicious.Class", "data": "test"}'
        if "{" in path_str and "}" in path_str:
            vulnerable_url = re.sub(r"\{[^}]+\}", "1", url)
            headers = {"Content-Type": "application/json"}
            resp, request_body, request_headers = self.make_request(
                method,
                vulnerable_url,
                data=deserialization_payload,
                headers=headers,
                session_id=session_id,
            )
            if resp and "error" in resp.text.lower():
                self.add_result(
                    endpoint=vulnerable_url,
                    method=method,
                    issue="Deserialization Vulnerabilities",
                    result="Endpoint responded with error to crafted deserialization payload.",
                    severity="High",
                    recommendation="Implement strict serialization/deserialization controls and validate input data.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=deserialization_payload,
                    response_body=resp.text,
                    resp=resp,
                    vulnerability_found=True,
                    session_id=session_id,
                )
            else:
                self.add_result(
                    endpoint=vulnerable_url,
                    method=method,
                    issue="Deserialization Vulnerabilities",
                    result=f"No deserialization vulnerability detected with payload: {deserialization_payload}. Received status code {resp.status_code if resp else 'No Response'}.",
                    severity="None",
                    recommendation="Serialization/deserialization controls are functioning as expected.",
                    req_method=method,
                    request_headers=request_headers,
                    request_body=deserialization_payload,
                    response_body=resp.text if resp else "No response",
                    resp=resp,
                    vulnerability_found=False,
                    session_id=session_id,
                )
        else:
            self.add_result(
                endpoint=url,
                method=method,
                issue="Deserialization Vulnerabilities",
                result="Deserialization test not applicable for this endpoint.",
                severity="None",
                recommendation="Ensure serialization/deserialization controls are in place where applicable.",
                req_method=method,
                request_headers={},
                request_body="N/A",
                response_body="N/A",
                resp=None,
                vulnerability_found=False,
                session_id=session_id,
            )

    def test_regex_dos(self, url, method, path_str, details, session_id):
        self.log("Testing Regex Denial of Service (RegexDOS).", session_id)
        malicious_input = "A" * 10000
        injection_point = self.get_injection_point(url, path_str)
        if injection_point:
            vulnerable_url = injection_point.replace("{{injection}}", malicious_input)
            resp, request_body, request_headers = self.make_request(
                method, vulnerable_url, session_id=session_id
            )
            if resp and resp.elapsed.total_seconds() > 5:
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
                    vulnerability_found=True,
                    session_id=session_id,
                )
            else:
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
                    vulnerability_found=False,
                    session_id=session_id,
                )
        else:
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
                vulnerability_found=False,
                session_id=session_id,
            )

    def test_fuzzing(self, url, method, path_str, details, session_id):
        self.log("Performing Fuzz Testing.", session_id)
        fuzz_payloads = [
            "!@#$%^&*()_+",
            "' OR 1=1 --",
            "🦄",
            "A" * 1000,
            "<script>alert(1)</script>",
            '{"key": "value"}',
            "DROP TABLE users;",
        ]
        for payload in fuzz_payloads:
            sub_id = self.get_new_session_id()
            self.log(f"Testing fuzz payload: {payload} on {url}", sub_id)
            try:
                if "{" in path_str and "}" in path_str:
                    fuzzed_url = re.sub(r"\{[^}]+\}", payload, url)
                    self.log(f"Normalized HTTP method: {method}", sub_id)
                    resp, request_body, request_headers = self.make_request(
                        method, fuzzed_url, session_id=sub_id
                    )
                    if resp and resp.status_code != 400:
                        self.add_result(
                            endpoint=fuzzed_url,
                            method=method,
                            issue="Potential Vulnerability via Fuzz Testing",
                            result=f"Endpoint responded with {resp.status_code} for payload: {payload}",
                            severity="Medium",
                            recommendation="Harden input validation to reject invalid or malicious inputs.",
                            req_method=method,
                            request_headers=request_headers,
                            request_body=request_body,
                            response_body=resp.text,
                            resp=resp,
                            vulnerability_found=True,
                            session_id=sub_id,
                        )
            except Exception as e:
                self.log(f"Error during fuzz testing for payload {payload}: {e}", sub_id)
                continue

    def perform_dynamic_tests(self):
        sid = self.get_new_session_id()
        self.log("Enhanced Dynamic Testing based on placeholders and sensitive data.", sid)
        if not self.endpoints_with_placeholders:
            self.log("No endpoints with placeholders found for dynamic testing.", sid)
            return
        dynamic_tests = []
        for endpoint in self.endpoints_with_placeholders:
            path = endpoint["path"]
            method = endpoint["method"]
            url_template = endpoint["url_template"]
            placeholders = re.findall(r"\{([^}]+)\}", path)
            for placeholder in placeholders:
                replacement_values = (
                    list(self.discovered_usernames)
                    + list(self.discovered_passwords)
                    + ["admin", "test", "guest", "null"]
                )
                for value in replacement_values:
                    dynamic_url = url_template.replace(f"{{{placeholder}}}", value)
                    dynamic_tests.append((dynamic_url, method, path, {"dynamic": True}))

        self.log(
            f"Generated {len(dynamic_tests)} dynamic test cases with multiple parameter scenarios.",
            sid,
        )
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self.test_endpoint, *test) for test in dynamic_tests]
            for future in futures:
                try:
                    future.result()
                except Exception as e:
                    self.log(f"Error in dynamic testing: {e}", sid)

    def get_injection_point(self, url, path_str):
        if "{" in path_str and "}" in path_str:
            return re.sub(r"\{[^}]+\}", "{{injection}}", url)
        return None

    def extract_usernames(self, response_text, session_id):
        self.log("Extracting usernames from response.", session_id)
        usernames = re.findall(r"username\s*[:=]\s*[\'\"]?(\w+)[\'\"]?", response_text, re.IGNORECASE)
        self.log(f"Discovered usernames: {usernames}", session_id)
        return usernames

    def extract_passwords(self, response_text, session_id):
        self.log("Extracting passwords from response.", session_id)
        passwords = re.findall(r"password\s*[:=]\s*[\'\"]?(\w+)[\'\"]?", response_text, re.IGNORECASE)
        self.log(f"Discovered passwords: {passwords}", session_id)
        return passwords

    def make_request(self, method, url, params=None, json_data=None, data=None, files=None, headers=None, session_id=None):
        """Send an HTTP request and return the response, request body, and request headers."""
        if session_id is None:
            session_id = self.get_new_session_id()
        self.log(f"Preparing {method} request to {url}.", session_id)

        try:
            # Combine headers with global headers
            merged_headers = self.headers.copy()
            if headers:
                merged_headers.update(headers)

            # Log the request details
            self.log(f"Headers: {merged_headers}", session_id)
            request_body = json.dumps(json_data, indent=2) if json_data else data
            self.log(f"Request body: {request_body}", session_id)

            # Send the request
            response = requests.request(
                method=method.upper(),
                url=url,
                headers=merged_headers,
                params=params,
                json=json_data,
                data=data,
                files=files,
                timeout=10,
                proxies=self.proxy
            )

            # Log response details
            self.log(f"Received response with status code {response.status_code}.", session_id)
            self.log(f"Response body: {response.text}", session_id)

            return response, request_body, merged_headers
        except Exception as e:
            self.log(f"Error during request: {e}", session_id)
            return None, None, None


    def send_to_openai(self, content, purpose="Analysis", sid=None):
        if sid is None:
            sid = self.get_new_session_id()
        self.log(f"Preparing to send content to OpenAI for {purpose}.", sid)
        if not content:
            self.log("No content available to send to OpenAI.", sid)
            return "No content available to send to OpenAI."
        prompt = (
            f"Analyze the following content for potential security vulnerabilities based on the OWASP API Security:\n\n"
            f"{content}\n\n"
            f"Provide a concise summary of potential risks, observations, and suggest any additional tests that should be performed to improve test coverage."
        )
        self.log(f"Sending to OpenAI prompt: {prompt}", sid)
        payload = {
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": "You are a cybersecurity expert."},
                {"role": "user", "content": prompt},
            ],
        }
        max_retries = 5
        retries = 0
        while retries < max_retries:
            try:
                response_openai = requests.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {openai.api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )
                if response_openai.status_code == 200:
                    feedback = response_openai.json()["choices"][0]["message"]["content"]
                    self.log(f"OpenAI GPT-4 response: {feedback}", sid)
                    return feedback
                elif response_openai.status_code == 429:
                    retries += 1
                    retry_after = int(response_openai.headers.get("Retry-After", "1"))
                    wait_time = (2 ** retries) + random.uniform(0, 1)
                    self.log(
                        f"OpenAI API rate limit exceeded. Retrying in {wait_time:.2f} seconds...",
                        sid,
                    )
                    time.sleep(wait_time)
                else:
                    self.log(
                        f"OpenAI API error: {response_openai.status_code} - {response_openai.text}",
                        sid,
                    )
                    return f"OpenAI API error: {response_openai.status_code}"
            except requests.exceptions.RequestException as e:
                self.log(f"Failed to communicate with OpenAI: {e}", sid)
                return f"Error communicating with OpenAI: {e}"
        self.log("Max retries exceeded for OpenAI API.", sid)
        return "Max retries exceeded for OpenAI API."

    def add_result(
        self,
        endpoint,
        method,
        issue,
        result,
        severity,
        recommendation,
        req_method,
        request_headers,
        request_body,
        response_body,
        resp=None,
        vulnerability_found=False,
        session_id=None,
    ):
        if not self.offai and vulnerability_found:
            openai_feedback = (
                self.send_to_openai(resp.text, purpose="Post-Scan Analysis", sid=session_id)
                if resp
                else "No feedback from OpenAI."
            )
        elif not self.offai:
            openai_feedback = "No vulnerability detected."
        else:
            openai_feedback = "OpenAI analysis disabled."

        if response_body is None:
            response_body = "N/A"
        elif not isinstance(response_body, str):
            response_body = str(response_body)

        headers_formatted = (
            "\n".join([f"{key}: {value}" for key, value in request_headers.items()])
            if request_headers
            else "N/A"
        )

        self.results.append(
            {
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
                "openai_feedback": openai_feedback,
            }
        )

def parse_args():
    parser = argparse.ArgumentParser(
        description="API Vulnerability Scanner with Enhanced Test Coverage and OpenAI Integration"
    )
    parser.add_argument("-i", "--input", required=True, help="Path to OpenAPI spec file")
    parser.add_argument("-u", "--url", required=True, help="Base URL of the API")
    parser.add_argument(
        "-o", "--output", default="report", help="Output report file name (without extension)"
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["json", "html"],
        default="json",
        help="Output report format (default: json)",
    )
    parser.add_argument(
        "-t",
        "--token",
        help="Bearer token for API authentication",
        required=False,
    )
    parser.add_argument(
        "-p", "--proxy", help="Proxy server URL", required=False
    )
    parser.add_argument(
        "--random",
        action="store_true",
        help="Enable random delays between requests to avoid rate limiting.",
    )
    parser.add_argument(
        "--offai",
        action="store_true",
        help="Disable sending data to OpenAI for analysis.",
    )
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
        randomize=args.random,
        offai=args.offai,
    )
    scanner.load_spec()
    scanner.scan_endpoints()
    scanner.generate_report()

if __name__ == "__main__":
    main()
