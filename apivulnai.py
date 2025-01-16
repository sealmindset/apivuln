#!/usr/bin/env python3
"""
API Vulnerability Scanner - OWASP API Security Top 10 (2023)
Integrated with OpenAI's new interface in openai>=1.0.0

Key Revisions:
- Uses openai.chat.completions.create(...) for calls to GPT models.
- Accesses response via completion["choices"][0]["message"]["content"].
- Removes references to .completions[0].
"""

import argparse
import json
import yaml
import requests
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
        self.spec_file = spec_file
        self.base_url = base_url
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.token = token
        self.headers = {"Authorization": f"Bearer {token}"} if token else {}
        self.output_format = output_format
        self.output_file = output_file

        # OpenAI configuration
        self.openai_api_key = openai_api_key
        self.openai_analysis = openai_analysis
        if openai_api_key:
            openai.api_key = openai_api_key

        # Will store any discovered vulnerabilities (including AI analysis)
        self.results = []

    def load_spec(self):
        """Load the OpenAPI/Swagger specification from file."""
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
        self.headers.pop("Authorization", None)
        try:
            resp = self.make_request(method, url)
            if resp and resp.status_code == 200:
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
            "endpoint": endpoint,
            "method": method,
            "issue": issue,
            "result": result,
            "severity": severity,
            "recommendation": recommendation,
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


if __name__ == "__main__":
    main()
