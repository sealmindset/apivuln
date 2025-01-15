# OWASP API Security Top 10 (2023) Scanner

A **Python 3** command-line tool that scans REST APIs (based on a **Swagger/OpenAPI** file) for **OWASP API Security Top 10 (2023)** issues, **Mass Assignment** vulnerabilities, and includes **debug mode** to view your CLI arguments without performing a scan.

---

## Features

1. **API Spec Parsing**  
   - Loads OpenAPI/Swagger (`.json` or `.yml/.yaml`) to find endpoints, HTTP methods, parameters, and requestBody schemas.

2. **OWASP API Security Top 10 (2023)**  
   - **Broken Object Level Authorization (BOLA)**: Checks for ID manipulation in path or query.  
   - **Broken Authentication**: Tests endpoints with no/invalid token.  
   - **Broken Object Property Level Authorization**: Attempts to set unauthorized properties in the request body.  
   - **Unrestricted Resource Consumption**: Sends multiple concurrent requests and tries large payloads.  
   - **Broken Function Level Authorization**: Tries to access admin endpoints with normal token.  
   - **Server-Side Request Forgery (SSRF)**: Injects `http://127.0.0.1:80` in likely parameters.  
   - **Security Misconfiguration**: Checks server banners, `X-Powered-By`.  
   - **Lack of Protection from Automated Threats**: Sends multiple requests to see if blocked.  
   - **Improper Inventory Management**: Flags old/test endpoints (`/v1`, `/old`, `/debug`, etc.).  
   - **Unsafe Consumption of APIs**: Detects references to external domains in responses.

3. **Mass Assignment**  
   - Sends extra fields (`"is_admin"`, `"role"`) in JSON to see if the server accepts them.

4. **SQL Injection** (Extended)  
   - Injects payloads in **query parameters**, **JSON body**, and **path parameters** (e.g., `{id}` replaced with `"' OR 1=1 --"`).

5. **JWT Bypass**  
   - Attempts forging JWT tokens with **weak keys** (e.g., `"secret"`, `"123456"`) to see if accepted.

---

## Requirements

- **Python 3.7+** recommended
- Third-party libraries (in `requirements.txt`):
  - **requests**
  - **PyYAML**
  - **PyJWT**

## Install with:
```bash
pip install -r requirements.txt
```

## Usage
1.	Normal Scan
 
```
python3 apivuln.py \
  --input openapi.json \
  --url http://localhost:5001 \
  --token <YOUR_JWT_TOKEN> \
  --proxy http://127.0.0.1:8080 \
  --format html \
  --output report
```
	•	Required (in normal mode):
	•	--input/-i: Path to your .json or .yml/.yaml API spec.
	•	--url/-u: Base URL of the API.
	•	Optional:
	•	--token/-t: Bearer token for authenticated endpoints.
	•	--proxy/-p: Proxy URL (e.g., http://127.0.0.1:8080).
	•	--format/-f: Output format (json, csv, or html).
	•	--output/-o: Output file name without extension (default: report).

	2.	Debug Mode (No Scan)
```
python3 apivuln.py --debug
```
or
```
python3 apivuln.py --debug -i openapi.json -u http://localhost:5001
```
	•	Prints a debug message showing your arguments, then exits without scanning.
	•	No --input / --url required in --debug mode.

	3.	Example
```
python3 apivuln.py \
  --input openapi.json \
  --url http://localhost:5001 \
  --format json \
  --output scan_results \
  --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```
## How It Works
	1.	Loads the OpenAPI File
	•	Identifies endpoints (paths), HTTP methods, parameters (query, path), and requestBody schemas.
	2.	Runs Each Vulnerability Check
	•	Submits test requests to endpoints, either injecting malicious payloads (SQLi, SSRF) or manipulating IDs (BOLA).
	3.	Analyzes Responses
	•	Looks for HTTP status codes (200, 500), error strings (e.g., “sql error”), or acceptance of unauthorized data (mass assignment, etc.).
	4.	Generates a Report
	•	Saves findings in the specified format (.json, .csv, or .html).

## Important Notes
	•	False Positives/Negatives: Automated scanning can’t replace thorough manual review.
	•	Legal: Only scan APIs you have explicit permission to test.
	•	Customization: For multi-step flows (login as user A, change user B’s password), you may need to enhance the script with more business-logic–specific checks.
	•	Debug: If you just want to see how the script would parse your arguments, use --debug (no scanning).

## Contributing
	1.	Fork this repository.
	2.	Create a branch for your feature/fix.
	3.	Commit changes, then open a pull request.

## License

This project is licensed under the MIT License.

Use at your own risk, and always comply with applicable laws and ethical guidelines.

