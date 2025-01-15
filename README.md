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

6. **Debug Mode**  
   - A `--debug` argument that prints the assembled command-line arguments and **exits** without scanning.  
   - **No** need to specify `--input` or `--url` if only using `--debug`.

---

## Requirements

- **Python 3.7+** recommended
- Third-party libraries (in `requirements.txt`):
  - **requests**
  - **PyYAML**
  - **PyJWT**

Install with:
```bash
pip install -r requirements.txt
