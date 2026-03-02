"""
AI chatbot engine with rich local cybersecurity knowledge base + optional OpenAI GPT-4o-mini.
Handles conversation management, context building, and intelligent response generation.
"""
import re
import logging
from django.conf import settings

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are SafeWeb AI Assistant, an expert cybersecurity advisor. Your role is to:

1. Answer questions about web security, vulnerabilities, and best practices
2. Explain scan results and vulnerability findings
3. Provide remediation guidance for security issues
4. Educate users about OWASP Top 10 and common attack vectors
5. Help users understand security concepts in plain language

Guidelines:
- Be concise and actionable
- Provide code examples when relevant
- Reference OWASP, CWE, and CVE identifiers where applicable
- If asked about something outside cybersecurity, politely redirect to security topics
- Never provide instructions for conducting actual attacks
- Suggest SafeWeb AI scanning features when relevant

You have knowledge about:
- SQL Injection, XSS, CSRF, SSRF
- Authentication and session management
- Security headers and HTTPS
- Malware analysis and phishing detection
- API security and access control
- Network security fundamentals
"""

MAX_CONTEXT_MESSAGES = 10

# ── Rich knowledge base ──────────────────────────────────────────────
# Each entry: (synonym_keywords, title, response_text)
KNOWLEDGE_BASE = [
    # --- Injection ---
    (
        ['xss', 'cross-site scripting', 'script injection', 'reflected xss', 'stored xss', 'dom xss'],
        'Cross-Site Scripting (XSS)',
        (
            '**Cross-Site Scripting (XSS)** is a vulnerability where attackers inject malicious scripts '
            'into web pages viewed by other users. (OWASP A03:2021 — Injection)\n\n'
            '**Types:**\n'
            '- **Reflected XSS** — payload is part of the HTTP request and reflected in the response\n'
            '- **Stored XSS** — payload is persisted in the database and served to all users\n'
            '- **DOM-based XSS** — payload is executed entirely in the browser via JavaScript\n\n'
            '**Prevention:**\n'
            '- Encode output based on context (HTML, JavaScript, URL, CSS)\n'
            '- Use Content Security Policy (CSP) headers\n'
            '- Sanitize input with libraries like DOMPurify\n'
            '- Enable `HttpOnly` and `Secure` flags on session cookies\n'
            '- Use frameworks with auto-escaping (React, Angular, Django templates)\n\n'
            '**CWE:** CWE-79 | **Related:** CWE-80, CWE-116\n\n'
            '💡 Run a SafeWeb AI scan to check your site for XSS vulnerabilities!'
        ),
    ),
    (
        ['sql injection', 'sqli', 'sql attack', 'database injection', 'blind sql'],
        'SQL Injection',
        (
            '**SQL Injection** occurs when untrusted data is sent to a database interpreter as part '
            'of a query, allowing attackers to read, modify, or delete data. (OWASP A03:2021)\n\n'
            '**Types:**\n'
            '- **Classic SQLi** — direct data extraction via UNION or error-based techniques\n'
            '- **Blind SQLi** — boolean-based or time-based inference when output is hidden\n'
            '- **Out-of-Band SQLi** — uses DNS or HTTP requests to exfiltrate data\n\n'
            '**Prevention:**\n'
            '- Use **parameterized queries** / prepared statements\n'
            '- Use ORM frameworks (Django ORM, SQLAlchemy, Prisma)\n'
            '- Validate and whitelist all input\n'
            '- Apply **least privilege** to database accounts\n'
            '- Use Web Application Firewalls (WAFs) as defense-in-depth\n\n'
            '**CWE:** CWE-89 | **CVSS typical:** 8.6–9.8\n\n'
            '💡 Would you like to scan a website for SQL injection vulnerabilities?'
        ),
    ),
    (
        ['csrf', 'cross-site request forgery', 'xsrf', 'session riding', 'one-click attack'],
        'Cross-Site Request Forgery (CSRF)',
        (
            '**Cross-Site Request Forgery (CSRF)** tricks authenticated users into performing '
            'unintended state-changing actions. (OWASP A01:2021 — Broken Access Control)\n\n'
            '**How it works:** An attacker crafts a link or form that, when visited by a logged-in '
            'user, silently submits a request to the target site using the victim\'s session.\n\n'
            '**Prevention:**\n'
            '- Include **CSRF tokens** in all state-changing forms\n'
            '- Use `SameSite=Strict` or `SameSite=Lax` cookie attribute\n'
            '- Verify the `Origin` / `Referer` header\n'
            '- Require re-authentication for sensitive actions (e.g., password change)\n'
            '- Use frameworks with built-in CSRF protection (Django, Rails, Laravel)\n\n'
            '**CWE:** CWE-352 | **CWE Related:** CWE-346'
        ),
    ),
    (
        ['ssrf', 'server-side request forgery', 'internal request'],
        'Server-Side Request Forgery (SSRF)',
        (
            '**Server-Side Request Forgery (SSRF)** allows an attacker to make the server send '
            'requests to internal resources or arbitrary external systems. (OWASP A10:2021)\n\n'
            '**Impact:**\n'
            '- Access internal services (metadata APIs, databases, admin panels)\n'
            '- Port scanning of internal networks\n'
            '- Read local files via `file://` protocol\n\n'
            '**Prevention:**\n'
            '- Validate and whitelist allowed URLs and IP ranges\n'
            '- Block requests to private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x)\n'
            '- Use a dedicated HTTP client that doesn\'t follow redirects\n'
            '- Run the application in a restricted network segment\n\n'
            '**CWE:** CWE-918'
        ),
    ),
    (
        ['command injection', 'os injection', 'shell injection', 'rce', 'remote code execution'],
        'Command Injection / RCE',
        (
            '**Command Injection** occurs when an application passes untrusted data to a system '
            'shell command, allowing attackers to execute arbitrary OS commands. (OWASP A03:2021)\n\n'
            '**Prevention:**\n'
            '- **Never** pass user input directly to shell commands\n'
            '- Use language-specific APIs (e.g., `subprocess.run(["cmd", arg])` with list args)\n'
            '- Whitelist allowed characters and validate input strictly\n'
            '- Run processes with minimum necessary privileges\n'
            '- Use containerization to limit blast radius\n\n'
            '**CWE:** CWE-78 (OS Command Injection), CWE-94 (Code Injection)'
        ),
    ),
    # --- Authentication & Session ---
    (
        ['authentication', 'login security', 'auth', 'credential', 'brute force', 'password attack',
         'credential stuffing', 'account takeover'],
        'Authentication Security',
        (
            '**Authentication Failures** represent one of the most critical risks. (OWASP A07:2021)\n\n'
            '**Common issues:**\n'
            '- Weak password policies\n'
            '- No brute force / rate-limiting protection\n'
            '- Credential stuffing with leaked databases\n'
            '- Missing multi-factor authentication (MFA)\n'
            '- Insecure "Remember Me" tokens\n\n'
            '**Best practices:**\n'
            '- Enforce **strong passwords** (min 8 chars, uppercase, lowercase, number, special)\n'
            '- Implement **account lockout** after failed attempts\n'
            '- Use **bcrypt / Argon2** for password hashing\n'
            '- Enable **2FA/MFA** (TOTP, WebAuthn, SMS as fallback)\n'
            '- Implement **JWT** with short access token lifetimes (15–60 min)\n'
            '- Use HttpOnly, Secure, SameSite cookies for session tokens\n\n'
            '**CWE:** CWE-287, CWE-307, CWE-798\n\n'
            '💡 You can enable 2FA in your SafeWeb AI profile settings!'
        ),
    ),
    (
        ['session', 'session management', 'cookie security', 'session fixation', 'session hijacking'],
        'Session Management',
        (
            '**Session Management** vulnerabilities let attackers hijack user sessions. (OWASP A07:2021)\n\n'
            '**Common attacks:**\n'
            '- **Session hijacking** — stealing session IDs via XSS or network sniffing\n'
            '- **Session fixation** — forcing a known session ID onto a user\n'
            '- **Insufficient session expiration** — sessions that never time out\n\n'
            '**Best practices:**\n'
            '- Regenerate session IDs after login\n'
            '- Set appropriate session timeouts (idle + absolute)\n'
            '- Use `HttpOnly`, `Secure`, `SameSite=Strict` cookie attributes\n'
            '- Invalidate sessions on logout and password change\n'
            '- Store session tokens securely (never in URL params)\n\n'
            '**CWE:** CWE-384 (Session Fixation), CWE-613 (Insufficient Expiration)'
        ),
    ),
    (
        ['password', 'password security', 'password hash', 'hashing', 'bcrypt', 'argon2',
         'password strength', 'passphrase', 'password policy'],
        'Password Security',
        (
            '**Password Security** is the foundation of user authentication.\n\n'
            '**Best practices for password storage:**\n'
            '- Use **bcrypt**, **Argon2**, or **scrypt** (never MD5 or SHA-1 alone)\n'
            '- Use a unique **salt** per password (most modern hashers do this automatically)\n'
            '- Set a high work factor / iteration count\n\n'
            '**Password policy recommendations (NIST SP 800-63B):**\n'
            '- Minimum 8 characters (12+ recommended)\n'
            '- Check against breached password databases (e.g., Have I Been Pwned)\n'
            '- Allow passphrases with spaces\n'
            '- Don\'t require forced rotation unless compromised\n'
            '- Implement password strength meters for user feedback\n\n'
            '**CWE:** CWE-521 (Weak Password Requirements), CWE-916 (Insufficient Hash)'
        ),
    ),
    (
        ['2fa', 'two-factor', 'two factor', 'mfa', 'multi-factor', 'authenticator', 'totp', 'otp'],
        'Two-Factor Authentication (2FA/MFA)',
        (
            '**Two-Factor Authentication (2FA)** adds a second verification step beyond passwords.\n\n'
            '**Types of 2FA:**\n'
            '- **TOTP** (Time-based One-Time Password) — Google Authenticator, Authy\n'
            '- **WebAuthn / FIDO2** — hardware security keys (YubiKey)\n'
            '- **SMS codes** — least secure, vulnerable to SIM swapping\n'
            '- **Push notifications** — app-based approval\n\n'
            '**Implementation tips:**\n'
            '- Use TOTP or WebAuthn over SMS when possible\n'
            '- Generate **backup codes** for account recovery\n'
            '- Rate-limit verification attempts\n'
            '- Don\'t bypass 2FA for "trusted devices" without user consent\n\n'
            '💡 SafeWeb AI supports TOTP-based 2FA — enable it in your Profile → Security Settings!'
        ),
    ),
    # --- HTTPS & Headers ---
    (
        ['https', 'ssl', 'tls', 'certificate', 'encryption in transit', 'mixed content'],
        'HTTPS / TLS Security',
        (
            '**HTTPS (TLS)** encrypts data in transit between the browser and server. '
            '(OWASP A02:2021 — Cryptographic Failures)\n\n'
            '**Best practices:**\n'
            '- Use **TLS 1.2+** (disable TLS 1.0/1.1 and all SSL versions)\n'
            '- Enable **HSTS** (HTTP Strict Transport Security) with a long `max-age`\n'
            '- Use strong cipher suites (ECDHE + AES-GCM preferred)\n'
            '- Redirect all HTTP traffic to HTTPS (301 redirect)\n'
            '- Avoid mixed content (loading HTTP resources on HTTPS pages)\n'
            '- Use certificates from a trusted CA (Let\'s Encrypt is free)\n'
            '- Enable **OCSP stapling** for faster certificate validation\n\n'
            '**CWE:** CWE-319 (Cleartext Transmission), CWE-295 (Improper Cert Validation)\n\n'
            '💡 SafeWeb AI scans check your TLS configuration automatically!'
        ),
    ),
    (
        ['header', 'security header', 'csp', 'content security policy', 'hsts', 'x-frame',
         'x-content-type', 'referrer-policy', 'permissions-policy', 'http header'],
        'Security Headers',
        (
            '**Security Headers** are HTTP response headers that protect against common attacks.\n\n'
            '**Essential headers:**\n'
            '| Header | Purpose |\n'
            '|---|---|\n'
            '| `Content-Security-Policy` | Prevents XSS by controlling allowed script sources |\n'
            '| `Strict-Transport-Security` | Forces HTTPS for future visits (HSTS) |\n'
            '| `X-Frame-Options` | Prevents clickjacking (use `DENY` or `SAMEORIGIN`) |\n'
            '| `X-Content-Type-Options` | Prevents MIME-type sniffing (`nosniff`) |\n'
            '| `Referrer-Policy` | Controls how much referrer info is sent |\n'
            '| `Permissions-Policy` | Restricts browser features (camera, geolocation, etc.) |\n\n'
            '**Example CSP:** `Content-Security-Policy: default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'`\n\n'
            '**CWE:** CWE-693 (Protection Mechanism Failure)\n\n'
            '💡 SafeWeb AI scans automatically check for missing security headers!'
        ),
    ),
    (
        ['cors', 'cross-origin', 'origin policy', 'same-origin', 'access-control-allow'],
        'CORS (Cross-Origin Resource Sharing)',
        (
            '**CORS** controls which origins can make cross-origin requests to your API.\n\n'
            '**Common misconfigurations:**\n'
            '- `Access-Control-Allow-Origin: *` (allows any origin)\n'
            '- Reflecting the requesting origin without validation\n'
            '- Exposing sensitive headers unnecessarily\n'
            '- Allowing credentials with wildcard origins\n\n'
            '**Best practices:**\n'
            '- Whitelist specific origins instead of `*`\n'
            '- Validate the `Origin` header on the server side\n'
            '- Limit allowed methods and headers to what\'s needed\n'
            '- Use `Access-Control-Max-Age` to cache preflight responses\n\n'
            '**CWE:** CWE-942 (Overly Permissive CORS Policy)'
        ),
    ),
    # --- OWASP ---
    (
        ['owasp', 'owasp top 10', 'owasp top ten', 'top 10 risks', 'web security risks'],
        'OWASP Top 10 (2021)',
        (
            'The **OWASP Top 10 (2021)** lists the most critical web application security risks:\n\n'
            '1. **A01 — Broken Access Control** — unauthorized access to resources\n'
            '2. **A02 — Cryptographic Failures** — weak encryption, data exposure\n'
            '3. **A03 — Injection** — SQL, XSS, command injection\n'
            '4. **A04 — Insecure Design** — flaws in architecture decisions\n'
            '5. **A05 — Security Misconfiguration** — default configs, open ports\n'
            '6. **A06 — Vulnerable & Outdated Components** — unpatched libraries\n'
            '7. **A07 — Identification & Authentication Failures** — weak auth\n'
            '8. **A08 — Software & Data Integrity Failures** — insecure CI/CD\n'
            '9. **A09 — Security Logging & Monitoring Failures** — lack of visibility\n'
            '10. **A10 — Server-Side Request Forgery (SSRF)** — internal resource access\n\n'
            'SafeWeb AI scans test for **all** of these categories! Each finding in your scan '
            'report references the applicable OWASP category.\n\n'
            '💡 Start a scan to see how your website scores against the OWASP Top 10.'
        ),
    ),
    (
        ['access control', 'authorization', 'privilege escalation', 'idor',
         'insecure direct object', 'broken access', 'rbac', 'permission'],
        'Broken Access Control',
        (
            '**Broken Access Control** is the #1 risk in the OWASP Top 10 (A01:2021).\n\n'
            '**Common vulnerabilities:**\n'
            '- **IDOR** — accessing other users\' data by changing an ID in the URL\n'
            '- **Privilege escalation** — a regular user performing admin actions\n'
            '- **Missing function-level access control** — no server-side auth checks\n'
            '- **Metadata manipulation** — modifying JWT tokens or hidden form fields\n\n'
            '**Prevention:**\n'
            '- Deny by default — require explicit access grants\n'
            '- Implement **RBAC** (Role-Based Access Control) or ABAC\n'
            '- Validate object ownership on every request (not just the first time)\n'
            '- Use UUIDs instead of sequential IDs for resource identifiers\n'
            '- Log and alert on access control failures\n\n'
            '**CWE:** CWE-284, CWE-639 (IDOR), CWE-862 (Missing Authorization)'
        ),
    ),
    (
        ['security misconfiguration', 'default credentials', 'default password',
         'misconfiguration', 'hardening', 'unnecessary features'],
        'Security Misconfiguration',
        (
            '**Security Misconfiguration** is one of the most common and dangerous risks. (OWASP A05:2021)\n\n'
            '**Common issues:**\n'
            '- Default credentials left unchanged (admin/admin)\n'
            '- Unnecessary features enabled (directory listing, debug mode)\n'
            '- Missing security patches\n'
            '- Verbose error messages exposing stack traces\n'
            '- Overly permissive cloud storage (S3 buckets, Azure blobs)\n\n'
            '**Prevention checklist:**\n'
            '- ✅ Change all default credentials\n'
            '- ✅ Disable directory listing and debug modes in production\n'
            '- ✅ Remove unused frameworks, features, and endpoints\n'
            '- ✅ Apply security patches promptly\n'
            '- ✅ Use infrastructure-as-code for repeatable hardening\n'
            '- ✅ Run automated configuration scanners regularly\n\n'
            '**CWE:** CWE-16 (Configuration), CWE-1188 (Insecure Default)'
        ),
    ),
    (
        ['vulnerable component', 'outdated', 'dependency', 'library vulnerability',
         'npm audit', 'supply chain', 'cve', 'patch'],
        'Vulnerable & Outdated Components',
        (
            '**Vulnerable & Outdated Components** expose your app to known exploits. (OWASP A06:2021)\n\n'
            '**Risks:**\n'
            '- Libraries with known CVEs (e.g., Log4Shell, Heartbleed)\n'
            '- Unmaintained dependencies\n'
            '- Transitive dependency vulnerabilities\n\n'
            '**Prevention:**\n'
            '- Regularly run `npm audit`, `pip-audit`, `snyk test`\n'
            '- Keep dependencies updated with tools like Dependabot or Renovate\n'
            '- Monitor CVE databases for your tech stack\n'
            '- Use lockfiles (`package-lock.json`, `Pipfile.lock`) for reproducibility\n'
            '- Remove unused dependencies\n\n'
            '**CWE:** CWE-1104 (Unmaintained Third-Party Components)'
        ),
    ),
    # --- Phishing & Social Engineering ---
    (
        ['phishing', 'spear phishing', 'email attack', 'social engineering', 'pretexting',
         'vishing', 'smishing', 'whaling'],
        'Phishing & Social Engineering',
        (
            '**Phishing** is a social engineering attack that tricks users into revealing sensitive '
            'information or performing harmful actions.\n\n'
            '**Types:**\n'
            '- **Email phishing** — mass-targeted deceptive emails\n'
            '- **Spear phishing** — targeted attacks against specific individuals\n'
            '- **Whaling** — targeting executives / high-value targets\n'
            '- **Vishing** — voice/phone-based phishing\n'
            '- **Smishing** — SMS-based phishing\n\n'
            '**Indicators of phishing:**\n'
            '- Suspicious URLs (IP addresses, misspelled domains, lookalike domains)\n'
            '- Urgency or threatening language\n'
            '- Requests for personal information or credentials\n'
            '- Mismatched sender name and email domain\n'
            '- Unexpected attachments\n\n'
            '💡 Use our **URL scanner** to check suspicious links before clicking!'
        ),
    ),
    # --- Malware ---
    (
        ['malware', 'virus', 'ransomware', 'trojan', 'worm', 'spyware', 'adware', 'keylogger',
         'rootkit', 'botnet'],
        'Malware & Ransomware',
        (
            '**Malware** is malicious software designed to damage, disrupt, or gain unauthorized access.\n\n'
            '**Common types:**\n'
            '- **Ransomware** — encrypts files and demands payment\n'
            '- **Trojans** — disguised as legitimate software\n'
            '- **Worms** — self-replicating across networks\n'
            '- **Spyware / Keyloggers** — secretly monitor user activity\n'
            '- **Rootkits** — hide deep in the OS for persistent access\n'
            '- **Botnets** — networks of compromised machines for DDoS\n\n'
            '**Prevention:**\n'
            '- Keep systems and software updated\n'
            '- Use endpoint detection & response (EDR) solutions\n'
            '- Implement email filtering and sandboxing\n'
            '- Follow the principle of least privilege\n'
            '- Maintain offline backups (3-2-1 rule)\n\n'
            '💡 Upload suspicious files to SafeWeb AI\'s **file scanner** for ML-powered analysis!'
        ),
    ),
    # --- DDoS ---
    (
        ['ddos', 'denial of service', 'dos attack', 'rate limit', 'flooding', 'traffic attack'],
        'DDoS / Denial of Service',
        (
            '**Denial of Service (DoS/DDoS)** overwhelms a service with traffic to make it unavailable.\n\n'
            '**Types:**\n'
            '- **Volumetric** — UDP/ICMP floods that saturate bandwidth\n'
            '- **Protocol** — SYN floods, Ping of Death\n'
            '- **Application-layer** — HTTP floods, Slowloris\n\n'
            '**Mitigation:**\n'
            '- Use a CDN / DDoS protection service (Cloudflare, AWS Shield)\n'
            '- Implement **rate limiting** on APIs and endpoints\n'
            '- Use auto-scaling infrastructure\n'
            '- Deploy Web Application Firewalls (WAFs)\n'
            '- Set up traffic anomaly detection and alerting\n'
            '- Have an incident response plan ready\n\n'
            '**CWE:** CWE-400 (Uncontrolled Resource Consumption)'
        ),
    ),
    # --- API Security ---
    (
        ['api security', 'api key', 'api authentication', 'rest api', 'graphql security',
         'api gateway', 'api protection', 'api vulnerability'],
        'API Security',
        (
            '**API Security** is critical as modern applications rely heavily on APIs.\n\n'
            '**OWASP API Security Top 10 (2023):**\n'
            '1. Broken Object-Level Authorization\n'
            '2. Broken Authentication\n'
            '3. Broken Object Property-Level Authorization\n'
            '4. Unrestricted Resource Consumption\n'
            '5. Broken Function-Level Authorization\n\n'
            '**Best practices:**\n'
            '- Use **JWT** or **OAuth 2.0** for authentication\n'
            '- Implement **rate limiting** per user/IP\n'
            '- Validate all input (type, length, range, format)\n'
            '- Use API gateways for centralized security\n'
            '- Log all API requests for audit trails\n'
            '- Version your APIs and deprecate old versions\n'
            '- Never expose API keys in client-side code\n\n'
            '💡 Use SafeWeb AI\'s API key management to secure programmatic access!'
        ),
    ),
    # --- Cryptography ---
    (
        ['encryption', 'cryptography', 'aes', 'rsa', 'hash', 'md5', 'sha', 'data at rest',
         'key management', 'cipher'],
        'Cryptography & Encryption',
        (
            '**Cryptographic Failures** are the #2 risk in OWASP Top 10 (A02:2021).\n\n'
            '**Common mistakes:**\n'
            '- Using deprecated algorithms (MD5, SHA-1, DES, RC4)\n'
            '- Hardcoding encryption keys in source code\n'
            '- Not encrypting sensitive data at rest\n'
            '- Using ECB mode for block ciphers\n\n'
            '**Best practices:**\n'
            '- Use **AES-256-GCM** for symmetric encryption\n'
            '- Use **RSA-2048+** or **ECDSA P-256+** for asymmetric encryption\n'
            '- Use **bcrypt/Argon2** for password hashing (never plain SHA/MD5)\n'
            '- Store encryption keys in **HSM** or key management services (AWS KMS, Vault)\n'
            '- Encrypt sensitive data at rest and in transit\n'
            '- Rotate keys periodically\n\n'
            '**CWE:** CWE-327 (Broken Crypto), CWE-328 (Reversible One-Way Hash)'
        ),
    ),
    # --- File Uploads ---
    (
        ['file upload', 'upload vulnerability', 'unrestricted upload', 'web shell',
         'malicious upload', 'file validation'],
        'File Upload Security',
        (
            '**Unrestricted File Uploads** can lead to remote code execution (RCE).\n\n'
            '**Risks:**\n'
            '- Uploading web shells (`.php`, `.jsp`, `.aspx`) for server takeover\n'
            '- Path traversal via crafted filenames (`../../etc/passwd`)\n'
            '- Denial of service via extremely large files\n'
            '- Client-side attacks via malicious `.html` or `.svg` files\n\n'
            '**Prevention:**\n'
            '- **Whitelist** allowed file extensions and MIME types\n'
            '- Validate file content (magic bytes), not just the extension\n'
            '- Set a **maximum file size** limit\n'
            '- Store uploads outside the web root\n'
            '- Rename uploaded files with random names\n'
            '- Scan uploads with antivirus / malware detection\n\n'
            '**CWE:** CWE-434 (Unrestricted File Upload)\n\n'
            '💡 SafeWeb AI supports file scanning for malware detection!'
        ),
    ),
    # --- Input Validation ---
    (
        ['input validation', 'sanitization', 'data validation', 'whitelist', 'blacklist',
         'output encoding', 'escape', 'sanitize'],
        'Input Validation & Output Encoding',
        (
            '**Input Validation** is the first line of defense against injection attacks.\n\n'
            '**Principles:**\n'
            '- **Validate input** — check type, length, format, and range\n'
            '- **Sanitize input** — remove or escape dangerous characters\n'
            '- **Encode output** — context-aware encoding (HTML, JS, URL, SQL)\n\n'
            '**Best practices:**\n'
            '- Use allowlists over denylists (whitelist > blacklist)\n'
            '- Validate on both client AND server side\n'
            '- Use parameterized queries for database operations\n'
            '- Use templating engines that auto-escape output\n'
            '- Apply the **principle of least privilege** to all data flows\n\n'
            '**CWE:** CWE-20 (Improper Input Validation), CWE-116 (Improper Encoding)'
        ),
    ),
    # --- Logging & Monitoring ---
    (
        ['logging', 'monitoring', 'siem', 'audit', 'incident response', 'detection',
         'security monitoring', 'log management', 'alerting'],
        'Security Logging & Monitoring',
        (
            '**Security Logging & Monitoring Failures** mean you can\'t detect or respond to '
            'attacks. (OWASP A09:2021)\n\n'
            '**What to log:**\n'
            '- All authentication events (login, logout, failed attempts)\n'
            '- Authorization failures (403 errors)\n'
            '- Input validation failures\n'
            '- Application errors and exceptions\n'
            '- Admin actions (user management, config changes)\n\n'
            '**Best practices:**\n'
            '- Use structured logging (JSON format)\n'
            '- Centralize logs with a SIEM (Splunk, ELK Stack, Datadog)\n'
            '- Set up **real-time alerting** for suspicious patterns\n'
            '- Retain logs for at least 90 days\n'
            '- Protect logs from tampering (append-only, separate storage)\n'
            '- Never log sensitive data (passwords, tokens, PII)\n\n'
            '**CWE:** CWE-778 (Insufficient Logging)'
        ),
    ),
    # --- Cloud Security ---
    (
        ['cloud security', 'aws security', 'azure security', 'gcp', 'cloud misconfiguration',
         's3 bucket', 'iam', 'cloud storage'],
        'Cloud Security',
        (
            '**Cloud Security** involves protecting data, applications, and infrastructure in '
            'cloud environments.\n\n'
            '**Common misconfigurations:**\n'
            '- Public S3 buckets / Azure Blob Storage\n'
            '- Overly permissive IAM roles\n'
            '- Unencrypted data at rest\n'
            '- Missing network segmentation\n'
            '- Exposed management APIs\n\n'
            '**Best practices:**\n'
            '- Follow the **shared responsibility model**\n'
            '- Apply **least privilege** for all IAM roles and policies\n'
            '- Enable encryption at rest and in transit\n'
            '- Use **Cloud Security Posture Management** (CSPM) tools\n'
            '- Implement VPCs, security groups, and network ACLs\n'
            '- Enable multi-factor authentication for cloud console access\n'
            '- Use infrastructure-as-code (Terraform, CloudFormation) for consistency'
        ),
    ),
    # --- Penetration Testing ---
    (
        ['penetration testing', 'pentest', 'pen test', 'ethical hacking', 'bug bounty',
         'vulnerability assessment', 'security testing', 'red team'],
        'Penetration Testing & Security Assessment',
        (
            '**Penetration Testing** simulates real-world attacks to find vulnerabilities before '
            'attackers do.\n\n'
            '**Types:**\n'
            '- **Black box** — no prior knowledge of the target\n'
            '- **White box** — full source code and architecture access\n'
            '- **Grey box** — partial knowledge (user-level access)\n\n'
            '**Methodology (typical phases):**\n'
            '1. **Reconnaissance** — gather information about the target\n'
            '2. **Scanning** — identify open ports, services, and potential entry points\n'
            '3. **Exploitation** — attempt to exploit discovered vulnerabilities\n'
            '4. **Post-exploitation** — assess impact and persistence\n'
            '5. **Reporting** — document findings with severity and remediation\n\n'
            '**Tools:** Burp Suite, OWASP ZAP, Nmap, Metasploit, Nuclei\n\n'
            '💡 SafeWeb AI provides automated security scanning as a starting point for your '
            'security assessment!'
        ),
    ),
    # --- Data Protection & Privacy ---
    (
        ['data protection', 'gdpr', 'privacy', 'pii', 'data breach', 'data leak',
         'sensitive data', 'data classification'],
        'Data Protection & Privacy',
        (
            '**Data Protection** ensures sensitive information is handled securely.\n\n'
            '**Regulations:**\n'
            '- **GDPR** (EU) — user consent, right to erasure, data portability\n'
            '- **CCPA** (California) — consumer privacy rights\n'
            '- **HIPAA** (US healthcare) — protected health information\n'
            '- **PCI DSS** — payment card data security\n\n'
            '**Best practices:**\n'
            '- Classify data by sensitivity (public, internal, confidential, restricted)\n'
            '- Encrypt PII at rest and in transit\n'
            '- Implement data retention and deletion policies\n'
            '- Minimize data collection (collect only what\'s needed)\n'
            '- Maintain a data breach response plan\n'
            '- Conduct regular privacy impact assessments\n\n'
            '**CWE:** CWE-359 (Exposure of Private Information)'
        ),
    ),
    # --- Secure Development ---
    (
        ['secure development', 'sdlc', 'devsecops', 'secure coding', 'code review',
         'security by design', 'shift left', 'sast', 'dast'],
        'Secure Development (DevSecOps)',
        (
            '**DevSecOps** integrates security into every stage of the development lifecycle.\n\n'
            '**Key practices:**\n'
            '- **Threat modeling** during design phase\n'
            '- **SAST** (Static Application Security Testing) in CI/CD pipeline\n'
            '- **DAST** (Dynamic Application Security Testing) against running apps\n'
            '- **SCA** (Software Composition Analysis) for dependency vulnerabilities\n'
            '- **Code review** with security checklists\n'
            '- **Security training** for all developers\n\n'
            '**Tools:**\n'
            '- SAST: SonarQube, Semgrep, CodeQL\n'
            '- DAST: OWASP ZAP, Burp Suite, **SafeWeb AI**\n'
            '- SCA: Snyk, Dependabot, npm audit\n'
            '- IaC scanning: Checkov, tfsec\n\n'
            '💡 Integrate SafeWeb AI into your CI/CD pipeline for automated security testing!'
        ),
    ),
    # --- Network Security ---
    (
        ['firewall', 'network security', 'vpn', 'ids', 'ips', 'intrusion detection',
         'port scanning', 'network segmentation', 'zero trust'],
        'Network Security',
        (
            '**Network Security** protects infrastructure from unauthorized access and attacks.\n\n'
            '**Key concepts:**\n'
            '- **Firewalls** — filter traffic based on rules (allow/deny)\n'
            '- **IDS/IPS** — detect and prevent intrusion attempts\n'
            '- **VPN** — encrypted tunnels for secure remote access\n'
            '- **Network segmentation** — isolate critical systems\n'
            '- **Zero Trust** — "never trust, always verify" architecture\n\n'
            '**Best practices:**\n'
            '- Implement defense in depth (multiple layers)\n'
            '- Keep firewall rules minimal and documented\n'
            '- Monitor network traffic for anomalies\n'
            '- Regularly scan for open ports and services\n'
            '- Use VLANs to separate different security zones\n'
            '- Implement DNS security (DNSSEC, DNS filtering)'
        ),
    ),
    # --- Clickjacking ---
    (
        ['clickjacking', 'ui redress', 'iframe attack', 'frame busting'],
        'Clickjacking',
        (
            '**Clickjacking** (UI Redress) tricks users into clicking something different from '
            'what they perceive, by layering invisible frames over legitimate content.\n\n'
            '**Prevention:**\n'
            '- Set `X-Frame-Options: DENY` (or `SAMEORIGIN`)\n'
            '- Use `Content-Security-Policy: frame-ancestors \'none\'`\n'
            '- Implement frame-busting JavaScript as a fallback\n\n'
            '**CWE:** CWE-1021 (Improper Restriction of Rendered UI Layers)'
        ),
    ),
    # --- Scan help ---
    (
        ['scan', 'how to scan', 'start scan', 'run scan', 'website scan', 'security scan',
         'scan my site', 'check my site', 'analyze'],
        'How to Scan with SafeWeb AI',
        (
            '**Starting a security scan** with SafeWeb AI is easy:\n\n'
            '1. Navigate to the **Scan** page from the dashboard\n'
            '2. Enter your website URL (e.g., `https://example.com`)\n'
            '3. Choose scan depth:\n'
            '   - **Quick** — fast scan of main pages\n'
            '   - **Medium** — balanced depth and speed\n'
            '   - **Deep** — thorough analysis of all discovered pages\n'
            '4. Configure options (subdomain scanning, SSL checks)\n'
            '5. Click **Start Scan** and wait for results\n\n'
            '**Scan types available:**\n'
            '- 🌐 **Website Scan** — full vulnerability assessment\n'
            '- 📁 **File Scan** — malware detection using ML\n'
            '- 🔗 **URL Scan** — phishing detection for suspicious links\n\n'
            '**Pro tip:** After scanning, export a **PDF report** for documentation!'
        ),
    ),
    (
        ['score', 'security score', 'scan score', 'what does the score mean', 'scoring'],
        'Understanding Security Scores',
        (
            '**Security Score** is a 0–100 rating of your website\'s security posture.\n\n'
            '**How it\'s calculated:**\n'
            '- Start at **100** (perfect score)\n'
            '- Deductions per vulnerability found:\n'
            '  - 🔴 Critical: -25 points\n'
            '  - 🟠 High: -15 points\n'
            '  - 🟡 Medium: -8 points\n'
            '  - 🔵 Low: -3 points\n\n'
            '**Score ranges:**\n'
            '- **90-100** — Excellent security posture ✅\n'
            '- **70-89** — Good, but room for improvement\n'
            '- **50-69** — Needs attention, several vulnerabilities\n'
            '- **Below 50** — Critical issues, immediate action needed ⚠️\n\n'
            '💡 Fix critical and high severity issues first for the biggest score improvement!'
        ),
    ),
    # --- Greeting / Small talk ---
    (
        ['hello', 'hi', 'hey', 'good morning', 'good afternoon', 'good evening',
         'greetings', 'howdy', 'what\'s up', 'sup'],
        'Greeting',
        (
            'Hello! 👋 I\'m **SafeWeb AI Assistant**, your cybersecurity expert.\n\n'
            'I can help you with:\n'
            '- 🔍 **Understanding scan results** and vulnerability findings\n'
            '- 🛡️ **Security best practices** and remediation guidance\n'
            '- 📚 **Learning about** OWASP Top 10, XSS, SQL Injection, and more\n'
            '- 🔑 **Authentication & encryption** best practices\n'
            '- 🌐 **API security**, headers, CORS, and HTTPS\n\n'
            'What would you like to know about cybersecurity?'
        ),
    ),
    (
        ['thank', 'thanks', 'thx', 'appreciate', 'ty'],
        'Thank You',
        (
            'You\'re welcome! 😊 I\'m always here to help with your cybersecurity questions.\n\n'
            'Is there anything else you\'d like to know about web security?'
        ),
    ),
    (
        ['help', 'what can you do', 'capabilities', 'features', 'how does this work'],
        'SafeWeb AI Assistant Capabilities',
        (
            'I\'m **SafeWeb AI Assistant** — here\'s what I can help with:\n\n'
            '**🔍 Security Topics:**\n'
            '- OWASP Top 10, XSS, SQL Injection, CSRF, SSRF\n'
            '- Authentication, session management, 2FA\n'
            '- Security headers, HTTPS/TLS, CORS\n'
            '- Cryptography, password security\n'
            '- API security, file upload security\n'
            '- Malware, phishing, ransomware\n'
            '- Cloud security, network security\n'
            '- DevSecOps, penetration testing\n\n'
            '**🛡️ SafeWeb AI Features:**\n'
            '- Understanding your scan results\n'
            '- Remediation guidance for vulnerabilities\n'
            '- Security score explanations\n'
            '- Best practices recommendations\n\n'
            'Just ask me any cybersecurity question!'
        ),
    ),
]


def _match_knowledge_base(user_message: str, scan_context: str = '') -> dict | None:
    """Match user message against the knowledge base using keyword scoring."""
    message_lower = user_message.lower()
    best_match = None
    best_score = 0

    for keywords, title, response_text in KNOWLEDGE_BASE:
        score = 0
        for keyword in keywords:
            # Exact phrase match scores higher
            if keyword in message_lower:
                score += len(keyword.split()) * 2  # multi-word phrases score higher
            # Check individual words for partial matching
            elif len(keyword.split()) == 1:
                for word in message_lower.split():
                    # Fuzzy: strip punctuation and check
                    clean_word = re.sub(r'[^\w]', '', word)
                    if clean_word == keyword.replace('-', '').replace(' ', ''):
                        score += 1

        if score > best_score:
            best_score = score
            best_match = (title, response_text)

    # Lower the threshold to 1 for better matching
    if best_match and best_score >= 1:
        title, response_text = best_match

        # Enhance response with scan context if available
        if scan_context and any(kw in message_lower for kw in ['scan', 'result', 'finding', 'score', 'vulnerability']):
            response_text += (
                f'\n\n---\n**📊 From your recent scan:**\n{scan_context}'
            )

        return {
            'response': response_text,
            'tokens_used': 0,
        }

    return None


class ChatEngine:
    """Manages AI chat interactions with rich local knowledge + optional OpenAI."""

    def __init__(self):
        self._client = None

    def _get_client(self):
        """Lazy-load OpenAI client."""
        if self._client is None:
            try:
                from openai import OpenAI
                api_key = getattr(settings, 'OPENAI_API_KEY', '')
                if not api_key:
                    raise ValueError('OPENAI_API_KEY not configured')
                self._client = OpenAI(api_key=api_key)
            except ImportError:
                raise ImportError('openai package is required. Install with: pip install openai')
        return self._client

    def _has_openai_key(self):
        """Check if an OpenAI API key is configured."""
        return bool(getattr(settings, 'OPENAI_API_KEY', ''))

    def generate_response(self, user_message: str, session=None, scan_context: str = '') -> dict:
        """
        Generate an AI response to a user message.
        Uses OpenAI if configured, otherwise falls back to the rich local knowledge base.
        """
        # If no OpenAI key, go directly to local engine (skip exception overhead)
        if not self._has_openai_key():
            return self._local_response(user_message, session, scan_context)

        # Try OpenAI first
        messages = self._build_messages(user_message, session, scan_context)
        try:
            client = self._get_client()
            completion = client.chat.completions.create(
                model='gpt-4o-mini',
                messages=messages,
                max_tokens=1000,
                temperature=0.7,
            )

            response_text = completion.choices[0].message.content
            tokens_used = completion.usage.total_tokens if completion.usage else 0

            return {
                'response': response_text,
                'tokens_used': tokens_used,
            }

        except Exception as e:
            logger.error(f'OpenAI API error: {e}')
            return self._local_response(user_message, session, scan_context)

    def _local_response(self, user_message: str, session=None, scan_context: str = '') -> dict:
        """Generate a response using the local knowledge base with context awareness."""
        import random

        # Try knowledge base match
        kb_match = _match_knowledge_base(user_message, scan_context)
        if kb_match:
            return kb_match

        message_lower = user_message.lower()

        # If scan context is provided and user is asking about their scan
        if scan_context and any(word in message_lower for word in
                                ['my scan', 'my result', 'my site', 'my score', 'what did you find',
                                 'scan result', 'finding', 'issue', 'problem', 'fix']):
            return {
                'response': (
                    f'Here\'s a summary of your scan findings:\n\n{scan_context}\n\n'
                    'Would you like me to explain any specific vulnerability in detail, '
                    'or provide remediation guidance for a particular finding?'
                ),
                'tokens_used': 0,
            }

        # Check conversation history for context-aware follow-ups
        if session:
            try:
                from .models import ChatMessage
                last_bot_msg = ChatMessage.objects.filter(
                    session=session, role='assistant'
                ).order_by('-created_at').first()

                if last_bot_msg:
                    last_content_lower = last_bot_msg.content.lower()
                    # Follow-up on XSS topic
                    if 'xss' in last_content_lower or 'cross-site scripting' in last_content_lower:
                        if any(w in message_lower for w in ['yes', 'more', 'tell me', 'example', 'how', 'detail']):
                            return {
                                'response': (
                                    '**More on XSS Prevention:**\n\n'
                                    '1. **Output Encoding** — Always encode data before inserting it into HTML:\n'
                                    '   - HTML context: `&lt;`, `&gt;`, `&amp;`, `&quot;`\n'
                                    '   - JavaScript context: Unicode escaping\n'
                                    '   - URL context: percent-encoding\n\n'
                                    '2. **Content Security Policy (CSP):**\n'
                                    '   ```\n'
                                    '   Content-Security-Policy: default-src \'self\'; script-src \'self\'\n'
                                    '   ```\n\n'
                                    '3. **DOM-based XSS** — Avoid `innerHTML`, `document.write()`, `eval()`. '
                                    'Use `textContent` instead.\n\n'
                                    '4. **Framework protections:** React auto-escapes by default; '
                                    'avoid `dangerouslySetInnerHTML`. Django templates auto-escape; '
                                    'avoid `|safe` filter on user data.\n\n'
                                    'Want to learn about another vulnerability type?'
                                ),
                                'tokens_used': 0,
                            }
                    # Follow-up on SQL injection topic
                    if 'sql injection' in last_content_lower or 'sqli' in last_content_lower:
                        if any(w in message_lower for w in ['yes', 'more', 'tell me', 'example', 'how', 'detail']):
                            return {
                                'response': (
                                    '**Advanced SQL Injection Prevention:**\n\n'
                                    '1. **Parameterized queries** (the #1 defense):\n'
                                    '   ```python\n'
                                    '   # WRONG: cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
                                    '   # RIGHT:\n'
                                    '   cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])\n'
                                    '   ```\n\n'
                                    '2. **ORM usage:** Django ORM, SQLAlchemy, and Prisma automatically parameterize queries.\n\n'
                                    '3. **Stored procedures** with parameterized inputs.\n\n'
                                    '4. **Least privilege:** Database accounts should only have necessary permissions.\n\n'
                                    '5. **WAF rules:** Web Application Firewalls can catch common SQLi patterns.\n\n'
                                    'Would you like to explore another security topic?'
                                ),
                                'tokens_used': 0,
                            }
                    # Generic follow-up
                    if any(w in message_lower for w in ['yes', 'more', 'continue', 'go on', 'tell me more']):
                        return {
                            'response': (
                                'I\'d be happy to dive deeper! Could you be a bit more specific about '
                                'what you\'d like to know more about? For example:\n\n'
                                '- A specific vulnerability type (XSS, SQLi, CSRF, etc.)\n'
                                '- How to secure a specific technology\n'
                                '- Understanding your scan results\n'
                                '- Best practices for web security\n\n'
                                'Just let me know what interests you!'
                            ),
                            'tokens_used': 0,
                        }
            except Exception:
                pass

        # Handle common conversational patterns
        if any(w in message_lower for w in ['thank', 'thanks', 'thx', 'ty']):
            responses = [
                'You\'re welcome! Feel free to ask if you have more security questions. 🔐',
                'Happy to help! Don\'t hesitate to ask about any other cybersecurity topics.',
                'Glad I could assist! Stay secure, and let me know if you need anything else.',
            ]
            return {'response': random.choice(responses), 'tokens_used': 0}

        if any(w in message_lower for w in ['bye', 'goodbye', 'see you', 'later']):
            responses = [
                'Goodbye! Stay safe online! 🛡️',
                'See you later! Remember — security is a continuous process. 🔒',
                'Take care! Come back anytime you have security questions.',
            ]
            return {'response': random.choice(responses), 'tokens_used': 0}

        if any(w in message_lower for w in ['who are you', 'what are you', 'your name']):
            return {
                'response': (
                    'I\'m the **SafeWeb AI Security Assistant** 🤖\n\n'
                    'I\'m specialized in cybersecurity and can help you with:\n'
                    '- Understanding vulnerabilities (XSS, SQLi, CSRF, etc.)\n'
                    '- Interpreting your scan results\n'
                    '- Security best practices and remediation guidance\n'
                    '- OWASP Top 10 and compliance\n'
                    '- Web application security concepts\n\n'
                    'How can I help you today?'
                ),
                'tokens_used': 0,
            }

        if any(w in message_lower for w in ['how are you', 'how\'s it going', 'what\'s up']):
            return {
                'response': (
                    'I\'m doing great, thanks for asking! 😊\n\n'
                    'I\'m ready to help with any cybersecurity questions. '
                    'What would you like to know about?'
                ),
                'tokens_used': 0,
            }

        # Conversational fallback — provide helpful suggestions
        fallback_responses = [
            (
                'I\'d love to help with that! I specialize in **cybersecurity** topics.\n\n'
                'Here are some things you can ask me about:\n'
                '- **"What is XSS?"** — Learn about Cross-Site Scripting\n'
                '- **"How to prevent SQL injection?"** — Secure your database queries\n'
                '- **"Explain OWASP Top 10"** — Overview of critical web security risks\n'
                '- **"How to scan my website?"** — Get started with SafeWeb AI scanning\n'
                '- **"What does my security score mean?"** — Understand your results\n\n'
                'What topic interests you?'
            ),
            (
                'That\'s an interesting question! While I\'m focused on **web security**, '
                'I can help with a wide range of cybersecurity topics:\n\n'
                '🔍 **Vulnerability Types:** XSS, SQL Injection, CSRF, SSRF\n'
                '🛡️ **Prevention:** Security headers, input validation, authentication\n'
                '📊 **Scanning:** How to use SafeWeb AI for security assessments\n'
                '📋 **Compliance:** OWASP, security best practices\n\n'
                'Try asking about any of these topics!'
            ),
            (
                'I\'m your cybersecurity assistant and I can help with lots of security topics!\n\n'
                'Here\'s what I know best:\n'
                '- **Web vulnerabilities** — XSS, SQLi, CSRF, and more\n'
                '- **Security headers** — CSP, HSTS, X-Frame-Options\n'
                '- **Authentication** — OAuth, JWT, 2FA, password security\n'
                '- **API security** — Rate limiting, input validation\n'
                '- **Your scan results** — Understanding findings and fixes\n\n'
                'What would you like to explore?'
            ),
        ]
        return {
            'response': random.choice(fallback_responses),
            'tokens_used': 0,
        }

    def _build_messages(self, user_message, session, scan_context):
        """Build the message list for the OpenAI API call."""
        messages = [{'role': 'system', 'content': SYSTEM_PROMPT}]

        # Add scan context if provided
        if scan_context:
            messages.append({
                'role': 'system',
                'content': f'Context from the user\'s recent scan:\n{scan_context}',
            })

        # Add conversation history
        if session:
            from .models import ChatMessage
            history = ChatMessage.objects.filter(
                session=session
            ).order_by('-created_at')[:MAX_CONTEXT_MESSAGES]

            for msg in reversed(list(history)):
                if msg.role in ('user', 'assistant'):
                    messages.append({
                        'role': msg.role,
                        'content': msg.content,
                    })

        # Add current message
        messages.append({'role': 'user', 'content': user_message})

        return messages


# Singleton instance
_engine = None


def get_chat_engine() -> ChatEngine:
    global _engine
    if _engine is None:
        _engine = ChatEngine()
    return _engine
