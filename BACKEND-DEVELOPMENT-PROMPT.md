# SAFEWEB AI — COMPLETE BACKEND DEVELOPMENT MASTER PROMPT

## FOR: Claude AI (or equivalent LLM with coding capabilities)
## PURPOSE: Build a production-ready, fully functional Django backend for the SafeWeb AI cybersecurity platform
## GENERATED: 2026-02-15
## AUTHOR CONTEXT: Senior Backend Engineer + Offensive Security Engineer + AI/ML Engineer + System Analyst

---

# ⚠️ CRITICAL INSTRUCTIONS — READ BEFORE GENERATING ANY CODE

1. **This is NOT a prototype.** Every endpoint, every scanner, every model, every feature MUST be fully functional.
2. **No placeholder code.** No `pass`, no `TODO`, no `# implement later`, no mock data in the backend.
3. **Production-grade.** Error handling, input validation, rate limiting, logging, security headers — everything.
4. **The frontend already exists.** You are building the backend to serve an existing React + TypeScript frontend. The API contract is NON-NEGOTIABLE — you must match the exact data structures the frontend expects.
5. **OWASP-compliant scanning engine.** The scanner must actually crawl, test, and detect real vulnerabilities based on OWASP Top 10 2021+ and CWE Top 25.
6. **ML models must work.** File malware detection and URL phishing detection must use real trained models with real inference.
7. **Every button on every page must work.** Login, register, scan, export PDF, re-scan, delete, filter, search, admin actions, chatbot AI, API key management, password change, 2FA — ALL OF IT.

---

# SECTION A: PROJECT CONTEXT & ARCHITECTURE

## A.1 What SafeWeb AI Is

SafeWeb AI is a full-stack cybersecurity web application (graduation project, enterprise-grade quality) providing:

1. **Web Application Vulnerability Scanning** — Real crawling + payload injection + severity classification based on OWASP Top 10
2. **File Malware Detection** — ML-based classification of uploaded files (malicious vs clean)
3. **URL Phishing Detection** — ML-based classification of submitted URLs (phishing vs legitimate)
4. **AI-Powered Remediation Chatbot** — Context-aware security assistant using LLM API
5. **Admin Monitoring & ML Control** — Platform-wide metrics, user management, model toggling
6. **Educational Security Learning Center** — Articles, guides, vulnerability references

## A.2 System Architecture

```
React Frontend (localhost:5173)
    │
    │ REST API (JSON over HTTPS)
    │ CORS enabled for frontend origin
    │
Django Backend (localhost:8000)
    ├── Authentication (JWT + Google OAuth)
    ├── Scanning Engine (async tasks)
    ├── ML Inference Engine (scikit-learn / PyTorch)
    ├── AI Chatbot (OpenAI / Anthropic API)
    ├── Report Generator (PDF + JSON export)
    └── Admin API
    │
    │ ORM
    │
SQLite (development) → MySQL/PostgreSQL (production upgrade path)
```

## A.3 Technology Stack (MANDATORY — Do NOT substitute)

| Layer | Technology | Version |
|-------|-----------|---------|
| Language | Python | 3.11+ |
| Framework | Django | 5.0+ |
| API | Django REST Framework | 3.15+ |
| Auth | djangorestframework-simplejwt | 5.3+ |
| OAuth | django-allauth + dj-rest-auth | latest |
| CORS | django-cors-headers | latest |
| Database | SQLite (dev) / MySQL (prod) | — |
| Task Queue | Celery + Redis | latest |
| ML | scikit-learn + joblib | latest |
| HTTP Client | requests + beautifulsoup4 + lxml | latest |
| PDF Export | reportlab or weasyprint | latest |
| File Analysis | python-magic + yara-python (optional) | latest |
| AI Chatbot | openai or anthropic SDK | latest |
| Security | django-ratelimit, bleach, python-dotenv | latest |
| Testing | pytest + pytest-django + factory-boy | latest |

---

# SECTION B: DATABASE MODELS (Django ORM)

## B.1 User Model (Extended AbstractUser)

```python
class User(AbstractUser):
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=255)
    role = models.CharField(max_length=20, choices=[('user', 'User'), ('admin', 'Admin')], default='user')
    avatar = models.ImageField(upload_to='avatars/', null=True, blank=True)
    company = models.CharField(max_length=255, blank=True)
    job_title = models.CharField(max_length=255, blank=True)
    plan = models.CharField(max_length=20, choices=[('free', 'Free'), ('pro', 'Pro'), ('enterprise', 'Enterprise')], default='free')
    is_2fa_enabled = models.BooleanField(default=False)
    two_fa_secret = models.CharField(max_length=32, blank=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']
```

## B.2 API Key Model

```python
class APIKey(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='api_keys')
    key = models.CharField(max_length=64, unique=True)  # sk_live_xxx or sk_test_xxx
    name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    scans_count = models.IntegerField(default=0)
    last_used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
```

## B.3 Scan Model

```python
class Scan(models.Model):
    SCAN_TYPES = [('website', 'Website'), ('file', 'File'), ('url', 'URL')]
    SCAN_STATUSES = [('pending', 'Pending'), ('scanning', 'Scanning'), ('completed', 'Completed'), ('failed', 'Failed')]
    SCAN_DEPTHS = [('shallow', 'Shallow'), ('medium', 'Medium'), ('deep', 'Deep')]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='scans')
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPES)
    target = models.TextField()  # URL or filename
    status = models.CharField(max_length=20, choices=SCAN_STATUSES, default='pending')
    depth = models.CharField(max_length=20, choices=SCAN_DEPTHS, default='medium')
    include_subdomains = models.BooleanField(default=False)
    check_ssl = models.BooleanField(default=True)
    follow_redirects = models.BooleanField(default=True)
    score = models.IntegerField(default=0)  # 0-100 security score
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration = models.IntegerField(default=0)  # seconds
    error_message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    # File upload (for file scans)
    uploaded_file = models.FileField(upload_to='scan_files/', null=True, blank=True)
```

## B.4 Vulnerability Model

```python
class Vulnerability(models.Model):
    SEVERITIES = [('critical', 'Critical'), ('high', 'High'), ('medium', 'Medium'), ('low', 'Low')]
    
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='vulnerabilities')
    name = models.CharField(max_length=255)
    severity = models.CharField(max_length=20, choices=SEVERITIES)
    category = models.CharField(max_length=100)  # e.g., 'Injection', 'XSS', 'CSRF'
    description = models.TextField()
    impact = models.TextField()
    remediation = models.TextField()
    cwe = models.CharField(max_length=20, blank=True)  # e.g., 'CWE-89'
    cvss = models.FloatField(default=0.0)  # 0.0-10.0
    affected_url = models.URLField(max_length=2048, blank=True)
    evidence = models.TextField(blank=True)  # Raw evidence/proof
    is_false_positive = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
```

## B.5 ML Result Model

```python
class MLResult(models.Model):
    scan = models.OneToOneField(Scan, on_delete=models.CASCADE, related_name='ml_result')
    prediction = models.CharField(max_length=20)  # 'malicious', 'clean', 'phishing', 'legitimate'
    confidence = models.FloatField()  # 0.0-1.0
    model_used = models.CharField(max_length=100)
    features_extracted = models.JSONField(default=dict)
    processing_time = models.FloatField(default=0.0)  # seconds
    created_at = models.DateTimeField(auto_now_add=True)
```

## B.6 ML Model Registry

```python
class MLModel(models.Model):
    name = models.CharField(max_length=100)
    model_type = models.CharField(max_length=50)  # 'file_malware', 'url_phishing'
    version = models.CharField(max_length=20)
    accuracy = models.FloatField(default=0.0)
    precision_score = models.FloatField(default=0.0)
    recall = models.FloatField(default=0.0)
    f1_score = models.FloatField(default=0.0)
    is_active = models.BooleanField(default=True)
    model_file = models.FileField(upload_to='ml_models/')
    training_dataset = models.CharField(max_length=255, blank=True)
    trained_at = models.DateTimeField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
```

## B.7 Chat Message Model

```python
class ChatMessage(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='chat_messages')
    session_id = models.CharField(max_length=64)
    message = models.TextField()
    response = models.TextField()
    context = models.JSONField(default=dict)  # scan context, vulnerability context
    created_at = models.DateTimeField(auto_now_add=True)
```

## B.8 System Alert Model (Admin)

```python
class SystemAlert(models.Model):
    ALERT_TYPES = [('info', 'Info'), ('warning', 'Warning'), ('critical', 'Critical')]
    
    alert_type = models.CharField(max_length=20, choices=ALERT_TYPES)
    message = models.TextField()
    is_resolved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
```

## B.9 Scan Report Model

```python
class ScanReport(models.Model):
    FORMATS = [('pdf', 'PDF'), ('json', 'JSON'), ('csv', 'CSV'), ('xml', 'XML'), ('html', 'HTML')]
    
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='reports')
    format = models.CharField(max_length=10, choices=FORMATS)
    file = models.FileField(upload_to='reports/')
    generated_at = models.DateTimeField(auto_now_add=True)
```

## B.10 Learn Article Model

```python
class LearnArticle(models.Model):
    title = models.CharField(max_length=255)
    slug = models.SlugField(unique=True)
    excerpt = models.TextField()
    content = models.TextField()  # Markdown content
    category = models.CharField(max_length=50)
    tags = models.JSONField(default=list)
    author_name = models.CharField(max_length=100)
    author_avatar = models.URLField(blank=True)
    thumbnail = models.ImageField(upload_to='articles/', null=True, blank=True)
    read_time = models.IntegerField(default=5)  # minutes
    is_featured = models.BooleanField(default=False)
    is_published = models.BooleanField(default=True)
    published_at = models.DateTimeField(auto_now_add=True)
```

## B.11 User Session Model

```python
class UserSession(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions')
    token = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    is_active = models.BooleanField(default=True)
    last_activity = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
```

---

# SECTION C: COMPLETE API SPECIFICATION

Every endpoint below MUST be implemented. The response format MUST match exactly what the React frontend expects.

## C.1 Authentication Endpoints

### POST /api/auth/register
```json
// Request
{
    "name": "John Doe",
    "email": "john@example.com",
    "password": "SecureP@ss1",
    "confirm_password": "SecureP@ss1"
}

// Response 201
{
    "id": "uuid",
    "email": "john@example.com",
    "name": "John Doe",
    "role": "user",
    "createdAt": "2026-02-15T10:30:00Z",
    "token": {
        "access": "eyJ...",
        "refresh": "eyJ..."
    }
}

// Validation Rules (MUST MATCH FRONTEND):
// - name: required, non-empty
// - email: required, valid format, unique
// - password: min 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special (!@#$%^&*)
// - confirm_password: must match password
```

### POST /api/auth/login
```json
// Request
{
    "email": "john@example.com",
    "password": "SecureP@ss1",
    "remember_me": true
}

// Response 200
{
    "id": "uuid",
    "email": "john@example.com",
    "name": "John Doe",
    "role": "user",
    "avatar": null,
    "createdAt": "2026-02-15T10:30:00Z",
    "lastLogin": "2026-02-15T14:30:00Z",
    "token": {
        "access": "eyJ...",     // 15min expiry (or 7 days if remember_me)
        "refresh": "eyJ..."     // 7 days (or 30 days if remember_me)
    }
}
```

### POST /api/auth/logout
```
Authorization: Bearer <access_token>
// Response 200
{ "detail": "Successfully logged out." }
```

### POST /api/auth/verify
```
Authorization: Bearer <access_token>
// Response 200 — returns current user data (same shape as login response minus token)
```

### POST /api/auth/refresh
```json
// Request
{ "refresh": "eyJ..." }
// Response 200
{ "access": "eyJ..." }
```

### POST /api/auth/google
```json
// Request
{ "credential": "<google_id_token>" }
// Response 200 — same shape as login response
```

### POST /api/auth/forgot-password
```json
// Request
{ "email": "john@example.com" }
// Response 200
{ "detail": "Password reset email sent." }
```

### POST /api/auth/reset-password
```json
// Request
{ "token": "reset-token", "password": "NewP@ss1", "confirm_password": "NewP@ss1" }
// Response 200
{ "detail": "Password reset successfully." }
```

### POST /api/auth/change-password
```json
// Request (authenticated)
{ "current_password": "OldP@ss1", "new_password": "NewP@ss2", "confirm_password": "NewP@ss2" }
// Response 200
{ "detail": "Password changed successfully." }
```

## C.2 User Profile Endpoints

### GET /api/user/profile
```json
// Response 200
{
    "id": "uuid",
    "email": "admin@safeweb.ai",
    "name": "Security Admin",
    "role": "user",
    "avatar": null,
    "company": "SafeWeb AI",
    "jobTitle": "Security Engineer",
    "plan": "pro",
    "is2faEnabled": false,
    "createdAt": "2026-01-15T10:30:00Z",
    "lastLogin": "2026-02-15T14:30:00Z",
    "stats": {
        "totalScans": 1932,
        "vulnerabilitiesFound": 4521,
        "issuesFixed": 3847
    },
    "subscription": {
        "plan": "Pro",
        "status": "active",
        "scansUsed": 847,
        "scansLimit": "Unlimited",
        "billingCycle": "Monthly",
        "nextBilling": "2026-03-15",
        "amount": "$49.00"
    }
}
```

### PUT /api/user/profile
```json
// Request (authenticated)
{
    "name": "Security Admin",
    "company": "SafeWeb AI",
    "jobTitle": "Security Engineer"
}
// Response 200 — returns updated profile
```

### GET /api/user/api-keys
```json
// Response 200
[
    {
        "id": "sk_live_abc123xyz",
        "name": "Production API",
        "created": "2024-01-15",
        "lastUsed": "2 hours ago",
        "scans": 1243,
        "isActive": true
    }
]
```

### POST /api/user/api-keys
```json
// Request
{ "name": "My New Key" }
// Response 201
{ "id": "sk_live_newkey123", "name": "My New Key", "key": "sk_live_full_visible_key_only_once", ... }
```

### DELETE /api/user/api-keys/{key_id}
```json
// Response 200
{ "detail": "API key revoked successfully." }
```

### GET /api/user/sessions
```json
// Response 200
[
    {
        "id": "session-uuid",
        "ipAddress": "192.168.1.1",
        "userAgent": "Mozilla/5.0...",
        "lastActivity": "2026-02-15T14:30:00Z",
        "isActive": true,
        "isCurrent": true
    }
]
```

### POST /api/user/2fa/enable
```json
// Response 200
{ "secret": "BASE32SECRET", "qrCode": "data:image/png;base64,..." }
```

### POST /api/user/2fa/verify
```json
// Request
{ "code": "123456" }
// Response 200
{ "detail": "2FA enabled successfully.", "backupCodes": ["code1", "code2", ...] }
```

## C.3 Scanning Endpoints

### POST /api/scan/website
```json
// Request (authenticated)
{
    "url": "https://example.com",
    "scanDepth": "medium",
    "includeSubdomains": false,
    "checkSsl": true,
    "followRedirects": true
}

// Response 201 — Scan created, processing starts asynchronously
{
    "id": "scan-uuid",
    "target": "https://example.com",
    "type": "website",
    "status": "pending",
    "startTime": "2026-02-15T10:30:00Z",
    "message": "Scan initiated. Use GET /api/scan/{id} to check progress."
}
```

### POST /api/scan/file
```
Content-Type: multipart/form-data
file: <binary>

// Response 201
{
    "id": "scan-uuid",
    "target": "malware_sample.exe",
    "type": "file",
    "status": "pending",
    "startTime": "2026-02-15T10:30:00Z"
}
```

### POST /api/scan/url
```json
// Request
{ "url": "https://suspicious-link.xyz/login" }

// Response 201
{
    "id": "scan-uuid",
    "target": "https://suspicious-link.xyz/login",
    "type": "url",
    "status": "pending",
    "startTime": "2026-02-15T10:30:00Z"
}
```

### GET /api/scan/{id}
```json
// Response 200 — MUST match this EXACT structure (frontend ScanResults.tsx depends on it)
{
    "id": "scan-uuid",
    "target": "https://example.com",
    "type": "website",
    "status": "completed",
    "startTime": "2026-02-15T10:30:00Z",
    "endTime": "2026-02-15T10:45:00Z",
    "duration": 15,
    "score": 82,
    "summary": {
        "total": 16,
        "critical": 1,
        "high": 2,
        "medium": 5,
        "low": 8
    },
    "vulnerabilities": [
        {
            "id": "vuln-uuid",
            "name": "SQL Injection in Login Form",
            "severity": "critical",
            "category": "Injection",
            "description": "The login form is vulnerable to SQL injection...",
            "impact": "An attacker could bypass authentication...",
            "remediation": "Use parameterized queries (prepared statements)...",
            "cwe": "CWE-89",
            "cvss": 9.8,
            "affectedUrl": "https://example.com/login",
            "evidence": "POST /login HTTP/1.1\nusername=' OR '1'='1\npassword=anything"
        }
    ],
    "scanOptions": {
        "depth": "medium",
        "includeSubdomains": false,
        "checkSsl": true
    }
}

// For file/URL scans, also include:
"mlResult": {
    "prediction": "malicious",
    "confidence": 0.93,
    "modelUsed": "RandomForest v2.1"
}
```

### GET /api/scans
```json
// Query params: ?search=example&status=completed&type=website&page=1&page_size=20
// Response 200 — MUST match ScanHistory.tsx mock data structure
{
    "count": 24,
    "next": "/api/scans?page=2",
    "previous": null,
    "results": [
        {
            "id": "scan-uuid",
            "target": "https://example.com",
            "type": "Website",
            "status": "completed",
            "date": "2025-12-20T10:30:00Z",
            "duration": 15,
            "score": 82,
            "vulnerabilities": {
                "critical": 1,
                "high": 2,
                "medium": 5,
                "low": 8
            }
        }
    ],
    "stats": {
        "total": 24,
        "completed": 20,
        "failed": 2,
        "avgScore": 85
    }
}
```

### DELETE /api/scan/{id}
```json
// Response 200
{ "detail": "Scan deleted successfully." }
```

### POST /api/scan/{id}/rescan
```json
// Response 201 — creates new scan with same config
{ "id": "new-scan-uuid", "status": "pending", ... }
```

## C.4 Report Export Endpoints

### GET /api/scan/{id}/export?format=pdf
```
// Response 200
Content-Type: application/pdf
Content-Disposition: attachment; filename="safeweb-scan-report-{id}.pdf"
<binary PDF data>
```

### GET /api/scan/{id}/export?format=json
```json
// Response 200
Content-Type: application/json
// Full scan result JSON
```

### GET /api/scan/{id}/export?format=csv
```
// Response 200
Content-Type: text/csv
<CSV data with vulnerability rows>
```

## C.5 Dashboard Endpoint

### GET /api/dashboard
```json
// Response 200 — MUST match Dashboard.tsx mock data structure
{
    "stats": {
        "totalScans": 24,
        "criticalIssues": 3,
        "securityScore": 87,
        "lastScan": "2 hours ago"
    },
    "recentScans": [
        {
            "id": "scan-uuid",
            "target": "https://example.com",
            "type": "Website",
            "status": "completed",
            "date": "2025-12-20T10:30:00Z",
            "vulnerabilities": { "critical": 1, "high": 2, "medium": 5, "low": 8 },
            "score": 82
        }
    ],
    "vulnerabilityOverview": {
        "critical": 3,
        "high": 7,
        "medium": 15,
        "low": 28
    }
}
```

## C.6 AI Chatbot Endpoint

### POST /api/chat
```json
// Request (authenticated)
{
    "message": "How do I fix SQL injection?",
    "sessionId": "chat-session-uuid",
    "context": {
        "scanId": "scan-uuid",  // optional — if user is asking about a specific scan
        "vulnerabilityId": "vuln-uuid"  // optional
    }
}

// Response 200
{
    "id": "msg-uuid",
    "message": "To fix SQL injection vulnerabilities, you should...",
    "sender": "bot",
    "time": "2026-02-15T14:30:00Z",
    "suggestions": [
        "Show me parameterized query examples",
        "Explain OWASP SQL Injection prevention"
    ]
}
```

## C.7 Admin Endpoints

### GET /api/admin/dashboard
```json
// Response 200 — MUST match AdminDashboard.tsx structure
{
    "stats": {
        "totalUsers": 2847,
        "activeScans": 143,
        "vulnerabilitiesFound": 8421,
        "systemUptime": "99.98%"
    },
    "scanStats": [
        { "status": "Completed", "count": 1247, "percentage": 68 },
        { "status": "In Progress", "count": 143, "percentage": 8 },
        { "status": "Failed", "count": 89, "percentage": 5 },
        { "status": "Queued", "count": 352, "percentage": 19 }
    ],
    "systemAlerts": [
        { "id": 1, "type": "warning", "message": "High API usage detected", "time": "10 min ago" }
    ],
    "recentUsers": [
        { "id": 1, "name": "John Doe", "email": "john@example.com", "plan": "Pro", "status": "active", "joined": "2 hours ago" }
    ]
}
```

### GET /api/admin/users
```json
// Query params: ?search=john&plan=pro&status=active&page=1
// Response 200 — Paginated user list
{
    "count": 2847,
    "results": [
        {
            "id": "uuid",
            "name": "John Doe",
            "email": "john@example.com",
            "plan": "Pro",
            "status": "active",
            "role": "user",
            "totalScans": 45,
            "joined": "2026-01-15T10:30:00Z",
            "lastLogin": "2 hours ago"
        }
    ]
}
```

### PUT /api/admin/users/{id}
```json
// Request — admin can change role, plan, status
{ "role": "admin", "plan": "enterprise", "status": "active" }
```

### DELETE /api/admin/users/{id}
```json
// Response 200
{ "detail": "User deleted." }
```

### GET /api/admin/scans
```json
// Query params: ?search=example&status=completed&page=1
// Response 200 — Platform-wide scan list (all users)
```

### GET /api/admin/ml/models
```json
// Response 200
{
    "models": [
        {
            "id": "model-uuid",
            "name": "MalwareDetector",
            "type": "file_malware",
            "version": "2.1",
            "accuracy": 0.967,
            "precision": 0.952,
            "recall": 0.978,
            "f1Score": 0.965,
            "isActive": true,
            "trainedAt": "2026-01-01T00:00:00Z",
            "trainingDataset": "EMBER-2024"
        }
    ],
    "trainingJobs": [
        { "id": 1, "model": "URLPhishingDetector", "status": "completed", "progress": 100, "startedAt": "...", "completedAt": "..." }
    ],
    "datasets": [
        { "name": "EMBER-2024", "size": "2.3 GB", "samples": 1200000, "lastUpdated": "2026-01-15" }
    ]
}
```

### POST /api/admin/ml/toggle
```json
// Request
{ "modelId": "model-uuid", "active": false }
// Response 200
{ "detail": "Model deactivated." }
```

### GET /api/admin/settings
```json
// Response 200 — system configuration
{
    "siteName": "SafeWeb AI",
    "siteUrl": "https://safeweb.ai",
    "adminEmail": "admin@safeweb.ai",
    "supportEmail": "support@safeweb.ai",
    "maxScanDepth": 100,
    "concurrentScans": 10,
    "scanTimeout": 3600,
    "enforce2FA": false,
    "passwordExpiry": 90,
    "ipWhitelist": "",
    "maintenanceMode": false,
    "registrationEnabled": true
}
```

### PUT /api/admin/settings
```json
// Request — update system settings
// Response 200 — returns updated settings
```

## C.8 Learn/Articles Endpoints

### GET /api/learn/articles
```json
// Query params: ?category=web-security&search=xss&featured=true&page=1
// Response 200
{
    "count": 24,
    "results": [
        {
            "id": "article-uuid",
            "title": "Understanding SQL Injection",
            "slug": "understanding-sql-injection",
            "excerpt": "Learn about one of the most critical web vulnerabilities...",
            "category": "Web Security",
            "tags": ["sql-injection", "owasp", "database"],
            "author": { "name": "Security Team", "avatar": null },
            "publishedAt": "2026-01-15T10:30:00Z",
            "readTime": 8,
            "thumbnail": null,
            "isFeatured": true
        }
    ]
}
```

### GET /api/learn/articles/{slug}
```json
// Response 200 — full article with content
{
    "id": "article-uuid",
    "title": "Understanding SQL Injection",
    "slug": "understanding-sql-injection",
    "content": "# Understanding SQL Injection\n\n## What is SQL Injection?\n\n...",
    "category": "Web Security",
    "tags": ["sql-injection", "owasp"],
    "author": { "name": "Security Team" },
    "publishedAt": "2026-01-15T10:30:00Z",
    "readTime": 8
}
```

---

# SECTION D: VULNERABILITY SCANNING ENGINE

This is the CORE of the application. The scanner MUST actually work — it must crawl websites, inject payloads, analyze responses, and classify vulnerabilities.

## D.1 Scanner Architecture

```
ScanOrchestrator
├── WebCrawler (discovers pages, forms, inputs, links)
├── HeaderAnalyzer (security headers check)
├── SSLAnalyzer (TLS configuration check)
├── VulnerabilityTesters
│   ├── SQLInjectionTester
│   ├── XSSTester
│   ├── CSRFTester
│   ├── AuthenticationTester
│   ├── SecurityMisconfigTester
│   ├── SensitiveDataTester
│   ├── AccessControlTester
│   ├── XXETester
│   ├── DeserializationTester
│   ├── ComponentVulnTester
│   ├── LoggingMonitoringTester
│   └── SSRFTester
├── SeverityClassifier (CVSS calculator)
└── ReportGenerator
```

## D.2 OWASP Top 10 (2021) Detection — MANDATORY

Each vulnerability tester below MUST:
1. Actually send HTTP requests with test payloads
2. Analyze the response for vulnerability indicators
3. Classify severity using CVSS 3.1 scoring
4. Generate a clear description, impact statement, and remediation guide
5. Capture evidence (request/response snippets)

### D.2.1 A01:2021 — Broken Access Control
**Detection Methods:**
- Test for IDOR: Modify IDs in URLs, request bodies, headers
- Check for directory traversal: `../../../etc/passwd`
- Test horizontal privilege escalation: Access other users' resources
- Check for missing function-level access control
- Verify CORS misconfiguration
- Test forced browsing to admin pages

**Payloads:**
```python
IDOR_PAYLOADS = ['/api/user/1', '/api/user/2', '/api/user/999']
DIR_TRAVERSAL = ['../../../etc/passwd', '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts', '....//....//etc/passwd']
FORCED_BROWSE = ['/admin', '/admin/dashboard', '/api/admin', '/backup', '/.env', '/config', '/debug', '/phpinfo.php']
```

### D.2.2 A02:2021 — Cryptographic Failures
**Detection Methods:**
- Check for HTTP (non-HTTPS) on sensitive pages
- Detect weak SSL/TLS versions (TLS 1.0, 1.1)
- Identify weak cipher suites
- Check for sensitive data in URLs (credentials, tokens)
- Verify secure cookie flags (Secure, HttpOnly, SameSite)
- Check for exposed API keys, passwords in source code

### D.2.3 A03:2021 — Injection
**Detection Methods:**
- **SQL Injection:** Test all input fields with SQL payloads
- **XSS:** Test with script injection payloads
- **Command Injection:** Test with OS command payloads
- **LDAP Injection:** Test with LDAP special characters
- **Header Injection:** Test CRLF injection

**SQL Injection Payloads:**
```python
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "'; DROP TABLE users; --",
    "' UNION SELECT NULL,NULL,NULL --",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "1 OR 1=1",
    "' OR ''='",
    "admin'--",
    "1; WAITFOR DELAY '0:0:5' --",  # Time-based blind
    "1' AND SLEEP(5) --",
    "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --",
]

SQLI_ERROR_PATTERNS = [
    r'SQL syntax.*MySQL',
    r'Warning.*mysql_',
    r'PostgreSQL.*ERROR',
    r'ORA-\d{5}',
    r'Microsoft.*ODBC.*SQL Server',
    r'Unclosed quotation mark',
    r'quoted string not properly terminated',
    r'SQLite.*error',
    r'SQLSTATE\[',
    r'pg_query.*ERROR',
    r'System\.Data\.SqlClient',
]
```

**XSS Payloads:**
```python
XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert("XSS")>',
    '"><script>alert("XSS")</script>',
    "'-alert('XSS')-'",
    '<body onload=alert("XSS")>',
    '<iframe src="javascript:alert(\'XSS\')">',
    '{{7*7}}',  # Template injection
    '${7*7}',   # Template injection
    '<details open ontoggle=alert("XSS")>',
    '<marquee onstart=alert("XSS")>',
    'javascript:alert("XSS")',
]

XSS_DETECTION_PATTERNS = [
    # Check if payload is reflected unescaped in response
    # Check if special characters are not encoded
    # Check response Content-Type headers
    # Check for CSP headers
]
```

### D.2.4 A04:2021 — Insecure Design
**Detection Methods:**
- Check for rate limiting on auth endpoints
- Test for account enumeration (different responses for valid/invalid emails)
- Check for CAPTCHA on sensitive forms
- Test for password complexity requirements
- Check for secure password reset flow

### D.2.5 A05:2021 — Security Misconfiguration
**Detection Methods:**
- Check for default credentials
- Check for exposed error messages / stack traces
- Check for directory listing
- Check for unnecessary HTTP methods (PUT, DELETE, TRACE)
- Check for exposed admin interfaces
- Check server version disclosure
- Check for missing security headers

**Required Security Headers Check:**
```python
REQUIRED_HEADERS = {
    'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
    'X-Content-Type-Options': ['nosniff'],
    'X-XSS-Protection': ['1; mode=block'],
    'Strict-Transport-Security': ['max-age='],
    'Content-Security-Policy': None,  # Just check presence
    'Referrer-Policy': ['strict-origin-when-cross-origin', 'no-referrer'],
    'Permissions-Policy': None,
    'Cache-Control': ['no-store', 'no-cache'],
}
```

### D.2.6 A06:2021 — Vulnerable and Outdated Components
**Detection Methods:**
- Identify server software versions from headers (Server, X-Powered-By)
- Check JavaScript libraries against known CVE databases
- Detect CMS versions (WordPress, Drupal, Joomla)
- Check for outdated jQuery, Bootstrap, Angular, React versions

### D.2.7 A07:2021 — Identification and Authentication Failures
**Detection Methods:**
- Test for default/weak credentials
- Test for brute force protection
- Check session management (secure cookies, session fixation)
- Test for credential stuffing protection
- Check for multi-factor authentication availability
- Test password reset security

### D.2.8 A08:2021 — Software and Data Integrity Failures
**Detection Methods:**
- Check for Subresource Integrity (SRI) on external scripts
- Detect unsigned/unverified updates
- Check for insecure deserialization indicators

### D.2.9 A09:2021 — Security Logging and Monitoring Failures
**Detection Methods:**
- Check for excessive information in error responses
- Test for log injection possibilities
- Verify security event logging indicators

### D.2.10 A10:2021 — Server-Side Request Forgery (SSRF)
**Detection Methods:**
- Test URL parameters for internal network access
- Test with internal IP ranges (127.0.0.1, 10.x, 172.16.x, 192.168.x)
- Test with cloud metadata endpoints (169.254.169.254)

**SSRF Payloads:**
```python
SSRF_PAYLOADS = [
    'http://127.0.0.1',
    'http://localhost',
    'http://[::1]',
    'http://169.254.169.254/latest/meta-data/',
    'http://10.0.0.1',
    'http://192.168.1.1',
    'http://172.16.0.1',
    'file:///etc/passwd',
    'dict://localhost:11211/',
    'gopher://localhost:25/',
]
```

## D.3 Scan Flow Implementation

```python
class ScanOrchestrator:
    """
    Main scan orchestrator — coordinates all scanning phases.
    Runs as a Celery async task.
    """
    
    def execute_scan(self, scan_id: str):
        scan = Scan.objects.get(id=scan_id)
        scan.status = 'scanning'
        scan.started_at = timezone.now()
        scan.save()
        
        try:
            if scan.scan_type == 'website':
                self._scan_website(scan)
            elif scan.scan_type == 'file':
                self._scan_file(scan)
            elif scan.scan_type == 'url':
                self._scan_url(scan)
            
            scan.status = 'completed'
            scan.score = self._calculate_security_score(scan)
        except Exception as e:
            scan.status = 'failed'
            scan.error_message = str(e)
        finally:
            scan.completed_at = timezone.now()
            scan.duration = (scan.completed_at - scan.started_at).seconds
            scan.save()
    
    def _scan_website(self, scan):
        # Phase 1: Crawl
        crawler = WebCrawler(scan.target, depth=scan.depth, follow_redirects=scan.follow_redirects)
        pages = crawler.crawl()
        
        # Phase 2: Analyze headers
        header_analyzer = HeaderAnalyzer()
        header_vulns = header_analyzer.analyze(scan.target)
        
        # Phase 3: SSL Check
        if scan.check_ssl:
            ssl_analyzer = SSLAnalyzer()
            ssl_vulns = ssl_analyzer.analyze(scan.target)
        
        # Phase 4: Test each page for vulnerabilities
        for page in pages:
            for tester_class in VULNERABILITY_TESTERS:
                tester = tester_class()
                vulns = tester.test(page, scan.depth)
                for vuln in vulns:
                    Vulnerability.objects.create(scan=scan, **vuln)
        
        # Phase 5: Save all findings
    
    def _scan_file(self, scan):
        # Use ML model for file classification
        ml_engine = MLEngine()
        result = ml_engine.predict_file(scan.uploaded_file.path)
        MLResult.objects.create(scan=scan, **result)
    
    def _scan_url(self, scan):
        # Use ML model for URL classification
        ml_engine = MLEngine()
        result = ml_engine.predict_url(scan.target)
        MLResult.objects.create(scan=scan, **result)
    
    def _calculate_security_score(self, scan):
        """Calculate 0-100 score based on vulnerability severity distribution"""
        vulns = scan.vulnerabilities.all()
        if not vulns.exists():
            return 100
        
        penalty = 0
        for vuln in vulns:
            if vuln.severity == 'critical': penalty += 25
            elif vuln.severity == 'high': penalty += 15
            elif vuln.severity == 'medium': penalty += 8
            elif vuln.severity == 'low': penalty += 3
        
        return max(0, 100 - penalty)
```

## D.4 WebCrawler Implementation Requirements

```python
class WebCrawler:
    """
    Crawls target website to discover:
    - All linked pages (up to depth limit)
    - HTML forms with input fields
    - URL parameters
    - JavaScript files
    - API endpoints
    - Cookies
    """
    
    def __init__(self, base_url, depth='medium', follow_redirects=True):
        self.base_url = base_url
        self.max_pages = {'shallow': 10, 'medium': 50, 'deep': 200}[depth]
        self.follow_redirects = follow_redirects
        self.visited = set()
        self.pages = []
    
    def crawl(self) -> list:
        """
        BFS crawl starting from base_url.
        Returns list of Page objects with:
        - url
        - forms (list of Form objects with action, method, inputs)
        - parameters (URL query params)
        - cookies
        - headers
        - response_body
        - links (outgoing links)
        """
        pass  # IMPLEMENT FULLY
```

## D.5 CVSS 3.1 Scoring

Each vulnerability MUST be assigned a CVSS score using proper vector calculation:

```python
def calculate_cvss(attack_vector, attack_complexity, privileges_required, 
                   user_interaction, scope, confidentiality, integrity, availability):
    """
    Calculate CVSS 3.1 Base Score
    Returns score 0.0 - 10.0
    """
    # Implement full CVSS 3.1 formula
    # Reference: https://www.first.org/cvss/v3.1/specification-document
```

## D.6 Report Generation

### PDF Report Structure:
1. **Cover Page** — SafeWeb AI logo, scan target, date, overall score
2. **Executive Summary** — High-level findings, risk rating, score breakdown
3. **Vulnerability Distribution** — Chart/table showing critical/high/medium/low counts
4. **Detailed Findings** — For each vulnerability:
   - Name, severity, CVSS score, CWE ID
   - Description
   - Affected URL
   - Evidence (request/response)
   - Impact Assessment
   - Detailed Remediation Guide with code examples
5. **Remediation Priority Matrix** — Ordered by severity and ease of fix
6. **Compliance Mapping** — OWASP Top 10 / CWE Top 25 / PCI DSS alignment
7. **Methodology** — Scanning approach description
8. **Appendix** — Full technical details, scan configuration

---

# SECTION E: ML ENGINE

## E.1 File Malware Detection

### Feature Extraction:
```python
class FileFeatureExtractor:
    """
    Extract features from uploaded files for malware classification.
    Features include:
    - File entropy (Shannon entropy)
    - File size
    - File type / magic bytes
    - PE header features (for executables): sections, imports, exports
    - String patterns: suspicious API calls, registry keys, URLs
    - Byte n-gram frequencies
    - Packed/obfuscated indicators
    """
    
    def extract(self, file_path: str) -> dict:
        features = {}
        features['file_size'] = os.path.getsize(file_path)
        features['entropy'] = self._calculate_entropy(file_path)
        features['file_type'] = magic.from_file(file_path)
        # ... more feature extraction
        return features
```

### Model Training:
- Use public datasets: EMBER, VirusShare, MalwareBazaar samples
- Algorithm: Random Forest (primary), Gradient Boosting (secondary)
- Train/test split: 80/20
- Cross-validation: 5-fold
- Target metrics: >95% accuracy, >90% precision, >90% recall

### Inference:
```python
class MalwareDetector:
    def predict(self, file_path: str) -> dict:
        features = self.feature_extractor.extract(file_path)
        features_array = self._prepare_features(features)
        prediction = self.model.predict(features_array)
        confidence = self.model.predict_proba(features_array).max()
        
        return {
            'prediction': 'malicious' if prediction[0] == 1 else 'clean',
            'confidence': float(confidence),
            'model_used': f'{self.model_name} v{self.model_version}',
            'features_extracted': features,
            'processing_time': elapsed_time
        }
```

## E.2 URL Phishing Detection

### Feature Extraction:
```python
class URLFeatureExtractor:
    """
    Extract features from URLs for phishing classification.
    Features include:
    - URL length
    - Domain length
    - Number of dots, hyphens, underscores
    - Has IP address as domain
    - Uses URL shortener
    - Has suspicious TLD
    - Has HTTPS
    - Domain age (via WHOIS)
    - Is subdomain count excessive
    - Path depth
    - Has @ symbol
    - Has suspicious keywords (login, verify, update, secure, account, banking)
    - Alexa/Tranco rank (top sites check)
    - URL entropy
    - Special character ratio
    - Has port number
    - Number of query parameters
    - Longest word in path
    - Has punycode/IDN
    """
```

### Model Training:
- Use public datasets: PhishTank, OpenPhish, URLhaus, Kaggle phishing datasets
- Algorithm: Random Forest + Logistic Regression ensemble
- Target metrics: >96% accuracy

---

# SECTION F: AI CHATBOT ENGINE

## F.1 Implementation

```python
class SecurityChatbot:
    """
    AI-powered security assistant using OpenAI/Anthropic API.
    
    Capabilities:
    1. Answer security questions
    2. Explain vulnerabilities from scan results
    3. Provide remediation guidance with code examples
    4. Suggest secure coding practices
    5. Context-aware — can reference user's scan history
    """
    
    SYSTEM_PROMPT = """You are SafeWeb AI's security assistant. You are an expert in:
    - Web application security (OWASP Top 10)
    - Vulnerability assessment and remediation
    - Secure coding practices
    - Network security fundamentals
    - Compliance frameworks (PCI DSS, GDPR, SOC 2)
    
    Rules:
    - Provide actionable, specific remediation advice
    - Include code examples when relevant
    - Reference CWE IDs and OWASP categories
    - Be concise but thorough
    - If user provides scan context, reference their specific findings
    - Never provide advice on how to exploit vulnerabilities maliciously
    - Always recommend defensive measures
    """
    
    def chat(self, user_message: str, session_id: str, context: dict = None) -> str:
        messages = self._build_conversation_history(session_id)
        
        if context and context.get('scanId'):
            scan_context = self._get_scan_context(context['scanId'])
            messages.append({
                'role': 'system',
                'content': f'User is asking about scan results: {scan_context}'
            })
        
        messages.append({'role': 'user', 'content': user_message})
        
        response = self.client.chat.completions.create(
            model='gpt-4o-mini',  # or claude-3-haiku
            messages=messages,
            max_tokens=1000,
            temperature=0.7
        )
        
        return response.choices[0].message.content
```

---

# SECTION G: DJANGO PROJECT STRUCTURE

```
backend/
├── manage.py
├── requirements.txt
├── .env.example
├── .env
├── celery_app.py
├── config/
│   ├── __init__.py
│   ├── settings/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── development.py
│   │   └── production.py
│   ├── urls.py
│   ├── wsgi.py
│   └── asgi.py
├── apps/
│   ├── __init__.py
│   ├── accounts/
│   │   ├── __init__.py
│   │   ├── models.py          # User, APIKey, UserSession
│   │   ├── serializers.py     # Registration, Login, Profile serializers
│   │   ├── views.py           # Auth views, Profile views, API Key views
│   │   ├── urls.py
│   │   ├── permissions.py     # IsAdmin, IsOwner custom permissions
│   │   ├── backends.py        # Custom auth backend
│   │   ├── signals.py         # Post-login signals
│   │   ├── admin.py
│   │   └── tests.py
│   ├── scanning/
│   │   ├── __init__.py
│   │   ├── models.py          # Scan, Vulnerability, ScanReport
│   │   ├── serializers.py     # Scan create/detail/list serializers
│   │   ├── views.py           # Scan CRUD, export views
│   │   ├── urls.py
│   │   ├── tasks.py           # Celery async scan tasks
│   │   ├── admin.py
│   │   └── tests.py
│   │   └── engine/
│   │       ├── __init__.py
│   │       ├── orchestrator.py    # ScanOrchestrator
│   │       ├── crawler.py         # WebCrawler
│   │       ├── analyzers/
│   │       │   ├── __init__.py
│   │       │   ├── header_analyzer.py
│   │       │   ├── ssl_analyzer.py
│   │       │   └── cookie_analyzer.py
│   │       ├── testers/
│   │       │   ├── __init__.py
│   │       │   ├── base_tester.py      # Abstract base class
│   │       │   ├── sqli_tester.py      # SQL Injection
│   │       │   ├── xss_tester.py       # Cross-Site Scripting
│   │       │   ├── csrf_tester.py      # CSRF
│   │       │   ├── auth_tester.py      # Authentication flaws
│   │       │   ├── misconfig_tester.py # Security misconfiguration
│   │       │   ├── data_exposure_tester.py  # Sensitive data
│   │       │   ├── access_control_tester.py # Broken access control
│   │       │   ├── xxe_tester.py       # XXE
│   │       │   ├── deserialization_tester.py
│   │       │   ├── component_tester.py # Known vulnerable components
│   │       │   ├── logging_tester.py   # Logging & monitoring
│   │       │   └── ssrf_tester.py      # SSRF
│   │       ├── scoring.py             # CVSS calculator
│   │       └── report_generator.py    # PDF/JSON/CSV export
│   ├── ml/
│   │   ├── __init__.py
│   │   ├── models.py          # MLResult, MLModel registry
│   │   ├── serializers.py
│   │   ├── views.py           # ML admin views
│   │   ├── urls.py
│   │   ├── admin.py
│   │   ├── tests.py
│   │   └── engine/
│   │       ├── __init__.py
│   │       ├── malware_detector.py    # File malware detection
│   │       ├── phishing_detector.py   # URL phishing detection
│   │       ├── feature_extractors.py  # Feature extraction
│   │       ├── model_trainer.py       # Training pipeline
│   │       └── trained_models/        # Serialized model files (.pkl)
│   ├── chatbot/
│   │   ├── __init__.py
│   │   ├── models.py          # ChatMessage
│   │   ├── serializers.py
│   │   ├── views.py           # Chat endpoint
│   │   ├── urls.py
│   │   └── engine.py          # SecurityChatbot (LLM integration)
│   ├── admin_panel/
│   │   ├── __init__.py
│   │   ├── models.py          # SystemAlert, SystemSettings
│   │   ├── serializers.py
│   │   ├── views.py           # Admin dashboard, user mgmt, ML mgmt
│   │   ├── urls.py
│   │   └── permissions.py     # Admin-only permissions
│   └── learn/
│       ├── __init__.py
│       ├── models.py          # LearnArticle
│       ├── serializers.py
│       ├── views.py           # Article list/detail
│       ├── urls.py
│       └── admin.py
├── fixtures/
│   ├── articles.json          # Seed data for learning center
│   └── admin_user.json        # Default admin user
├── media/                     # User uploads
├── static/                    # Static files
└── ml_models/                 # Trained ML model files
```

---

# SECTION H: CONFIGURATION

## H.1 settings/base.py Key Configuration

```python
# CORS — must allow frontend origin
CORS_ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://localhost:3000",
]
CORS_ALLOW_CREDENTIALS = True

# JWT Configuration
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=15),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'AUTH_HEADER_TYPES': ('Bearer',),
}

# REST Framework
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '30/minute',
        'user': '120/minute',
        'scan': '10/hour',
    }
}

# Celery
CELERY_BROKER_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
CELERY_RESULT_BACKEND = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
CELERY_TASK_SERIALIZER = 'json'
CELERY_ACCEPT_CONTENT = ['json']

# File upload limits
FILE_UPLOAD_MAX_MEMORY_SIZE = 50 * 1024 * 1024  # 50MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 50 * 1024 * 1024

# Security
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
CSRF_COOKIE_HTTPONLY = True

# AI API
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')
ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY', '')
```

## H.2 .env.example

```env
# Django
SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database (production)
DATABASE_URL=sqlite:///db.sqlite3

# Redis (for Celery)
REDIS_URL=redis://localhost:6379/0

# JWT
JWT_ACCESS_LIFETIME_MINUTES=15
JWT_REFRESH_LIFETIME_DAYS=7

# Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# AI API (choose one)
OPENAI_API_KEY=your-openai-api-key
ANTHROPIC_API_KEY=your-anthropic-api-key

# Email (for password reset)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
EMAIL_USE_TLS=True

# File scanning
MAX_FILE_SIZE_MB=50
ALLOWED_FILE_TYPES=exe,dll,pdf,doc,docx,xls,xlsx,zip,rar,py,js,php

# Scan limits
MAX_CONCURRENT_SCANS=10
SCAN_TIMEOUT_SECONDS=3600
MAX_CRAWL_PAGES=200
```

## H.3 URL Routing (config/urls.py)

```python
urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('apps.accounts.urls')),
    path('api/user/', include('apps.accounts.profile_urls')),
    path('api/scan/', include('apps.scanning.urls')),
    path('api/scans', include('apps.scanning.list_urls')),
    path('api/dashboard', include('apps.scanning.dashboard_urls')),
    path('api/chat', include('apps.chatbot.urls')),
    path('api/admin/', include('apps.admin_panel.urls')),
    path('api/learn/', include('apps.learn.urls')),
]
```

---

# SECTION I: FRONTEND INTEGRATION REQUIREMENTS

The frontend is ALREADY BUILT. The backend MUST integrate seamlessly. Here are the critical requirements:

## I.1 Fix ScanWebsite.tsx Route Bug

The frontend `ScanWebsite.tsx` navigates to `/results/mock-scan-id` after scan submission. The route in `App.tsx` is `/scan/results/:id`. The backend should return the scan ID, and the frontend navigation should go to `/scan/results/${scanId}`. 

**The backend must return `id` in the scan creation response so the frontend can navigate to the results page.**

## I.2 Frontend Data Contracts (CRITICAL)

The backend serializers MUST output JSON using **camelCase** keys (not snake_case), because the React frontend uses camelCase. Use Django REST Framework's `CamelCaseJSONParser` and `CamelCaseJSONRenderer` from `djangorestframework-camel-case` package, OR manually define serializer field names.

Examples:
- `created_at` → `createdAt`
- `scan_type` → `scanType` (or just `type`)
- `affected_url` → `affectedUrl`
- `evidence_code` → `evidenceCode`
- `start_time` → `startTime`
- `end_time` → `endTime`
- `is_2fa_enabled` → `is2faEnabled`
- `last_login` → `lastLogin`
- `ml_result` → `mlResult`

## I.3 Authentication Token Storage

The frontend will store JWT tokens in localStorage. The backend response format for login/register MUST include:

```json
{
    "token": {
        "access": "eyJ...",
        "refresh": "eyJ..."
    },
    "id": "uuid",
    "email": "...",
    "name": "...",
    "role": "user"
}
```

## I.4 Error Response Format

All error responses MUST follow this format:
```json
{
    "detail": "Error message string",
    "errors": {
        "field_name": ["Error message for this field"]
    }
}
```

## I.5 CORS Configuration

The backend MUST accept requests from `http://localhost:5173` (Vite dev server) with credentials enabled.

---

# SECTION J: SECURITY REQUIREMENTS

## J.1 Backend Security Hardening

1. **Input Validation** on ALL endpoints — use Django serializer validators
2. **Rate Limiting** — login: 5/min, register: 3/min, scan: 10/hour, API: 120/min
3. **SQL Injection Prevention** — use Django ORM exclusively, never raw SQL
4. **XSS Prevention** — auto-escape all output, use bleach for user content
5. **CSRF Protection** — DRF uses JWT (stateless), so CSRF exempt for API, but enforce for session-based views
6. **File Upload Security** — validate file type, size limit (50MB), scan uploads with ClamAV or custom checks, never execute uploaded files
7. **Authentication** — bcrypt password hashing (Django default), JWT with short access token lifetime (15 min)
8. **Authorization** — custom permissions for admin, owner-only access to user data, superuser checks for admin endpoints
9. **Secure Headers** — HSTS, X-Content-Type-Options, X-Frame-Options, CSP
10. **Logging** — log all auth events, scan events, admin actions, errors
11. **Error Handling** — never expose stack traces in production, use custom exception handler
12. **Scan Safety** — the scanner must NOT store or display plaintext passwords, must sanitize evidence output

## J.2 Scan Engine Safety

The vulnerability scanner targets EXTERNAL websites that users submit. Safety measures:
1. **Timeout** — each scan has a maximum duration (configurable, default 1 hour)
2. **Rate limiting** — don't overwhelm target servers, add delay between requests
3. **Scope control** — only scan within the target domain unless subdomains enabled
4. **No destructive payloads** — never use DROP/DELETE SQL payloads on real targets, use detection-only payloads
5. **User agent** — identify as "SafeWeb AI Scanner" in User-Agent header
6. **robots.txt** — respect robots.txt unless explicitly overridden
7. **Legal disclaimer** — users must accept ToS before scanning (frontend already has this)

---

# SECTION K: TESTING REQUIREMENTS

## K.1 Unit Tests

Every module must have unit tests:
- **accounts/tests.py** — registration, login, JWT refresh, profile CRUD, API key management, 2FA
- **scanning/tests.py** — scan creation, status updates, vulnerability creation, scoring, report generation
- **ml/tests.py** — feature extraction, model loading, inference
- **chatbot/tests.py** — message handling, context injection
- **admin_panel/tests.py** — admin access control, user management, settings CRUD
- **learn/tests.py** — article CRUD, filtering, search

## K.2 Integration Tests

- Full scan workflow: create → process → complete → view results → export
- Auth flow: register → login → refresh → logout
- Admin flow: view dashboard → manage users → toggle ML models

## K.3 Test Fixtures

Create fixtures with seed data for:
- 1 admin user (admin@safeweb.ai / Admin@123)
- 3 regular users with different plans
- 6+ learning articles covering OWASP Top 10
- Sample scan results with vulnerabilities

---

# SECTION L: DEPLOYMENT & EXECUTION

## L.1 Setup Commands

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install dependencies
pip install -r requirements.txt

# Setup database
python manage.py migrate
python manage.py loaddata fixtures/admin_user.json
python manage.py loaddata fixtures/articles.json

# Create superuser (if not using fixture)
python manage.py createsuperuser

# Train ML models (first time)
python manage.py train_models

# Start Redis (required for Celery)
redis-server

# Start Celery worker
celery -A config worker -l info

# Start Django server
python manage.py runserver 8000
```

## L.2 requirements.txt

```
django>=5.0
djangorestframework>=3.15
djangorestframework-simplejwt>=5.3
djangorestframework-camel-case>=1.4
django-cors-headers>=4.3
django-allauth>=0.60
dj-rest-auth>=5.0
django-ratelimit>=4.1
django-filter>=24.1

celery>=5.3
redis>=5.0

requests>=2.31
beautifulsoup4>=4.12
lxml>=5.1
python-magic>=0.4  # or python-magic-bin on Windows
urllib3>=2.1

scikit-learn>=1.4
joblib>=1.3
numpy>=1.26
pandas>=2.2

reportlab>=4.1
Pillow>=10.2

openai>=1.12
anthropic>=0.18

python-dotenv>=1.0
bleach>=6.1
PyJWT>=2.8
pyotp>=2.9
qrcode>=7.4

gunicorn>=21.2
whitenoise>=6.6

pytest>=8.0
pytest-django>=4.8
factory-boy>=3.3
```

---

# SECTION M: CRITICAL REMINDERS

1. **EVERY endpoint must be fully implemented** — no stubs, no placeholders, no TODOs
2. **EVERY vulnerability tester must actually send payloads and analyze responses** — no mock scanning
3. **ML models must be trainable and produce real predictions** — include training scripts and sample data generation
4. **PDF export must generate a real, professional PDF report** — not a plaintext dump
5. **The chatbot must connect to a real AI API** — OpenAI or Anthropic, with proper system prompt and context injection
6. **camelCase JSON responses** — the React frontend expects camelCase, not snake_case
7. **JWT authentication on protected routes** — dashboard, scan, profile, admin all require auth
8. **Admin routes require admin role check** — not just authentication, but `role == 'admin'`
9. **Celery for async scanning** — scans run in background, frontend polls for status
10. **Proper error handling everywhere** — custom exception handler, meaningful error messages, proper HTTP status codes
11. **Seed data** — learning articles, default admin user, sample scan data for testing
12. **The scanner must be safe** — detection-only payloads, timeout limits, scope control, rate limiting to target
13. **All buttons must work** — export PDF, re-scan, delete scan, generate API key, revoke API key, change password, enable 2FA, admin actions

---

# END OF BACKEND DEVELOPMENT MASTER PROMPT

Use this prompt with Claude (or equivalent) to generate the COMPLETE, FUNCTIONAL, PRODUCTION-READY Django backend for SafeWeb AI. Every section is mandatory. No shortcuts. No placeholders. Enterprise-grade quality.
