import requests
import re
import logging
from bs4 import BeautifulSoup
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from typing import List
from pydantic import BaseModel, Field
import uuid

logger = logging.getLogger(__name__)

class VulnerabilityResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: str
    severity: str
    location: str
    description: str
    evidence: str
    recommendation: str

class ScanRequest(BaseModel):
    url: str
    scan_types: List[str] = ['sqli', 'xss', 'csrf']

class ScanResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    url: str
    scan_types: List[str]
    status: str
    vulnerabilities: List[VulnerabilityResult] = []
    ai_recommendations: List[str] = []
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    total_vulnerabilities: int = 0
    high_severity_count: int = 0
    medium_severity_count: int = 0
    low_severity_count: int = 0

def sanitize_url(url: str) -> str:
    """Remove trailing backslashes and normalize URL."""
    return url.rstrip('/\\').replace('\\', '/')

async def check_domain_exists(url: str) -> bool:
    """Check if the domain is reachable."""
    url = sanitize_url(url)
    try:
        response = requests.head(url, timeout=5, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0'})
        logging.debug(f"Domain check for {url}: Status {response.status_code}")
        return response.status_code in range(200, 400)
    except requests.RequestException as e:
        logging.error(f"Domain check failed for {url}: {str(e)}")
        return False

async def scan_sqli(url: str) -> List[VulnerabilityResult]:
    """Scan for SQL injection vulnerabilities using embedded payload testing."""
    vulnerabilities = []
    url = sanitize_url(url)
    sqli_payloads = [
        "' OR '1'='1' --",
        "1' OR '1'='1' --",
        "' UNION SELECT NULL, NULL, NULL --",
        "1' UNION SELECT username, password FROM users --",
        "' OR SLEEP(5) --",
        "1; DROP TABLE users; --",
        "' AND 1=0 UNION SELECT NULL, version() --",
        "' OR EXISTS(SELECT * FROM users) --",
        "1' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
        "' OR 1=1 LIMIT 1 OFFSET 0 --"
    ]
    error_patterns = [
        re.compile(r"mysql_fetch|mysql_error|You have an error in your SQL syntax", re.I),
        re.compile(r"pg_query|pg_exec|PostgreSQL.*error", re.I),
        re.compile(r"SQL Server|ODBC.*Microsoft|Invalid object name", re.I),
        re.compile(r"ORA-|Oracle error", re.I),
        re.compile(r"SQLITE_ERROR|SQLiteException", re.I),
        re.compile(r"DB2 SQL error|SQLCODE", re.I)
    ]
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    }

    try:
        # Fetch the page and find forms
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        logging.debug(f"Found {len(forms)} forms at {url} for SQLi scan")

        for form in forms:
            action = form.get('action', '')
            form_url = f"{url.rstrip('/')}/{action.lstrip('/')}" if action else url
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            params = {inp.get('name'): '' for inp in inputs if inp.get('name')}

            for payload in sqli_payloads:
                for key in params:
                    test_params = params.copy()
                    test_params[key] = payload
                    try:
                        start_time = datetime.now()
                        if method == 'post':
                            resp = requests.post(form_url, data=test_params, headers=headers, timeout=10)
                        else:
                            resp = requests.get(form_url, params=test_params, headers=headers, timeout=10)
                        response_time = (datetime.now() - start_time).total_seconds()

                        # Check for error-based SQLi
                        for pattern in error_patterns:
                            if pattern.search(resp.text):
                                vulnerabilities.append(VulnerabilityResult(
                                    type="SQLi",
                                    severity="High",
                                    location=form_url,
                                    description=f"SQL injection vulnerability detected with payload: {payload}",
                                    evidence=f"Database error detected: {resp.text[:200]}...",
                                    recommendation="Use parameterized queries, prepared statements, and input sanitization"
                                ))
                                break

                        # Check for time-based SQLi
                        if 'SLEEP' in payload and response_time >= 4.5:
                            vulnerabilities.append(VulnerabilityResult(
                                type="SQLi",
                                severity="High",
                                location=form_url,
                                description=f"Time-based SQL injection vulnerability detected with payload: {payload}",
                                evidence=f"Response delayed by {response_time:.2f} seconds",
                                recommendation="Implement prepared statements and validate inputs"
                            ))

                    except requests.RequestException as e:
                        logging.error(f"SQLi test failed for {form_url} with payload {payload}: {str(e)}")

    except requests.RequestException as e:
        logging.error(f"SQLi scan failed for {url}: {str(e)}")
    return vulnerabilities

async def scan_xss(url: str) -> List[VulnerabilityResult]:
    """Scan for XSS vulnerabilities using embedded payload testing."""
    vulnerabilities = []
    url = sanitize_url(url)
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "'><script>alert('XSS')</script>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<input value='XSS' onfocus=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')></iframe>",
        "<object data=javascript:alert('XSS')>",
        "<embed src=javascript:alert('XSS')>"
    ]
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    }

    try:
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')

        for form in forms:
            action = form.get('action', '')
            form_url = f"{url.rstrip('/')}/{action.lstrip('/')}" if action else url
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            params = {inp.get('name'): '' for inp in inputs if inp.get('name')}

            for payload in xss_payloads:
                for key in params:
                    test_params = params.copy()
                    test_params[key] = payload
                    try:
                        if method == 'post':
                            resp = requests.post(form_url, data=test_params, headers=headers, timeout=10)
                        else:
                            resp = requests.get(form_url, params=test_params, headers=headers, timeout=10)

                        # Check if payload is reflected in response
                        if payload in resp.text:
                            vulnerabilities.append(VulnerabilityResult(
                                type="XSS",
                                severity="High",
                                location=form_url,
                                description=f"Cross-site scripting vulnerability detected with payload: {payload}",
                                evidence=f"Payload reflected in response: {resp.text[:200]}...",
                                recommendation="Implement proper input validation and output encoding"
                            ))

                    except requests.RequestException as e:
                        logging.error(f"XSS test failed for {form_url} with payload {payload}: {str(e)}")

    except requests.RequestException as e:
        logging.error(f"XSS scan failed for {url}: {str(e)}")
    return vulnerabilities

async def scan_csrf(url: str) -> List[VulnerabilityResult]:
    """Scan for CSRF vulnerabilities."""
    vulnerabilities = []
    url = sanitize_url(url)
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    }

    try:
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')

        for form in forms:
            # Check for CSRF tokens
            csrf_tokens = form.find_all('input', {'name': re.compile(r'csrf|token|_token', re.I)})
            
            if not csrf_tokens:
                action = form.get('action', '')
                form_url = f"{url.rstrip('/')}/{action.lstrip('/')}" if action else url
                
                vulnerabilities.append(VulnerabilityResult(
                    type="CSRF",
                    severity="Medium",
                    location=form_url,
                    description="Form lacks CSRF protection token",
                    evidence="No CSRF token found in form",
                    recommendation="Implement CSRF tokens for all state-changing operations"
                ))

    except requests.RequestException as e:
        logging.error(f"CSRF scan failed for {url}: {str(e)}")
    return vulnerabilities

