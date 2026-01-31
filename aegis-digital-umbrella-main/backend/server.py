import os
import sys
from pathlib import Path
import yaml
import requests
from bs4 import BeautifulSoup
import logging
import re
from fastapi import FastAPI, APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field
from typing import List, Optional
import uuid
from datetime import datetime, timedelta
import asyncio
import bcrypt
import io
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from urllib.parse import urlparse, parse_qs, urljoin
import html

# --- UPDATED AI IMPORTS (Required for Gemini 3) ---
from google import genai
from google.genai import types

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('debug.log')
    ]
)
logger = logging.getLogger(__name__)

# --- FIXED CONFIG PATH ---
# Uses the current file's directory instead of a hardcoded path
ROOT_DIR = Path(__file__).parent
CONFIG_PATH = ROOT_DIR / ".emergent"

def load_emergent_config():
    """Load configuration from .emergent YAML file"""
    try:
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH, 'r') as f:
                return yaml.safe_load(f) or {}
        return {}
    except Exception as e:
        logging.warning(f"Config load error: {str(e)}")
        return {}

# --- Gemini AI Integration (UPDATED FOR GEMINI 3 FLASH) ---
class LlmChat:
    def __init__(self, api_key: str, session_id: str, system_message: str):
        self.config = load_emergent_config()
        self.api_key = api_key or os.getenv('GEMINI_API_KEY', '')
        if not self.api_key:
            raise ValueError("Gemini API key is required")
        self.session_id = session_id
        self.system_message = system_message
        
        # Initialize the new Client
        self.client = genai.Client(api_key=self.api_key)
        
        # SETTING: Default to Gemini 3 Flash Preview
        self.model_name = 'gemini-3-flash-preview'

    def with_model(self, provider: str, model: str):
        self.model_name = model
        return self

    async def send_message(self, message):
        """
        Sends a message to Gemini with automatic fallbacks for stability.
        Priority: Gemini 3 Flash -> Gemini 2.0 Flash -> Gemini 1.5 Flash
        """
        # List of models to try in order of preference
        models_to_try = [
            self.model_name,          # The requested model (default: gemini-3-flash-preview)
            'gemini-2.0-flash-exp',   # Fallback 1: High speed experimental
            'gemini-1.5-flash'        # Fallback 2: Stable legacy
        ]

        last_error = None

        for model in models_to_try:
            try:
                logging.debug(f"Attempting to generate response using {model}...")
                
                # Create chat using the new SDK structure
                chat = self.client.chats.create(
                    model=model,
                    config=types.GenerateContentConfig(
                        system_instruction=self.system_message,
                        temperature=0.7
                    )
                )
                response = await asyncio.to_thread(chat.send_message, message.text)
                logging.info(f"Successfully generated response using {model}")
                return response.text

            except Exception as e:
                error_msg = str(e)
                last_error = error_msg
                logging.warning(f"Failed to use {model}: {error_msg}")
                
                # If it's a 404 (Not Found) or 429 (Rate Limit), try the next model
                if "404" in error_msg or "429" in error_msg or "503" in error_msg:
                    continue
                else:
                    # For other errors (like auth), fail immediately
                    return f"[ERROR] AI Error ({model}): {error_msg}"
        
        return f"[ERROR] All AI models failed. Last error: {last_error}"

class UserMessage:
    def __init__(self, text: str):
        self.text = text

load_dotenv(ROOT_DIR / '.env')


# MongoDB connection
mongo_url = os.environ['MONGODB_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Enhanced Models
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: str
    password: str
    full_name: Optional[str] = None
    company: Optional[str] = None
    phone: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None
    is_active: bool = True
    reset_token: Optional[str] = None
    reset_token_expires: Optional[datetime] = None

class UserCreate(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = None
    company: Optional[str] = None
    phone: Optional[str] = None

class UserLogin(BaseModel):
    email: str
    password: str

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    company: Optional[str] = None
    phone: Optional[str] = None

class PasswordChange(BaseModel):
    current_password: str
    new_password: str

class PasswordReset(BaseModel):
    email: str

class PasswordResetConfirm(BaseModel):
    reset_token: str
    new_password: str

class ChatMessage(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    message: str
    response: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class ChatRequest(BaseModel):
    message: str
    user_id: str

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

class DashboardStats(BaseModel):
    total_scans: int
    active_scans: int
    total_vulnerabilities: int
    high_risk_vulnerabilities: int

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def generate_reset_token() -> str:
    return str(uuid.uuid4())

def sanitize_url(url: str) -> str:
    """Remove trailing backslashes and normalize URL."""
    return url.rstrip('/\\').replace('\\', '/')

def sanitize_text_for_pdf(text: str) -> str:
    """Sanitize text for ReportLab by removing HTML tags and special characters."""
    if not text:
        return "No content available"
    try:
        # Log raw text for debugging
        logger.debug(f"Raw text before sanitization: {text[:200]}")
        
        # Remove HTML tags using regex
        clean_text = re.sub(r'<[^>]+>', '', text)
        # Escape remaining HTML entities
        clean_text = html.escape(clean_text)
        # Replace problematic characters
        clean_text = clean_text.replace('\r', '').replace('\n', ' ').replace('\t', ' ')
        # Remove control characters
        clean_text = re.sub(r'[\x00-\x1F\x7F]', '', clean_text)
        # Truncate to avoid overwhelming ReportLab
        clean_text = clean_text[:1000]
        # Log sanitized text
        logger.debug(f"Sanitized text: {clean_text[:200]}")
        return clean_text if clean_text.strip() else "No content available"
    except Exception as e:
        logger.error(f"Sanitization error: {str(e)}")
        return "Error processing content"

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
            form_url = urljoin(url, action) if action else url
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            params = {inp.get('name'): '' for inp in inputs if inp.get('name')}
            logging.debug(f"Form at {form_url}: Method={method}, Params={params}")

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
                        logging.debug(f"Tested SQLi payload {payload} on {form_url}: Status {resp.status_code}, Time {response_time:.2f}s")

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

                        # Check for union-based SQLi
                        if 'UNION SELECT' in payload and ('username' in resp.text.lower() or 'password' in resp.text.lower()):
                            vulnerabilities.append(VulnerabilityResult(
                                type="SQLi",
                                severity="High",
                                location=form_url,
                                description=f"Union-based SQL injection vulnerability detected with payload: {payload}",
                                evidence=f"Potential data leakage in response: {resp.text[:200]}...",
                                recommendation="Restrict database permissions and use parameterized queries"
                            ))

                    except requests.RequestException as e:
                        logging.error(f"SQLi test failed for {form_url} with payload {payload}: {str(e)}")

        # Check URL parameters for SQLi
        parsed_url = urlparse(url)
        if parsed_url.query:
            params = {k: v[0] for k, v in parse_qs(parsed_url.query).items()}
            for key in params:
                for payload in sqli_payloads:
                    test_params = params.copy()
                    test_params[key] = payload
                    try:
                        start_time = datetime.now()
                        resp = requests.get(url, params=test_params, headers=headers, timeout=10)
                        response_time = (datetime.now() - start_time).total_seconds()
                        logging.debug(f"Tested SQLi URL param {key}={payload} on {url}: Status {resp.status_code}, Time {response_time:.2f}s")

                        for pattern in error_patterns:
                            if pattern.search(resp.text):
                                vulnerabilities.append(VulnerabilityResult(
                                    type="SQLi",
                                    severity="High",
                                    location=url,
                                    description=f"SQL injection vulnerability in URL parameter with payload: {payload}",
                                    evidence=f"Database error detected: {resp.text[:200]}...",
                                    recommendation="Sanitize and validate URL parameters"
                                ))
                                break

                        if 'SLEEP' in payload and response_time >= 4.5:
                            vulnerabilities.append(VulnerabilityResult(
                                type="SQLi",
                                severity="High",
                                location=url,
                                description=f"Time-based SQL injection in URL parameter with payload: {payload}",
                                evidence=f"Response delayed by {response_time:.2f} seconds",
                                recommendation="Use parameterized queries for dynamic inputs"
                            ))

                        if 'UNION SELECT' in payload and ('username' in resp.text.lower() or 'password' in resp.text.lower()):
                            vulnerabilities.append(VulnerabilityResult(
                                type="SQLi",
                                severity="High",
                                location=url,
                                description=f"Union-based SQL injection in URL parameter with payload: {payload}",
                                evidence=f"Potential data leakage in response: {resp.text[:200]}...",
                                recommendation="Restrict database permissions and validate inputs"
                            ))

                    except requests.RequestException as e:
                        logging.error(f"SQLi test failed for {url} with payload {payload}: {str(e)}")

        if not vulnerabilities:
            logging.info(f"No SQLi vulnerabilities found for {url}")
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
        "<a href='javascript:alert(\"XSS\")'>Click</a>",
        "<iframe src='javascript:alert(\"XSS\")'>",
        "'';!--\"<XSS>=&{()}",
        "<script>document.write('XSS')</script>",
        "<img src='javascript:alert(\"XSS\")'>"
    ]
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    }

    scan_urls = []
    if "testphp.vulnweb.com" in url.lower():
        scan_urls = [
            url,
            f"{url.rstrip('/')}/search.php",
            f"{url.rstrip('/')}/listproducts.php",
            f"{url.rstrip('/')}/userinfo.php",
            f"{url.rstrip('/')}/index.php",
            f"{url.rstrip('/')}/guestbook.php"
        ]
    elif "xss-game.appspot.com" in url.lower():
        scan_urls = [
            f"{url.rstrip('/')}/level1",
            f"{url.rstrip('/')}/level2",
            f"{url.rstrip('/')}/level3",
            f"{url.rstrip('/')}/level4",
            f"{url.rstrip('/')}/level5/signup",
            f"{url.rstrip('/')}/level6"
        ]
    else:
        scan_urls = [url]

    for scan_url in scan_urls:
        try:
            response = requests.get(scan_url, headers=headers, timeout=10, allow_redirects=True)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            logging.debug(f"Found {len(forms)} forms at {scan_url}")

            for form in forms:
                action = form.get('action', '')
                form_url = urljoin(scan_url, action) if action else scan_url
                method = form.get('method', 'get').lower()
                inputs = form.find_all('input')
                params = {inp.get('name'): '' for inp in inputs if inp.get('name')}
                logging.debug(f"Form at {form_url}: Method={method}, Params={params}")

                for payload in xss_payloads:
                    for key in params:
                        test_params = params.copy()
                        test_params[key] = payload
                        try:
                            if method == 'post':
                                resp = requests.post(form_url, data=test_params, headers=headers, timeout=10)
                            else:
                                resp = requests.get(form_url, params=test_params, headers=headers, timeout=10)
                            logging.debug(f"Tested payload {payload} on {form_url}: Status {resp.status_code}")
                            
                            if any(p in resp.text for p in [payload, 'alert(', 'document.write']):
                                vulnerabilities.append(VulnerabilityResult(
                                    type="XSS",
                                    severity="Medium",
                                    location=form_url,
                                    description=f"Reflected XSS vulnerability detected with payload: {payload}",
                                    evidence=f"Payload reflected in response: {resp.text[:200]}...",
                                    recommendation="Implement output encoding (e.g., HTML escape), Content Security Policy, and input validation"
                                ))
                        except requests.RequestException as e:
                            logging.error(f"XSS test failed for {form_url} with payload {payload}: {str(e)}")

            parsed_url = urlparse(scan_url)
            if parsed_url.query:
                params = {k: v[0] for k, v in parse_qs(parsed_url.query).items()}
                for key in params:
                    for payload in xss_payloads:
                        test_params = params.copy()
                        test_params[key] = payload
                        try:
                            resp = requests.get(scan_url, params=test_params, headers=headers, timeout=10)
                            logging.debug(f"Tested URL param {key}={payload} on {scan_url}: Status {resp.status_code}")
                            if any(p in resp.text for p in [payload, 'alert(', 'document.write']):
                                vulnerabilities.append(VulnerabilityResult(
                                    type="XSS",
                                    severity="Medium",
                                    location=scan_url,
                                    description=f"Reflected XSS vulnerability detected in URL parameter with payload: {payload}",
                                    evidence=f"Payload reflected in response: {resp.text[:200]}...",
                                    recommendation="Sanitize and validate URL parameters, use CSP"
                                ))
                        except requests.RequestException as e:
                            logging.error(f"XSS test failed for {scan_url} with payload {payload}: {str(e)}")

            logging.info(f"Completed XSS scan for {scan_url}")
        except requests.RequestException as e:
            logging.error(f"XSS scan failed for {scan_url}: {str(e)}")
    return vulnerabilities

async def scan_csrf(url: str) -> List[VulnerabilityResult]:
    """Scan for CSRF vulnerabilities."""
    vulnerabilities = []
    url = sanitize_url(url)
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        logging.debug(f"Found {len(forms)} forms for CSRF scan at {url}")

        for form in forms:
            action = form.get('action', '')
            form_url = urljoin(url, action) if action else url
            has_csrf_token = bool(form.find('input', {'name': re.compile(r'csrf|token|_token|authenticity', re.I)}))
            has_custom_protection = bool(soup.find('script', text=re.compile(r'csrf|x-csrf|xsrf|authenticity', re.I)))
            cookies = response.cookies
            has_samesite = any(cookie.samesite in ['Strict', 'Lax'] for cookie in cookies if cookie.samesite)
            has_header_protection = any(h.lower() in response.headers for h in ['x-csrf-token', 'x-xsrf-token', 'x-authenticity-token'])

            if not (has_csrf_token or has_samesite or has_custom_protection or has_header_protection):
                vulnerabilities.append(VulnerabilityResult(
                    type="CSRF",
                    severity="High",
                    location=form_url,
                    description="Form lacks CSRF protection",
                    evidence="No CSRF token, SameSite cookie, or custom header protection detected",
                    recommendation="Implement CSRF tokens, set SameSite cookie attributes, and use custom headers"
                ))
            else:
                logging.info(f"CSRF protection detected for form at {form_url}")
        if not forms:
            logging.info(f"No forms found for CSRF scanning at {url}")
    except requests.RequestException as e:
        logging.error(f"CSRF scan failed for {url}: {str(e)}")
    return vulnerabilities

async def simulate_vulnerability_scan(url: str, scan_types: List[str]) -> List[VulnerabilityResult]:
    """Simulate vulnerability scans for the specified URL."""
    url = sanitize_url(url)
    if not await check_domain_exists(url):
        logging.warning(f"Domain {url} does not exist or is unreachable. Skipping scan.")
        return []
    vulnerabilities = []
    tasks = []
    if 'sqli' in scan_types:
        tasks.append(scan_sqli(url))
    if 'xss' in scan_types:
        tasks.append(scan_xss(url))
    if 'csrf' in scan_types:
        tasks.append(scan_csrf(url))
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, list):
            vulnerabilities.extend(result)
        else:
            logging.error(f"Scan error: {str(result)}")
    
    logging.info(f"Found {len(vulnerabilities)} vulnerabilities for {url}")
    return vulnerabilities

async def generate_ai_recommendations(vulnerabilities: List[VulnerabilityResult]) -> List[str]:
    """Generate AI-powered remediation recommendations."""
    if not vulnerabilities:
        logging.info("No vulnerabilities found, skipping AI recommendations")
        return []
    try:
        vuln_summary = [f"{vuln.type.upper()} - {vuln.severity}: {vuln.description} at {vuln.location}" for vuln in vulnerabilities]
        vulnerability_text = "\n".join(vuln_summary)
        chat = LlmChat(
            api_key=os.environ.get('GEMINI_API_KEY'),
            session_id=f"vulnerability_analysis_{uuid.uuid4()}",
            system_message="""You are a cybersecurity expert specializing in web application security. 
            Analyze vulnerability scan results and provide specific, actionable remediation recommendations.
            Focus on practical steps developers can take to fix each vulnerability type."""
        ) # Initialized with default model (Gemini 3 Flash)
        
        user_message = UserMessage(
            text=f"""Analyze these web application vulnerabilities and provide 5-7 specific, actionable remediation recommendations:

{vulnerability_text}

Please provide practical, developer-friendly recommendations that address:
1. Immediate fixes for high-severity issues
2. Input validation and sanitization strategies
3. Security configuration improvements
4. Code-level changes needed
5. Long-term security hardening measures

Format each recommendation as a clear, actionable bullet point."""
        )
        response = await chat.send_message(user_message)
        recommendations = [line.strip().lstrip('•-*0123456789. ') for line in response.split('\n') if line.strip() and (line.startswith('•') or line.startswith('-') or line.startswith('*') or line[0].isdigit())]
        return recommendations[:7]
    except Exception as e:
        logging.error(f"AI recommendation generation failed: {e}")
        return []

async def generate_chatbot_response(message: str, user_id: str = None) -> str:
    """Generate chatbot responses for user queries."""
    try:
        chat = LlmChat(
            api_key=os.environ.get('GEMINI_API_KEY'),
            session_id=f"chatbot_{user_id or uuid.uuid4()}",
            system_message="""You are AEGIS AI, a cybersecurity expert assistant. Provide accurate, concise, and practical answers to cybersecurity-related questions."""
        ) # Initialized with default model (Gemini 3 Flash)
        
        user_message = UserMessage(text=message)
        response = await chat.send_message(user_message)
        logging.info(f"Generated response for user {user_id or 'anonymous'}")
        return response.strip()
    except ValueError as e:
        logging.error(f"Configuration error: {str(e)}")
        return "System configuration error. Please contact support."
    except Exception as e:
        logging.error(f"Chatbot error - {type(e).__name__}: {str(e)}")
        return "I'm having technical difficulties. Please try again later or contact support."

def generate_pdf_report(scan_result: ScanResult) -> io.BytesIO:
    """Generate a PDF report for the scan results."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=1,
        textColor=colors.darkblue
    )
    normal_style = styles['Normal']
    normal_style.leading = 14
    normal_style.fontSize = 10
    story = []
    
    # Add report header
    story.append(Paragraph("AEGIS Digital Umbrella", title_style))
    story.append(Paragraph("Cybersecurity Vulnerability Report", styles['Heading2']))
    story.append(Spacer(1, 20))
    
    # Scan information table
    scan_info = [
        ['Scan ID:', scan_result.id],
        ['Target URL:', sanitize_text_for_pdf(scan_result.url)],
        ['Scan Date:', scan_result.created_at.strftime('%Y-%m-%d %H:%M:%S')],
        ['Scan Types:', ', '.join([t.upper() for t in scan_result.scan_types])],
        ['Status:', scan_result.status.upper()],
        ['Total Vulnerabilities:', str(scan_result.total_vulnerabilities)]
    ]
    scan_table = Table(scan_info, colWidths=[2*inch, 4*inch])
    scan_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('BACKGROUND', (1, 0), (1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(scan_table)
    story.append(Spacer(1, 20))
    
    # Vulnerability summary table
    story.append(Paragraph("Vulnerability Summary", styles['Heading2']))
    summary_data = [
        ['High Severity', str(scan_result.high_severity_count)],
        ['Medium Severity', str(scan_result.medium_severity_count)],
        ['Low Severity', str(scan_result.low_severity_count)],
        ['Total', str(scan_result.total_vulnerabilities)]
    ]
    summary_table = Table(summary_data, colWidths=[3*inch, 1*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))
    
    # Detailed vulnerability analysis
    if scan_result.vulnerabilities:
        story.append(Paragraph("Detailed Vulnerability Analysis", styles['Heading2']))
        for i, vuln in enumerate(scan_result.vulnerabilities, 1):
            try:
                # Sanitize all fields
                location = sanitize_text_for_pdf(vuln.location)
                description = sanitize_text_for_pdf(vuln.description)
                evidence = sanitize_text_for_pdf(vuln.evidence)
                recommendation = sanitize_text_for_pdf(vuln.recommendation)
                
                # Add vulnerability details
                story.append(Paragraph(f"{i}. {vuln.type} - {vuln.severity} Severity", styles['Heading3']))
                story.append(Paragraph(f"<b>Location:</b> {location}", normal_style))
                story.append(Paragraph(f"<b>Description:</b> {description}", normal_style))
                story.append(Paragraph(f"<b>Evidence:</b> {evidence}", normal_style))
                story.append(Paragraph(f"<b>Recommendation:</b> {recommendation}", normal_style))
                story.append(Spacer(1, 10))
            except Exception as e:
                logger.error(f"Error processing vulnerability {i} (ID: {vuln.id}): {str(e)}")
                story.append(Paragraph(f"Error processing vulnerability {i}: Content could not be processed", normal_style))
                story.append(Spacer(1, 10))
    
    # AI-powered recommendations
    if scan_result.ai_recommendations:
        story.append(Paragraph("AI-Powered Security Recommendations", styles['Heading2']))
        for i, rec in enumerate(scan_result.ai_recommendations, 1):
            try:
                sanitized_rec = sanitize_text_for_pdf(rec)
                story.append(Paragraph(f"{i}. {sanitized_rec}", normal_style))
                story.append(Spacer(1, 8))
            except Exception as e:
                logger.error(f"Error processing recommendation {i}: {str(e)}")
                story.append(Paragraph(f"Error processing recommendation {i}: Content could not be processed", normal_style))
                story.append(Spacer(1, 8))
    
    # Footer
    story.append(Spacer(1, 20))
    story.append(Paragraph("Generated by AEGIS Digital Umbrella - Cybersecurity Vulnerability Scanner", normal_style))
    story.append(Paragraph(f"Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    
    try:
        doc.build(story)
    except Exception as e:
        logger.error(f"PDF generation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {str(e)}")
    
    buffer.seek(0)
    return buffer

@api_router.post("/auth/register")
async def register(user_data: UserCreate):
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = hash_password(user_data.password)
    user = User(**user_data.dict())
    user.password = hashed_password
    await db.users.insert_one(user.dict())
    return {"message": "User registered successfully", "user_id": user.id}

@api_router.post("/auth/login")
async def login(login_data: UserLogin):
    user = await db.users.find_one({"email": login_data.email})
    if not user or not verify_password(login_data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    await db.users.update_one(
        {"id": user["id"]}, 
        {"$set": {"last_login": datetime.utcnow()}}
    )
    return {
        "message": "Login successful", 
        "user_id": user["id"], 
        "email": user["email"],
        "full_name": user.get("full_name"),
        "company": user.get("company")
    }

@api_router.post("/auth/forgot-password")
async def forgot_password(reset_data: PasswordReset):
    user = await db.users.find_one({"email": reset_data.email})
    if not user:
        return {"message": "If the email exists, a reset link has been sent"}
    reset_token = generate_reset_token()
    expires_at = datetime.utcnow() + timedelta(hours=1)
    await db.users.update_one(
        {"id": user["id"]},
        {"$set": {"reset_token": reset_token, "reset_token_expires": expires_at}}
    )
    return {"message": "Password reset token generated", "reset_token": reset_token}

@api_router.post("/auth/reset-password")
async def reset_password(reset_data: PasswordResetConfirm):
    user = await db.users.find_one({
        "reset_token": reset_data.reset_token,
        "reset_token_expires": {"$gt": datetime.utcnow()}
    })
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    hashed_password = hash_password(reset_data.new_password)
    await db.users.update_one(
        {"id": user["id"]},
        {"$set": {
            "password": hashed_password,
            "reset_token": None,
            "reset_token_expires": None
        }}
    )
    return {"message": "Password reset successful"}

@api_router.get("/user/profile/{user_id}")
async def get_user_profile(user_id: str):
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.pop("password", None)
    user.pop("reset_token", None)
    user.pop("reset_token_expires", None)
    user.pop("_id", None)
    return user

@api_router.put("/user/profile/{user_id}")
async def update_user_profile(user_id: str, update_data: UserUpdate):
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    update_dict = {k: v for k, v in update_data.dict().items() if v is not None}
    if update_dict:
        await db.users.update_one({"id": user_id}, {"$set": update_dict})
    return {"message": "Profile updated successfully"}

@api_router.post("/user/change-password/{user_id}")
async def change_password(user_id: str, password_data: PasswordChange):
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not verify_password(password_data.current_password, user["password"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    new_hashed_password = hash_password(password_data.new_password)
    await db.users.update_one(
        {"id": user_id},
        {"$set": {"password": new_hashed_password}}
    )
    return {"message": "Password changed successfully"}

@api_router.post("/scan")
async def start_scan(scan_request: ScanRequest, user_id: str = "demo_user"):
    scan = ScanResult(
        user_id=user_id,
        url=sanitize_url(scan_request.url),
        scan_types=scan_request.scan_types,
        status="running"
    )
    await db.scans.insert_one(scan.dict())
    try:
        vulnerabilities = await simulate_vulnerability_scan(scan_request.url, scan_request.scan_types)
        ai_recommendations = await generate_ai_recommendations(vulnerabilities)
        high_count = sum(1 for v in vulnerabilities if v.severity == "High")
        medium_count = sum(1 for v in vulnerabilities if v.severity == "Medium")
        low_count = sum(1 for v in vulnerabilities if v.severity == "Low")
        scan.vulnerabilities = vulnerabilities
        scan.ai_recommendations = ai_recommendations
        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        scan.total_vulnerabilities = len(vulnerabilities)
        scan.high_severity_count = high_count
        scan.medium_severity_count = medium_count
        scan.low_severity_count = low_count
        await db.scans.replace_one({"id": scan.id}, scan.dict())
        return scan
    except Exception as e:
        await db.scans.update_one(
            {"id": scan.id}, 
            {"$set": {"status": "failed", "completed_at": datetime.utcnow()}}
        )
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@api_router.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    scan = await db.scans.find_one({"id": scan_id})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResult(**scan)

@api_router.get("/scans")
async def get_user_scans(user_id: str = "demo_user"):
    scans = await db.scans.find({"user_id": user_id}).sort("created_at", -1).to_list(50)
    return [ScanResult(**scan) for scan in scans]

@api_router.get("/dashboard/stats")
async def get_dashboard_stats(user_id: str = "demo_user"):
    scans = await db.scans.find({"user_id": user_id}).to_list(1000)
    total_scans = len(scans)
    active_scans = len([s for s in scans if s.get("status") in ["pending", "running"]])
    total_vulnerabilities = 0
    high_risk_count = 0
    for scan in scans:
        if scan.get("vulnerabilities"):
            total_vulnerabilities += len(scan["vulnerabilities"])
            high_risk_count += len([v for v in scan["vulnerabilities"] if v.get("severity") == "High"])
    return DashboardStats(
        total_scans=total_scans,
        active_scans=active_scans,
        total_vulnerabilities=total_vulnerabilities,
        high_risk_vulnerabilities=high_risk_count
    )

@api_router.delete("/user/profile/{user_id}")
async def delete_user_profile(user_id: str):
    try:
        user = await db.users.find_one({"id": user_id})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        await db.scans.delete_many({"user_id": user_id})
        await db.chat_history.delete_many({"user_id": user_id})
        result = await db.users.delete_one({"id": user_id})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="User not found")
        return {"message": "User profile deleted successfully", "deleted_user_id": user_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete user profile: {str(e)}")

@api_router.get("/scans/history/{user_id}")
async def get_scan_history(user_id: str, limit: int = 100):
    try:
        scans = await db.scans.find({"user_id": user_id}).sort("created_at", -1).limit(limit).to_list(limit)
        return [ScanResult(**scan) for scan in scans]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve scan history: {str(e)}")

@api_router.get("/scans/history/{user_id}/download")
async def download_scan_history(user_id: str, format: str = "pdf"):
    try:
        scans = await db.scans.find({"user_id": user_id}).sort("created_at", -1).to_list(1000)
        if not scans:
            raise HTTPException(status_code=404, detail="No scan history found")
        if format.lower() == "csv":
            return await generate_csv_history(scans, user_id)
        else:
            return await generate_pdf_history(scans, user_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to download scan history: {str(e)}")

async def generate_csv_history(scans: List[dict], user_id: str) -> StreamingResponse:
    import csv
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Scan ID', 'URL', 'Date', 'Status', 'Total Vulnerabilities', 
        'High Severity', 'Medium Severity', 'Low Severity', 'Scan Types'
    ])
    for scan in scans:
        writer.writerow([
            scan.get('id', ''),
            scan.get('url', ''),
            scan.get('created_at', ''),
            scan.get('status', ''),
            scan.get('total_vulnerabilities', 0),
            scan.get('high_severity_count', 0),
            scan.get('medium_severity_count', 0),
            scan.get('low_severity_count', 0),
            ', '.join(scan.get('scan_types', []))
        ])
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode('utf-8')),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=aegis_scan_history_{user_id}.csv"}
    )

async def generate_pdf_history(scans: List[dict], user_id: str) -> StreamingResponse:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=1,
        textColor=colors.darkblue
    )
    story = []
    story.append(Paragraph("AEGIS Digital Umbrella", title_style))
    story.append(Paragraph("Scan History Report", styles['Heading2']))
    story.append(Spacer(1, 20))
    total_scans = len(scans)
    total_vulns = sum(scan.get('total_vulnerabilities', 0) for scan in scans)
    summary_data = [
        ['Total Scans:', str(total_scans)],
        ['Total Vulnerabilities Found:', str(total_vulns)],
        ['Report Generated:', datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')]
    ]
    summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))
    story.append(Paragraph("Detailed Scan History", styles['Heading2']))
    history_data = [['Date', 'URL', 'Status', 'Vulnerabilities']]
    for scan in scans[:50]:
        history_data.append([
            scan.get('created_at', '')[:10] if scan.get('created_at') else '',
            scan.get('url', '')[:40] + '...' if len(scan.get('url', '')) > 40 else scan.get('url', ''),
            scan.get('status', '').upper(),
            str(scan.get('total_vulnerabilities', 0))
        ])
    history_table = Table(history_data, colWidths=[1.5*inch, 2.5*inch, 1*inch, 1*inch])
    history_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
    ]))
    story.append(history_table)
    doc.build(story)
    buffer.seek(0)
    return StreamingResponse(
        io.BytesIO(buffer.read()),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=aegis_scan_history_{user_id}.pdf"}
    )

@api_router.get("/scan/{scan_id}/report")
async def download_report(scan_id: str):
    scan = await db.scans.find_one({"id": scan_id})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan_result = ScanResult(**scan)
    pdf_buffer = generate_pdf_report(scan_result)
    return StreamingResponse(
        io.BytesIO(pdf_buffer.read()),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=aegis_scan_report_{scan_id}.pdf"}
    )

@api_router.post("/chat")
async def chat_with_ai(chat_request: ChatRequest):
    try:
        response = await generate_chatbot_response(chat_request.message)
        chat_message = ChatMessage(
            user_id=chat_request.user_id,
            message=chat_request.message,
            response=response
        )
        await db.chat_history.insert_one(chat_message.dict())
        return {"response": response, "message_id": chat_message.id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chat failed: {str(e)}")

@api_router.get("/chat/history/{user_id}")
async def get_chat_history(user_id: str, limit: int = 50):
    chats = await db.chat_history.find({"user_id": user_id}).sort("timestamp", -1).limit(limit).to_list(limit)
    return [ChatMessage(**chat) for chat in chats]

@api_router.get("/")
async def root():
    return {"message": "AEGIS Digital Umbrella API - Enhanced Cybersecurity Vulnerability Scanner"}

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
  client.close()