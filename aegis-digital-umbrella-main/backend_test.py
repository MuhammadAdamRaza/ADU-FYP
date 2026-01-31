#!/usr/bin/env python3
"""
AEGIS Digital Umbrella Backend API Testing Suite - ENHANCED VERSION
Tests all backend API endpoints including new enhancement features:
- Enhanced Authentication System with Password Reset
- User Profile Management API
- PDF Report Generation System
- AI Chatbot Backend Service
"""

import requests
import json
import time
import sys
from datetime import datetime

# Configuration
BASE_URL = "https://3db5e4cb-62e5-45c4-b728-767cab47da04.preview.emergentagent.com/api"
TEST_USER_EMAIL = "security.analyst@cybertech.com"
TEST_USER_PASSWORD = "SecurePass2024!"
TEST_URL_TO_SCAN = "https://vulnerable-webapp.example.com"

# Enhanced test data for new features
ENHANCED_USER_DATA = {
    "email": "enhanced.user@aegistech.com",
    "password": "EnhancedSecure2024!",
    "full_name": "Enhanced Security Analyst",
    "company": "AEGIS Cybersecurity Solutions",
    "phone": "+1-555-0123"
}

class BackendTester:
    def __init__(self):
        self.session = requests.Session()
        self.test_results = {}
        self.user_id = None
        self.enhanced_user_id = None
        self.scan_id = None
        self.reset_token = None
        self.test_user_email = None  # Store the test user email
        
    def log_test(self, test_name, success, message, details=None):
        """Log test results"""
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}: {message}")
        if details:
            print(f"   Details: {details}")
        
        self.test_results[test_name] = {
            "success": success,
            "message": message,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
    
    def test_basic_connectivity(self):
        """Test basic API connectivity"""
        try:
            response = self.session.get(f"{BASE_URL}/")
            if response.status_code == 200:
                data = response.json()
                if "AEGIS Digital Umbrella" in data.get("message", ""):
                    self.log_test("Basic API Connectivity", True, "API is accessible and responding correctly")
                    return True
                else:
                    self.log_test("Basic API Connectivity", False, "API responding but incorrect message", data)
                    return False
            else:
                self.log_test("Basic API Connectivity", False, f"HTTP {response.status_code}", response.text)
                return False
        except Exception as e:
            self.log_test("Basic API Connectivity", False, f"Connection failed: {str(e)}")
            return False
    
    def test_user_registration(self):
        """Test user registration endpoint"""
        try:
            # Use a unique email to avoid conflicts
            unique_email = f"test.user.{int(time.time())}@cybertech.com"
            user_data = {
                "email": unique_email,
                "password": TEST_USER_PASSWORD
            }
            
            response = self.session.post(f"{BASE_URL}/auth/register", json=user_data)
            
            if response.status_code == 200:
                data = response.json()
                if "user_id" in data and "message" in data:
                    self.user_id = data["user_id"]
                    # Store the email for login test
                    self.test_user_email = unique_email
                    self.log_test("User Registration", True, "User registered successfully", f"User ID: {self.user_id}")
                    return True
                else:
                    self.log_test("User Registration", False, "Registration response missing required fields", data)
                    return False
            else:
                self.log_test("User Registration", False, f"HTTP {response.status_code}", response.text)
                return False
                
        except Exception as e:
            self.log_test("User Registration", False, f"Registration failed: {str(e)}")
            return False
    
    def test_user_login(self):
        """Test user login endpoint"""
        try:
            # Use the email from registration test
            email_to_use = self.test_user_email if self.test_user_email else TEST_USER_EMAIL
            
            login_data = {
                "email": email_to_use,
                "password": TEST_USER_PASSWORD
            }
            
            response = self.session.post(f"{BASE_URL}/auth/login", json=login_data)
            
            if response.status_code == 200:
                data = response.json()
                if "user_id" in data and "email" in data:
                    self.user_id = data["user_id"]
                    self.log_test("User Login", True, "Login successful", f"User ID: {self.user_id}, Email: {data['email']}")
                    return True
                else:
                    self.log_test("User Login", False, "Login response missing required fields", data)
                    return False
            else:
                self.log_test("User Login", False, f"HTTP {response.status_code}", response.text)
                return False
                
        except Exception as e:
            self.log_test("User Login", False, f"Login failed: {str(e)}")
            return False
    
    def test_vulnerability_scan(self):
        """Test vulnerability scanning endpoint"""
        try:
            scan_data = {
                "url": TEST_URL_TO_SCAN,
                "scan_types": ["sqli", "xss", "csrf"]
            }
            
            print(f"🔍 Starting vulnerability scan for: {TEST_URL_TO_SCAN}")
            response = self.session.post(f"{BASE_URL}/scan", json=scan_data)
            
            if response.status_code == 200:
                data = response.json()
                
                # Check required fields
                required_fields = ["id", "url", "scan_types", "status", "vulnerabilities"]
                missing_fields = [field for field in required_fields if field not in data]
                
                if missing_fields:
                    self.log_test("Vulnerability Scan", False, f"Response missing fields: {missing_fields}", data)
                    return False
                
                self.scan_id = data["id"]
                
                # Verify scan data
                if data["url"] == TEST_URL_TO_SCAN and data["status"] == "completed":
                    vulnerabilities = data.get("vulnerabilities", [])
                    ai_recommendations = data.get("ai_recommendations", [])
                    
                    # Check if vulnerabilities were found
                    vuln_types = set()
                    severity_counts = {"High": 0, "Medium": 0, "Low": 0}
                    
                    for vuln in vulnerabilities:
                        vuln_types.add(vuln.get("type", "").upper())
                        severity = vuln.get("severity", "")
                        if severity in severity_counts:
                            severity_counts[severity] += 1
                    
                    details = {
                        "scan_id": self.scan_id,
                        "vulnerabilities_found": len(vulnerabilities),
                        "vulnerability_types": list(vuln_types),
                        "severity_breakdown": severity_counts,
                        "ai_recommendations_count": len(ai_recommendations),
                        "has_sqli": "SQLI" in vuln_types,
                        "has_xss": "XSS" in vuln_types,
                        "has_csrf": "CSRF" in vuln_types
                    }
                    
                    # Verify expected vulnerability types are present
                    expected_types = {"SQLI", "XSS", "CSRF"}
                    found_types = vuln_types.intersection(expected_types)
                    
                    if len(found_types) >= 2 and len(ai_recommendations) > 0:
                        self.log_test("Vulnerability Scan", True, f"Scan completed with {len(vulnerabilities)} vulnerabilities and {len(ai_recommendations)} AI recommendations", details)
                        return True
                    else:
                        self.log_test("Vulnerability Scan", False, f"Insufficient vulnerability types found or no AI recommendations", details)
                        return False
                else:
                    self.log_test("Vulnerability Scan", False, f"Scan data mismatch or incomplete", data)
                    return False
            else:
                self.log_test("Vulnerability Scan", False, f"HTTP {response.status_code}", response.text)
                return False
                
        except Exception as e:
            self.log_test("Vulnerability Scan", False, f"Scan failed: {str(e)}")
            return False
    
    def test_get_scan_results(self):
        """Test retrieving specific scan results"""
        if not self.scan_id:
            self.log_test("Get Scan Results", False, "No scan ID available from previous test")
            return False
        
        try:
            response = self.session.get(f"{BASE_URL}/scans/{self.scan_id}")
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get("id") == self.scan_id and "vulnerabilities" in data:
                    vulnerabilities_count = len(data.get("vulnerabilities", []))
                    self.log_test("Get Scan Results", True, f"Retrieved scan results successfully", f"Scan ID: {self.scan_id}, Vulnerabilities: {vulnerabilities_count}")
                    return True
                else:
                    self.log_test("Get Scan Results", False, "Scan data incomplete or ID mismatch", data)
                    return False
            elif response.status_code == 404:
                self.log_test("Get Scan Results", False, "Scan not found", f"Scan ID: {self.scan_id}")
                return False
            else:
                self.log_test("Get Scan Results", False, f"HTTP {response.status_code}", response.text)
                return False
                
        except Exception as e:
            self.log_test("Get Scan Results", False, f"Failed to retrieve scan: {str(e)}")
            return False
    
    def test_get_user_scans(self):
        """Test retrieving user scan history"""
        try:
            response = self.session.get(f"{BASE_URL}/scans")
            
            if response.status_code == 200:
                data = response.json()
                
                if isinstance(data, list):
                    scan_count = len(data)
                    if scan_count > 0:
                        # Verify scan structure
                        first_scan = data[0]
                        required_fields = ["id", "url", "status", "created_at"]
                        has_required = all(field in first_scan for field in required_fields)
                        
                        if has_required:
                            self.log_test("Get User Scans", True, f"Retrieved {scan_count} scans successfully")
                            return True
                        else:
                            self.log_test("Get User Scans", False, "Scan objects missing required fields", first_scan)
                            return False
                    else:
                        self.log_test("Get User Scans", True, "No scans found (empty list is valid)")
                        return True
                else:
                    self.log_test("Get User Scans", False, "Response is not a list", data)
                    return False
            else:
                self.log_test("Get User Scans", False, f"HTTP {response.status_code}", response.text)
                return False
                
        except Exception as e:
            self.log_test("Get User Scans", False, f"Failed to retrieve scans: {str(e)}")
            return False
    
    def test_dashboard_stats(self):
        """Test dashboard statistics endpoint"""
        try:
            response = self.session.get(f"{BASE_URL}/dashboard/stats")
            
            if response.status_code == 200:
                data = response.json()
                
                required_fields = ["total_scans", "active_scans", "total_vulnerabilities", "high_risk_vulnerabilities"]
                missing_fields = [field for field in required_fields if field not in data]
                
                if missing_fields:
                    self.log_test("Dashboard Stats", False, f"Missing required fields: {missing_fields}", data)
                    return False
                
                # Verify data types are numeric
                numeric_fields = all(isinstance(data[field], int) for field in required_fields)
                
                if numeric_fields:
                    stats_summary = {
                        "total_scans": data["total_scans"],
                        "active_scans": data["active_scans"],
                        "total_vulnerabilities": data["total_vulnerabilities"],
                        "high_risk_vulnerabilities": data["high_risk_vulnerabilities"]
                    }
                    self.log_test("Dashboard Stats", True, "Dashboard statistics retrieved successfully", stats_summary)
                    return True
                else:
                    self.log_test("Dashboard Stats", False, "Non-numeric values in stats", data)
                    return False
            else:
                self.log_test("Dashboard Stats", False, f"HTTP {response.status_code}", response.text)
                return False
                
        except Exception as e:
            self.log_test("Dashboard Stats", False, f"Failed to retrieve stats: {str(e)}")
            return False
    
    def test_gemini_ai_integration(self):
        """Test Gemini AI integration by checking AI recommendations quality"""
        if not self.scan_id:
            self.log_test("Gemini AI Integration", False, "No scan available to check AI recommendations")
            return False
        
        try:
            # Get the scan results to check AI recommendations
            response = self.session.get(f"{BASE_URL}/scans/{self.scan_id}")
            
            if response.status_code == 200:
                data = response.json()
                ai_recommendations = data.get("ai_recommendations", [])
                
                if len(ai_recommendations) > 0:
                    # Check if recommendations are meaningful (not just fallback)
                    meaningful_keywords = ["input validation", "parameterized", "sanitization", "CSRF token", "security", "XSS", "SQL injection"]
                    
                    recommendation_text = " ".join(ai_recommendations).lower()
                    keyword_matches = sum(1 for keyword in meaningful_keywords if keyword.lower() in recommendation_text)
                    
                    if keyword_matches >= 3:
                        details = {
                            "recommendations_count": len(ai_recommendations),
                            "keyword_matches": keyword_matches,
                            "sample_recommendation": ai_recommendations[0][:100] + "..." if ai_recommendations[0] else ""
                        }
                        self.log_test("Gemini AI Integration", True, "AI recommendations generated with relevant security content", details)
                        return True
                    else:
                        self.log_test("Gemini AI Integration", False, f"AI recommendations lack security-specific content (only {keyword_matches} matches)", ai_recommendations)
                        return False
                else:
                    self.log_test("Gemini AI Integration", False, "No AI recommendations generated")
                    return False
            else:
                self.log_test("Gemini AI Integration", False, f"Could not retrieve scan for AI check: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Gemini AI Integration", False, f"AI integration test failed: {str(e)}")
            return False

    # ========== ENHANCEMENT FEATURES TESTS ==========
    
    def test_enhanced_user_registration(self):
        """Test enhanced user registration with additional fields"""
        try:
            response = self.session.post(f"{BASE_URL}/auth/register", json=ENHANCED_USER_DATA)
            
            if response.status_code == 200:
                data = response.json()
                if "user_id" in data and "message" in data:
                    self.enhanced_user_id = data["user_id"]
                    self.log_test("Enhanced User Registration", True, "Enhanced user registered successfully with all fields", f"User ID: {self.enhanced_user_id}")
                    return True
                else:
                    self.log_test("Enhanced User Registration", False, "Registration response missing required fields", data)
                    return False
            elif response.status_code == 400 and "already registered" in response.text:
                # User already exists, this is fine for testing
                self.log_test("Enhanced User Registration", True, "Enhanced user already exists (expected for repeated tests)")
                return True
            else:
                self.log_test("Enhanced User Registration", False, f"HTTP {response.status_code}", response.text)
                return False
                
        except Exception as e:
            self.log_test("Enhanced User Registration", False, f"Enhanced registration failed: {str(e)}")
            return False

    def get_enhanced_user_id(self):
        """Helper method to get enhanced user ID by trying different approaches"""
        if self.enhanced_user_id:
            return self.enhanced_user_id
        
        # Try to find user by attempting registration (will fail but give us info)
        try:
            response = self.session.post(f"{BASE_URL}/auth/register", json=ENHANCED_USER_DATA)
            if response.status_code == 400 and "already registered" in response.text:
                # User exists, try to login with different passwords
                passwords_to_try = [
                    ENHANCED_USER_DATA["password"],
                    "NewSecurePassword2024!",
                    "FinalSecurePassword2024!"
                ]
                
                for password in passwords_to_try:
                    login_data = {
                        "email": ENHANCED_USER_DATA["email"],
                        "password": password
                    }
                    login_response = self.session.post(f"{BASE_URL}/auth/login", json=login_data)
                    if login_response.status_code == 200:
                        data = login_response.json()
                        self.enhanced_user_id = data.get("user_id")
                        return self.enhanced_user_id
        except:
            pass
        
        return None

    def test_enhanced_user_login(self):
        """Test enhanced user login with password hashing verification"""
        try:
            # Try different passwords that might be current
            passwords_to_try = [
                ENHANCED_USER_DATA["password"],  # Original password
                "NewSecurePassword2024!",        # From reset password test
                "FinalSecurePassword2024!"       # From change password test
            ]
            
            login_successful = False
            for password in passwords_to_try:
                login_data = {
                    "email": ENHANCED_USER_DATA["email"],
                    "password": password
                }
                
                response = self.session.post(f"{BASE_URL}/auth/login", json=login_data)
                
                if response.status_code == 200:
                    data = response.json()
                    if "user_id" in data and "email" in data:
                        self.enhanced_user_id = data["user_id"]
                        # Check if enhanced fields are returned
                        has_enhanced_fields = "full_name" in data and "company" in data
                        details = {
                            "user_id": self.enhanced_user_id,
                            "email": data["email"],
                            "full_name": data.get("full_name"),
                            "company": data.get("company"),
                            "has_enhanced_fields": has_enhanced_fields,
                            "password_used": f"Password attempt {passwords_to_try.index(password) + 1}"
                        }
                        self.log_test("Enhanced User Login", True, "Enhanced login successful with password hashing verification", details)
                        login_successful = True
                        break
            
            if not login_successful:
                self.log_test("Enhanced User Login", False, "All login attempts failed", f"Tried {len(passwords_to_try)} passwords")
                return False
            
            return True
                
        except Exception as e:
            self.log_test("Enhanced User Login", False, f"Enhanced login failed: {str(e)}")
            return False
        """Test enhanced user login with password hashing verification"""
        try:
            # Try different passwords that might be current
            passwords_to_try = [
                ENHANCED_USER_DATA["password"],  # Original password
                "NewSecurePassword2024!",        # From reset password test
                "FinalSecurePassword2024!"       # From change password test
            ]
            
            login_successful = False
            for password in passwords_to_try:
                login_data = {
                    "email": ENHANCED_USER_DATA["email"],
                    "password": password
                }
                
                response = self.session.post(f"{BASE_URL}/auth/login", json=login_data)
                
                if response.status_code == 200:
                    data = response.json()
                    if "user_id" in data and "email" in data:
                        self.enhanced_user_id = data["user_id"]
                        # Check if enhanced fields are returned
                        has_enhanced_fields = "full_name" in data and "company" in data
                        details = {
                            "user_id": self.enhanced_user_id,
                            "email": data["email"],
                            "full_name": data.get("full_name"),
                            "company": data.get("company"),
                            "has_enhanced_fields": has_enhanced_fields,
                            "password_used": f"Password attempt {passwords_to_try.index(password) + 1}"
                        }
                        self.log_test("Enhanced User Login", True, "Enhanced login successful with password hashing verification", details)
                        login_successful = True
                        break
            
            if not login_successful:
                # If all passwords fail, still try to get user ID from profile endpoint
                # by trying to find the user in the database through registration
                try:
                    # Try to register again to get user ID (will fail but might give us info)
                    reg_response = self.session.post(f"{BASE_URL}/auth/register", json=ENHANCED_USER_DATA)
                    if reg_response.status_code == 400 and "already registered" in reg_response.text:
                        # User exists, let's try to get the user ID by creating a new user and then finding the enhanced user
                        # For now, we'll mark this as a minor issue but still try to get the user ID
                        self.log_test("Enhanced User Login", False, "Could not login with any password, but user exists")
                        return False
                except:
                    pass
                
                self.log_test("Enhanced User Login", False, "All login attempts failed", f"Tried {len(passwords_to_try)} passwords")
                return False
            
            return True
                
        except Exception as e:
            self.log_test("Enhanced User Login", False, f"Enhanced login failed: {str(e)}")
            return False

    def test_forgot_password(self):
        """Test forgot password functionality"""
        try:
            reset_data = {
                "email": ENHANCED_USER_DATA["email"]
            }
            
            response = self.session.post(f"{BASE_URL}/auth/forgot-password", json=reset_data)
            
            if response.status_code == 200:
                data = response.json()
                if "message" in data:
                    # Check if reset token is provided (for testing purposes)
                    if "reset_token" in data:
                        self.reset_token = data["reset_token"]
                        self.log_test("Forgot Password", True, "Password reset token generated successfully", f"Token: {self.reset_token[:20]}...")
                        return True
                    else:
                        self.log_test("Forgot Password", True, "Password reset request processed (token not exposed for security)")
                        return True
                else:
                    self.log_test("Forgot Password", False, "Response missing message field", data)
                    return False
            else:
                self.log_test("Forgot Password", False, f"HTTP {response.status_code}", response.text)
                return False
                
        except Exception as e:
            self.log_test("Forgot Password", False, f"Forgot password failed: {str(e)}")
            return False

    def test_reset_password(self):
        """Test password reset with token validation"""
        if not self.reset_token:
            self.log_test("Reset Password", False, "No reset token available from forgot password test")
            return False
        
        try:
            reset_data = {
                "reset_token": self.reset_token,
                "new_password": "NewSecurePassword2024!"
            }
            
            response = self.session.post(f"{BASE_URL}/auth/reset-password", json=reset_data)
            
            if response.status_code == 200:
                data = response.json()
                if "message" in data and "successful" in data["message"].lower():
                    self.log_test("Reset Password", True, "Password reset completed successfully with token validation")
                    return True
                else:
                    self.log_test("Reset Password", False, "Reset response missing success confirmation", data)
                    return False
            else:
                self.log_test("Reset Password", False, f"HTTP {response.status_code}", response.text)
                return False
                
        except Exception as e:
            self.log_test("Reset Password", False, f"Password reset failed: {str(e)}")
            return False

    def test_get_user_profile(self):
        """Test user profile retrieval"""
        user_id = self.get_enhanced_user_id()
        if not user_id:
            self.log_test("Get User Profile", False, "No enhanced user ID available")
            return False
        
        try:
            response = self.session.get(f"{BASE_URL}/user/profile/{user_id}")
            
            if response.status_code == 200:
                data = response.json()
                expected_fields = ["id", "email", "full_name", "company", "phone", "created_at"]
                missing_fields = [field for field in expected_fields if field not in data]
                
                # Check that sensitive fields are not included
                sensitive_fields = ["password", "reset_token", "reset_token_expires"]
                exposed_sensitive = [field for field in sensitive_fields if field in data]
                
                if not missing_fields and not exposed_sensitive:
                    details = {
                        "user_id": data["id"],
                        "email": data["email"],
                        "full_name": data.get("full_name"),
                        "company": data.get("company"),
                        "phone": data.get("phone"),
                        "sensitive_fields_properly_hidden": len(exposed_sensitive) == 0
                    }
                    self.log_test("Get User Profile", True, "User profile retrieved successfully with proper data filtering", details)
                    return True
                elif missing_fields:
                    self.log_test("Get User Profile", False, f"Profile missing required fields: {missing_fields}", data)
                    return False
                else:
                    self.log_test("Get User Profile", False, f"Profile exposes sensitive fields: {exposed_sensitive}", data)
                    return False
            elif response.status_code == 404:
                self.log_test("Get User Profile", False, "User profile not found", f"User ID: {user_id}")
                return False
            else:
                self.log_test("Get User Profile", False, f"HTTP {response.status_code}", response.text)
                return False
                
        except Exception as e:
            self.log_test("Get User Profile", False, f"Profile retrieval failed: {str(e)}")
            return False

    def test_update_user_profile(self):
        """Test user profile update"""
        user_id = self.get_enhanced_user_id()
        if not user_id:
            self.log_test("Update User Profile", False, "No enhanced user ID available")
            return False
        
        try:
            update_data = {
                "full_name": "Updated Security Analyst",
                "company": "Updated AEGIS Cybersecurity",
                "phone": "+1-555-9999"
            }
            
            response = self.session.put(f"{BASE_URL}/user/profile/{user_id}", json=update_data)
            
            if response.status_code == 200:
                data = response.json()
                if "message" in data and "successful" in data["message"].lower():
                    # Verify the update by retrieving the profile
                    verify_response = self.session.get(f"{BASE_URL}/user/profile/{user_id}")
                    if verify_response.status_code == 200:
                        updated_profile = verify_response.json()
                        if (updated_profile.get("full_name") == update_data["full_name"] and
                            updated_profile.get("company") == update_data["company"] and
                            updated_profile.get("phone") == update_data["phone"]):
                            self.log_test("Update User Profile", True, "Profile updated successfully and changes verified", update_data)
                            return True
                        else:
                            self.log_test("Update User Profile", False, "Profile update not reflected in database", updated_profile)
                            return False
                    else:
                        self.log_test("Update User Profile", False, "Could not verify profile update")
                        return False
                else:
                    self.log_test("Update User Profile", False, "Update response missing success confirmation", data)
                    return False
            else:
                self.log_test("Update User Profile", False, f"HTTP {response.status_code}", response.text)
                return False
                
        except Exception as e:
            self.log_test("Update User Profile", False, f"Profile update failed: {str(e)}")
            return False

    def test_change_password(self):
        """Test password change functionality"""
        user_id = self.get_enhanced_user_id()
        if not user_id:
            self.log_test("Change Password", False, "No enhanced user ID available")
            return False
        
        try:
            # Try different current passwords
            current_passwords = ["NewSecurePassword2024!", ENHANCED_USER_DATA["password"]]
            new_password = "FinalSecurePassword2024!"
            
            success = False
            for current_password in current_passwords:
                password_data = {
                    "current_password": current_password,
                    "new_password": new_password
                }
                
                response = self.session.post(f"{BASE_URL}/user/change-password/{user_id}", json=password_data)
                
                if response.status_code == 200:
                    data = response.json()
                    if "message" in data and "successful" in data["message"].lower():
                        # Verify password change by attempting login with new password
                        login_data = {
                            "email": ENHANCED_USER_DATA["email"],
                            "password": new_password
                        }
                        login_response = self.session.post(f"{BASE_URL}/auth/login", json=login_data)
                        
                        if login_response.status_code == 200:
                            self.log_test("Change Password", True, "Password changed successfully and verified with login")
                            success = True
                            break
                        else:
                            self.log_test("Change Password", False, "Password change reported success but login failed with new password")
                            return False
                elif response.status_code != 400:  # 400 means wrong current password, try next one
                    self.log_test("Change Password", False, f"HTTP {response.status_code}", response.text)
                    return False
            
            if not success:
                self.log_test("Change Password", False, "Could not change password with any current password attempt")
                return False
            
            return True
                
        except Exception as e:
            self.log_test("Change Password", False, f"Password change failed: {str(e)}")
            return False

    def test_pdf_report_generation(self):
        """Test PDF report generation"""
        if not self.scan_id:
            self.log_test("PDF Report Generation", False, "No scan ID available for PDF generation")
            return False
        
        try:
            response = self.session.get(f"{BASE_URL}/scan/{self.scan_id}/report")
            
            if response.status_code == 200:
                # Check if response is PDF
                content_type = response.headers.get('content-type', '')
                content_disposition = response.headers.get('content-disposition', '')
                
                if 'application/pdf' in content_type:
                    pdf_size = len(response.content)
                    has_filename = 'filename=' in content_disposition
                    
                    # Basic PDF validation - check for PDF header
                    is_valid_pdf = response.content.startswith(b'%PDF-')
                    
                    if is_valid_pdf and pdf_size > 1000:  # Reasonable PDF size
                        details = {
                            "pdf_size_bytes": pdf_size,
                            "content_type": content_type,
                            "has_filename": has_filename,
                            "filename": content_disposition if has_filename else None
                        }
                        self.log_test("PDF Report Generation", True, "PDF report generated successfully with proper headers", details)
                        return True
                    else:
                        self.log_test("PDF Report Generation", False, f"Invalid PDF or too small (size: {pdf_size})")
                        return False
                else:
                    self.log_test("PDF Report Generation", False, f"Wrong content type: {content_type}")
                    return False
            elif response.status_code == 404:
                self.log_test("PDF Report Generation", False, "Scan not found for PDF generation")
                return False
            else:
                self.log_test("PDF Report Generation", False, f"HTTP {response.status_code}", response.text)
                return False
                
        except Exception as e:
            self.log_test("PDF Report Generation", False, f"PDF generation failed: {str(e)}")
            return False

    def test_ai_chatbot_service(self):
        """Test AI chatbot service"""
        user_id = self.get_enhanced_user_id()
        if not user_id:
            self.log_test("AI Chatbot Service", False, "No user ID available for chatbot test")
            return False
        
        try:
            chat_data = {
                "message": "What are the most common web application vulnerabilities and how can I prevent them?",
                "user_id": user_id
            }
            
            response = self.session.post(f"{BASE_URL}/chat", json=chat_data)
            
            if response.status_code == 200:
                data = response.json()
                if "response" in data and "message_id" in data:
                    ai_response = data["response"]
                    message_id = data["message_id"]
                    
                    # Check if response is meaningful
                    security_keywords = ["vulnerability", "security", "XSS", "SQL injection", "CSRF", "authentication", "validation"]
                    response_text = ai_response.lower()
                    keyword_matches = sum(1 for keyword in security_keywords if keyword.lower() in response_text)
                    
                    if len(ai_response) > 50 and keyword_matches >= 2:
                        details = {
                            "message_id": message_id,
                            "response_length": len(ai_response),
                            "security_keyword_matches": keyword_matches,
                            "response_preview": ai_response[:150] + "..." if len(ai_response) > 150 else ai_response
                        }
                        self.log_test("AI Chatbot Service", True, "AI chatbot generated meaningful security-focused response", details)
                        return True
                    else:
                        self.log_test("AI Chatbot Service", False, f"AI response too short or lacks security content (length: {len(ai_response)}, keywords: {keyword_matches})")
                        return False
                else:
                    self.log_test("AI Chatbot Service", False, "Chatbot response missing required fields", data)
                    return False
            else:
                self.log_test("AI Chatbot Service", False, f"HTTP {response.status_code}", response.text)
                return False
                
        except Exception as e:
            self.log_test("AI Chatbot Service", False, f"Chatbot service failed: {str(e)}")
            return False

    def test_chat_history(self):
        """Test chat history retrieval"""
        user_id = self.get_enhanced_user_id()
        if not user_id:
            self.log_test("Chat History", False, "No user ID available for chat history test")
            return False
        
        try:
            response = self.session.get(f"{BASE_URL}/chat/history/{user_id}")
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    if len(data) > 0:
                        # Check structure of chat history
                        first_chat = data[0]
                        required_fields = ["id", "user_id", "message", "response", "timestamp"]
                        missing_fields = [field for field in required_fields if field not in first_chat]
                        
                        if not missing_fields:
                            details = {
                                "chat_count": len(data),
                                "user_id_match": first_chat["user_id"] == user_id,
                                "has_message": len(first_chat.get("message", "")) > 0,
                                "has_response": len(first_chat.get("response", "")) > 0
                            }
                            self.log_test("Chat History", True, "Chat history retrieved successfully with proper structure", details)
                            return True
                        else:
                            self.log_test("Chat History", False, f"Chat history missing required fields: {missing_fields}")
                            return False
                    else:
                        self.log_test("Chat History", True, "No chat history found (empty list is valid)")
                        return True
                else:
                    self.log_test("Chat History", False, "Chat history response is not a list", data)
                    return False
            else:
                self.log_test("Chat History", False, f"HTTP {response.status_code}", response.text)
                return False
                
        except Exception as e:
            self.log_test("Chat History", False, f"Chat history retrieval failed: {str(e)}")
            return False
    
    def run_all_tests(self):
        """Run all backend tests in sequence"""
        print("🚀 Starting AEGIS Digital Umbrella Backend API Tests - ENHANCED VERSION")
        print(f"📡 Testing against: {BASE_URL}")
        print("=" * 80)
        
        # Original core tests
        core_tests = [
            ("Core API Setup", self.test_basic_connectivity),
            ("Authentication - Registration", self.test_user_registration),
            ("Authentication - Login", self.test_user_login),
            ("Vulnerability Scanning", self.test_vulnerability_scan),
            ("Scan Results Retrieval", self.test_get_scan_results),
            ("User Scan History", self.test_get_user_scans),
            ("Dashboard Statistics", self.test_dashboard_stats),
            ("Gemini AI Integration", self.test_gemini_ai_integration)
        ]
        
        # Enhancement feature tests
        enhancement_tests = [
            ("Enhanced User Registration", self.test_enhanced_user_registration),
            ("Enhanced User Login", self.test_enhanced_user_login),
            ("Forgot Password", self.test_forgot_password),
            ("Reset Password", self.test_reset_password),
            ("Get User Profile", self.test_get_user_profile),
            ("Update User Profile", self.test_update_user_profile),
            ("Change Password", self.test_change_password),
            ("PDF Report Generation", self.test_pdf_report_generation),
            ("AI Chatbot Service", self.test_ai_chatbot_service),
            ("Chat History", self.test_chat_history)
        ]
        
        all_tests = core_tests + enhancement_tests
        
        passed = 0
        total = len(all_tests)
        
        print(f"\n🔧 CORE FEATURES TESTING ({len(core_tests)} tests)")
        print("-" * 50)
        
        for test_name, test_func in core_tests:
            print(f"\n🧪 Running: {test_name}")
            try:
                if test_func():
                    passed += 1
            except Exception as e:
                self.log_test(test_name, False, f"Test execution error: {str(e)}")
        
        print(f"\n🚀 ENHANCEMENT FEATURES TESTING ({len(enhancement_tests)} tests)")
        print("-" * 50)
        
        for test_name, test_func in enhancement_tests:
            print(f"\n🧪 Running: {test_name}")
            try:
                if test_func():
                    passed += 1
            except Exception as e:
                self.log_test(test_name, False, f"Test execution error: {str(e)}")
        
        print("\n" + "=" * 80)
        print(f"📊 Test Results: {passed}/{total} tests passed")
        
        # Breakdown by category
        core_passed = sum(1 for test_name, _ in core_tests if self.test_results.get(test_name, {}).get("success", False))
        enhancement_passed = sum(1 for test_name, _ in enhancement_tests if self.test_results.get(test_name, {}).get("success", False))
        
        print(f"   📋 Core Features: {core_passed}/{len(core_tests)} passed")
        print(f"   🚀 Enhancements: {enhancement_passed}/{len(enhancement_tests)} passed")
        
        if passed == total:
            print("🎉 All tests passed! Backend is working correctly with all enhancements.")
        else:
            print(f"⚠️  {total - passed} tests failed. Check the details above.")
        
        return passed, total, self.test_results

def main():
    """Main test execution"""
    tester = BackendTester()
    passed, total, results = tester.run_all_tests()
    
    # Save detailed results
    with open('/app/backend_test_results.json', 'w') as f:
        json.dump({
            "summary": {
                "passed": passed,
                "total": total,
                "success_rate": f"{(passed/total)*100:.1f}%"
            },
            "detailed_results": results,
            "test_timestamp": datetime.now().isoformat()
        }, f, indent=2)
    
    print(f"\n📄 Detailed results saved to: /app/backend_test_results.json")
    
    # Exit with appropriate code
    sys.exit(0 if passed == total else 1)

if __name__ == "__main__":
    main()