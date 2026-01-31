import os
import sys
import asyncio
import logging
from fastapi import FastAPI, APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from starlette.middleware.cors import CORSMiddleware
from typing import Optional
import io

# Import modules
from modules.auth import *
from modules.scanner import *
from modules.ai_chat import *
from modules.admin import AdminService, is_admin
from modules.report_generator import generate_pdf_report
from utils.database import get_database, close_database
from config.settings import CORS_ORIGINS, CORS_CREDENTIALS, CORS_METHODS, CORS_HEADERS

logger = logging.getLogger(__name__)

# Create the main app
app = FastAPI(title="AEGIS Digital Umbrella API", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=CORS_CREDENTIALS,
    allow_methods=CORS_METHODS,
    allow_headers=CORS_HEADERS,
)

# Create API router
api_router = APIRouter(prefix="/api")

class DashboardStats(BaseModel):
    total_scans: int
    active_scans: int
    total_vulnerabilities: int
    high_risk_vulnerabilities: int

# Authentication endpoints
@api_router.post("/auth/register")
async def register_user(user_data: UserCreate):
    """Register a new user."""
    try:
        db = await get_database()
        
        # Check if user already exists
        existing_user = await db.users.find_one({"email": user_data.email})
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Hash password and create user
        hashed_password = hash_password(user_data.password)
        user = User(
            email=user_data.email,
            password=hashed_password,
            full_name=user_data.full_name,
            company=user_data.company,
            phone=user_data.phone
        )
        
        # Insert user into database
        result = await db.users.insert_one(user.dict())
        user.id = str(result.inserted_id)
        
        return {"message": "User registered successfully", "user_id": user.id}
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        raise HTTPException(status_code=500, detail="Registration failed")

@api_router.post("/auth/login")
async def login_user(login_data: UserLogin):
    """Login user."""
    try:
        db = await get_database()
        
        # Find user by email
        user = await db.users.find_one({"email": login_data.email})
        if not user or not verify_password(login_data.password, user["password"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Update last login
        await db.users.update_one(
            {"_id": user["_id"]},
            {"$set": {"last_login": datetime.utcnow()}}
        )
        
        return {
            "user_id": str(user["_id"]),
            "email": user["email"],
            "full_name": user.get("full_name"),
            "company": user.get("company")
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(status_code=500, detail="Login failed")

# Scanning endpoints
@api_router.post("/scan")
async def start_scan(scan_request: ScanRequest, user_id: str = "demo_user"):
    """Start a security scan."""
    try:
        db = await get_database()
        
        # Check if domain exists
        if not await check_domain_exists(scan_request.url):
            raise HTTPException(status_code=400, detail="Domain not reachable")
        
        # Create scan result
        scan_result = ScanResult(
            user_id=user_id,
            url=scan_request.url,
            scan_types=scan_request.scan_types,
            status="running"
        )
        
        # Insert scan into database
        result = await db.scans.insert_one(scan_result.dict())
        scan_result.id = str(result.inserted_id)
        
        # Start scanning in background
        asyncio.create_task(perform_scan(scan_result.id, scan_request))
        
        return scan_result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Scan start error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to start scan")

async def perform_scan(scan_id: str, scan_request: ScanRequest):
    """Perform the actual scanning."""
    try:
        db = await get_database()
        vulnerabilities = []
        
        # Perform scans based on types
        if 'sqli' in scan_request.scan_types:
            sqli_vulns = await scan_sqli(scan_request.url)
            vulnerabilities.extend(sqli_vulns)
        
        if 'xss' in scan_request.scan_types:
            xss_vulns = await scan_xss(scan_request.url)
            vulnerabilities.extend(xss_vulns)
        
        if 'csrf' in scan_request.scan_types:
            csrf_vulns = await scan_csrf(scan_request.url)
            vulnerabilities.extend(csrf_vulns)
        
        # Calculate statistics
        total_vulnerabilities = len(vulnerabilities)
        high_severity_count = len([v for v in vulnerabilities if v.severity == 'High'])
        medium_severity_count = len([v for v in vulnerabilities if v.severity == 'Medium'])
        low_severity_count = len([v for v in vulnerabilities if v.severity == 'Low'])
        
        # Generate AI recommendations
        ai_recommendations = generate_ai_recommendations(vulnerabilities)
        
        # Update scan result
        await db.scans.update_one(
            {"_id": scan_id},
            {"$set": {
                "status": "completed",
                "vulnerabilities": [v.dict() for v in vulnerabilities],
                "ai_recommendations": ai_recommendations,
                "completed_at": datetime.utcnow(),
                "total_vulnerabilities": total_vulnerabilities,
                "high_severity_count": high_severity_count,
                "medium_severity_count": medium_severity_count,
                "low_severity_count": low_severity_count
            }}
        )
        
    except Exception as e:
        logger.error(f"Scan execution error: {str(e)}")
        db = await get_database()
        await db.scans.update_one(
            {"_id": scan_id},
            {"$set": {"status": "failed"}}
        )

def generate_ai_recommendations(vulnerabilities):
    """Generate AI recommendations based on vulnerabilities."""
    recommendations = []
    
    if any(v.type == "SQLi" for v in vulnerabilities):
        recommendations.append("Implement parameterized queries and prepared statements to prevent SQL injection attacks.")
    
    if any(v.type == "XSS" for v in vulnerabilities):
        recommendations.append("Use proper input validation and output encoding to prevent cross-site scripting attacks.")
    
    if any(v.type == "CSRF" for v in vulnerabilities):
        recommendations.append("Implement CSRF tokens for all state-changing operations to prevent cross-site request forgery.")
    
    if not recommendations:
        recommendations.append("Your website appears to be secure against the tested vulnerabilities. Continue following security best practices.")
    
    return recommendations

@api_router.get("/scan/{scan_id}")
async def get_scan_result(scan_id: str):
    """Get scan result by ID."""
    try:
        db = await get_database()
        scan = await db.scans.find_one({"_id": scan_id})
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return scan
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get scan error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get scan result")

@api_router.get("/scan/{scan_id}/report")
async def download_scan_report(scan_id: str):
    """Download PDF report for scan."""
    try:
        db = await get_database()
        scan = await db.scans.find_one({"_id": scan_id})
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Convert to ScanResult object
        scan_result = ScanResult(**scan)
        
        # Generate PDF
        pdf_data = generate_pdf_report(scan_result)
        
        return StreamingResponse(
            io.BytesIO(pdf_data),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=aegis_scan_report_{scan_id}.pdf"}
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Report download error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to generate report")

# Chat endpoints
@api_router.post("/chat")
async def chat_with_ai(chat_request: ChatRequest):
    """Chat with AI assistant."""
    try:
        # Initialize AI chat
        llm_chat = LlmChat(
            api_key=os.getenv('GEMINI_API_KEY', ''),
            session_id=chat_request.user_id,
            system_message=get_system_message()
        )
        
        # Send message to AI
        user_message = UserMessage(chat_request.message)
        response = await llm_chat.send_message(user_message)
        
        # Save chat message to database
        db = await get_database()
        chat_message = ChatMessage(
            user_id=chat_request.user_id,
            message=chat_request.message,
            response=response
        )
        await db.chat_messages.insert_one(chat_message.dict())
        
        return {"response": response}
    except Exception as e:
        logger.error(f"Chat error: {str(e)}")
        return {"response": "I'm sorry, I'm having trouble processing your request right now. Please try again."}

# Dashboard endpoints
@api_router.get("/dashboard/stats/{user_id}")
async def get_dashboard_stats(user_id: str):
    """Get dashboard statistics for user."""
    try:
        db = await get_database()
        
        # Get user scans
        total_scans = await db.scans.count_documents({"user_id": user_id})
        active_scans = await db.scans.count_documents({"user_id": user_id, "status": "running"})
        
        # Get vulnerability counts
        user_scans = db.scans.find({"user_id": user_id, "status": "completed"})
        total_vulnerabilities = 0
        high_risk_vulnerabilities = 0
        
        async for scan in user_scans:
            total_vulnerabilities += scan.get("total_vulnerabilities", 0)
            high_risk_vulnerabilities += scan.get("high_severity_count", 0)
        
        return DashboardStats(
            total_scans=total_scans,
            active_scans=active_scans,
            total_vulnerabilities=total_vulnerabilities,
            high_risk_vulnerabilities=high_risk_vulnerabilities
        )
    except Exception as e:
        logger.error(f"Dashboard stats error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get dashboard stats")

@api_router.get("/scans/user/{user_id}")
async def get_user_scans(user_id: str):
    """Get all scans for a user."""
    try:
        db = await get_database()
        scans = []
        
        async for scan in db.scans.find({"user_id": user_id}).sort("created_at", -1):
            scans.append(scan)
        
        return scans
    except Exception as e:
        logger.error(f"Get user scans error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get user scans")

# User profile endpoints
@api_router.get("/user/profile/{user_id}")
async def get_user_profile(user_id: str):
    """Get user profile."""
    try:
        db = await get_database()
        user = await db.users.find_one({"_id": user_id})
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {
            "email": user["email"],
            "full_name": user.get("full_name"),
            "company": user.get("company"),
            "phone": user.get("phone")
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get profile error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get user profile")

@api_router.put("/user/profile/{user_id}")
async def update_user_profile(user_id: str, profile_data: UserUpdate):
    """Update user profile."""
    try:
        db = await get_database()
        
        update_data = {}
        if profile_data.full_name is not None:
            update_data["full_name"] = profile_data.full_name
        if profile_data.company is not None:
            update_data["company"] = profile_data.company
        if profile_data.phone is not None:
            update_data["phone"] = profile_data.phone
        
        result = await db.users.update_one(
            {"_id": user_id},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {"message": "Profile updated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Update profile error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update profile")

# Admin endpoints
@api_router.get("/admin/users")
async def get_all_users():
    """Get all users (admin only)."""
    try:
        db = await get_database()
        admin_service = AdminService(db)
        users = await admin_service.get_all_users()
        return users
    except Exception as e:
        logger.error(f"Get all users error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get users")

@api_router.get("/admin/scans")
async def get_all_scans():
    """Get all scans (admin only)."""
    try:
        db = await get_database()
        admin_service = AdminService(db)
        scans = await admin_service.get_all_scans()
        return scans
    except Exception as e:
        logger.error(f"Get all scans error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get scans")

@api_router.get("/admin/stats")
async def get_system_stats():
    """Get system statistics (admin only)."""
    try:
        db = await get_database()
        admin_service = AdminService(db)
        stats = await admin_service.get_system_stats()
        return stats
    except Exception as e:
        logger.error(f"Get system stats error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get system stats")

@api_router.delete("/admin/users/{user_id}")
async def delete_user(user_id: str):
    """Delete a user (admin only)."""
    try:
        db = await get_database()
        admin_service = AdminService(db)
        success = await admin_service.delete_user(user_id)
        
        if not success:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {"message": "User deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete user error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to delete user")

@api_router.put("/admin/users/{user_id}/toggle-status")
async def toggle_user_status(user_id: str, status_data: dict):
    """Toggle user active status (admin only)."""
    try:
        db = await get_database()
        admin_service = AdminService(db)
        success = await admin_service.toggle_user_status(user_id, status_data.get('active', True))
        
        if not success:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {"message": "User status updated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Toggle user status error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update user status")

@api_router.delete("/admin/scans/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan (admin only)."""
    try:
        db = await get_database()
        admin_service = AdminService(db)
        success = await admin_service.delete_scan(scan_id)
        
        if not success:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return {"message": "Scan deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete scan error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to delete scan")

@api_router.get("/admin/users/{user_id}/activity")
async def get_user_activity(user_id: str):
    """Get detailed user activity (admin only)."""
    try:
        db = await get_database()
        admin_service = AdminService(db)
        activity = await admin_service.get_user_activity(user_id)
        
        if not activity:
            raise HTTPException(status_code=404, detail="User not found")
        
        return activity
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get user activity error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get user activity")

@api_router.post("/admin/cleanup-scans")
async def cleanup_old_scans(days: int = 30):
    """Clean up old scans (admin only)."""
    try:
        db = await get_database()
        admin_service = AdminService(db)
        deleted_count = await admin_service.cleanup_old_scans(days)
        
        return {"message": f"Cleaned up {deleted_count} old scans"}
    except Exception as e:
        logger.error(f"Cleanup scans error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to cleanup scans")

@api_router.get("/admin/scan-statistics")
async def get_scan_statistics():
    """Get detailed scan statistics (admin only)."""
    try:
        db = await get_database()
        admin_service = AdminService(db)
        stats = await admin_service.get_scan_statistics()
        return stats
    except Exception as e:
        logger.error(f"Get scan statistics error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get scan statistics")

@api_router.post("/admin/backup")
async def backup_database():
    """Create database backup (admin only)."""
    try:
        db = await get_database()
        admin_service = AdminService(db)
        backup_info = await admin_service.backup_database()
        return backup_info
    except Exception as e:
        logger.error(f"Database backup error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create backup")

# Include API router
app.include_router(api_router)

@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "AEGIS Digital Umbrella API", "version": "1.0.0"}

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    await close_database()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

