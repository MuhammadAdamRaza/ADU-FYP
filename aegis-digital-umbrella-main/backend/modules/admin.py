from datetime import datetime
from typing import List, Dict, Any, Optional
from bson import ObjectId
import logging

logger = logging.getLogger(__name__)

class AdminService:
    def __init__(self, db):
        self.db = db
        self.users_collection = db.users
        self.scans_collection = db.scans
        self.chat_collection = db.chat_messages

    async def get_all_users(self) -> List[Dict[str, Any]]:
        """Get all users in the system"""
        try:
            users = []
            cursor = self.users_collection.find({})
            async for user in cursor:
                user['_id'] = str(user['_id'])
                # Remove sensitive information
                user.pop('password', None)
                users.append(user)
            return users
        except Exception as e:
            logger.error(f"Error fetching users: {e}")
            return []

    async def get_all_scans(self) -> List[Dict[str, Any]]:
        """Get all scans in the system"""
        try:
            scans = []
            # Join with users to get username
            pipeline = [
                {
                    "$lookup": {
                        "from": "users",
                        "localField": "user_id",
                        "foreignField": "_id",
                        "as": "user_info"
                    }
                },
                {
                    "$addFields": {
                        "username": {
                            "$ifNull": [
                                {"$arrayElemAt": ["$user_info.username", 0]},
                                "Unknown"
                            ]
                        }
                    }
                },
                {
                    "$project": {
                        "user_info": 0
                    }
                },
                {
                    "$sort": {"createdAt": -1}
                }
            ]
            
            cursor = self.scans_collection.aggregate(pipeline)
            async for scan in cursor:
                scan['_id'] = str(scan['_id'])
                if 'user_id' in scan:
                    scan['user_id'] = str(scan['user_id'])
                scans.append(scan)
            return scans
        except Exception as e:
            logger.error(f"Error fetching scans: {e}")
            return []

    async def get_system_stats(self) -> Dict[str, Any]:
        """Get system statistics"""
        try:
            # Count total users
            total_users = await self.users_collection.count_documents({})
            
            # Count active users (assuming active field exists)
            active_users = await self.users_collection.count_documents({"active": True})
            
            # Count total scans
            total_scans = await self.scans_collection.count_documents({})
            
            # Count total vulnerabilities found
            pipeline = [
                {"$match": {"vulnerabilities": {"$exists": True}}},
                {"$project": {"vulnerability_count": {"$size": "$vulnerabilities"}}},
                {"$group": {"_id": None, "total": {"$sum": "$vulnerability_count"}}}
            ]
            
            vulnerability_result = await self.scans_collection.aggregate(pipeline).to_list(1)
            total_vulnerabilities = vulnerability_result[0]['total'] if vulnerability_result else 0
            
            # Recent activity (scans in last 7 days)
            from datetime import datetime, timedelta
            week_ago = datetime.utcnow() - timedelta(days=7)
            recent_scans = await self.scans_collection.count_documents({
                "createdAt": {"$gte": week_ago}
            })
            
            return {
                "totalUsers": total_users,
                "activeUsers": active_users,
                "totalScans": total_scans,
                "totalVulnerabilities": total_vulnerabilities,
                "recentScans": recent_scans
            }
        except Exception as e:
            logger.error(f"Error fetching system stats: {e}")
            return {
                "totalUsers": 0,
                "activeUsers": 0,
                "totalScans": 0,
                "totalVulnerabilities": 0,
                "recentScans": 0
            }

    async def delete_user(self, user_id: str) -> bool:
        """Delete a user and their associated data"""
        try:
            user_object_id = ObjectId(user_id)
            
            # Delete user's scans
            await self.scans_collection.delete_many({"user_id": user_object_id})
            
            # Delete user's chat messages
            await self.chat_collection.delete_many({"user_id": user_object_id})
            
            # Delete the user
            result = await self.users_collection.delete_one({"_id": user_object_id})
            
            return result.deleted_count > 0
        except Exception as e:
            logger.error(f"Error deleting user {user_id}: {e}")
            return False

    async def toggle_user_status(self, user_id: str, active: bool) -> bool:
        """Toggle user active status"""
        try:
            user_object_id = ObjectId(user_id)
            result = await self.users_collection.update_one(
                {"_id": user_object_id},
                {"$set": {"active": active, "updatedAt": datetime.utcnow()}}
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Error toggling user status {user_id}: {e}")
            return False

    async def delete_scan(self, scan_id: str) -> bool:
        """Delete a specific scan"""
        try:
            scan_object_id = ObjectId(scan_id)
            result = await self.scans_collection.delete_one({"_id": scan_object_id})
            return result.deleted_count > 0
        except Exception as e:
            logger.error(f"Error deleting scan {scan_id}: {e}")
            return False

    async def update_user_role(self, user_id: str, role: str) -> bool:
        """Update user role"""
        try:
            user_object_id = ObjectId(user_id)
            result = await self.users_collection.update_one(
                {"_id": user_object_id},
                {"$set": {"role": role, "updatedAt": datetime.utcnow()}}
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Error updating user role {user_id}: {e}")
            return False

    async def get_user_activity(self, user_id: str) -> Dict[str, Any]:
        """Get detailed activity for a specific user"""
        try:
            user_object_id = ObjectId(user_id)
            
            # Get user info
            user = await self.users_collection.find_one({"_id": user_object_id})
            if not user:
                return {}
            
            # Get user's scans
            scans = []
            cursor = self.scans_collection.find({"user_id": user_object_id}).sort("createdAt", -1)
            async for scan in cursor:
                scan['_id'] = str(scan['_id'])
                scan['user_id'] = str(scan['user_id'])
                scans.append(scan)
            
            # Get user's chat messages count
            chat_count = await self.chat_collection.count_documents({"user_id": user_object_id})
            
            return {
                "user": {
                    "_id": str(user['_id']),
                    "username": user.get('username', 'Unknown'),
                    "email": user.get('email', ''),
                    "role": user.get('role', 'user'),
                    "active": user.get('active', True),
                    "createdAt": user.get('createdAt'),
                    "lastLogin": user.get('lastLogin')
                },
                "scans": scans,
                "chatMessageCount": chat_count,
                "totalScans": len(scans),
                "totalVulnerabilities": sum(len(scan.get('vulnerabilities', [])) for scan in scans)
            }
        except Exception as e:
            logger.error(f"Error fetching user activity {user_id}: {e}")
            return {}

    async def cleanup_old_scans(self, days: int = 30) -> int:
        """Clean up scans older than specified days"""
        try:
            from datetime import datetime, timedelta
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            result = await self.scans_collection.delete_many({
                "createdAt": {"$lt": cutoff_date}
            })
            
            logger.info(f"Cleaned up {result.deleted_count} old scans")
            return result.deleted_count
        except Exception as e:
            logger.error(f"Error cleaning up old scans: {e}")
            return 0

    async def get_scan_statistics(self) -> Dict[str, Any]:
        """Get detailed scan statistics"""
        try:
            # Scans by status
            status_pipeline = [
                {"$group": {"_id": "$status", "count": {"$sum": 1}}}
            ]
            status_stats = {}
            cursor = self.scans_collection.aggregate(status_pipeline)
            async for stat in cursor:
                status_stats[stat['_id']] = stat['count']
            
            # Scans by scan type
            type_pipeline = [
                {"$unwind": "$scanTypes"},
                {"$group": {"_id": "$scanTypes", "count": {"$sum": 1}}}
            ]
            type_stats = {}
            cursor = self.scans_collection.aggregate(type_pipeline)
            async for stat in cursor:
                type_stats[stat['_id']] = stat['count']
            
            # Vulnerability distribution
            vuln_pipeline = [
                {"$match": {"vulnerabilities": {"$exists": True, "$ne": []}}},
                {"$unwind": "$vulnerabilities"},
                {"$group": {"_id": "$vulnerabilities.type", "count": {"$sum": 1}}}
            ]
            vuln_stats = {}
            cursor = self.scans_collection.aggregate(vuln_pipeline)
            async for stat in cursor:
                vuln_stats[stat['_id']] = stat['count']
            
            return {
                "scansByStatus": status_stats,
                "scansByType": type_stats,
                "vulnerabilityDistribution": vuln_stats
            }
        except Exception as e:
            logger.error(f"Error fetching scan statistics: {e}")
            return {
                "scansByStatus": {},
                "scansByType": {},
                "vulnerabilityDistribution": {}
            }

    async def backup_database(self) -> Dict[str, Any]:
        """Create a backup of critical data"""
        try:
            # This is a simplified backup - in production, you'd use proper backup tools
            backup_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "users_count": await self.users_collection.count_documents({}),
                "scans_count": await self.scans_collection.count_documents({}),
                "chat_messages_count": await self.chat_collection.count_documents({})
            }
            
            logger.info(f"Database backup created: {backup_data}")
            return backup_data
        except Exception as e:
            logger.error(f"Error creating database backup: {e}")
            return {"error": str(e)}

def is_admin(user_data: Dict[str, Any]) -> bool:
    """Check if user has admin privileges"""
    return user_data.get('role') == 'admin'

def admin_required(func):
    """Decorator to require admin privileges"""
    def wrapper(*args, **kwargs):
        # This would be implemented based on your authentication system
        # For now, it's a placeholder
        return func(*args, **kwargs)
    return wrapper

