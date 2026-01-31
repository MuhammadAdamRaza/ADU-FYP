import os
from motor.motor_asyncio import AsyncIOMotorClient

# MongoDB connection
mongo_url = os.environ.get('MONGODB_URL', 'mongodb://localhost:27017')
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ.get('DB_NAME', 'aegis_db')]

async def get_database():
    """Get database instance."""
    return db

async def close_database():
    """Close database connection."""
    client.close()

