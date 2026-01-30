"""
Run this from project root python -m scripts.test_pg_conn
If you dont wanna modify path or install the app as python package
"""
import asyncio
import asyncpg
from app.config.setting import settings


async def test_connection():
    """Test PostgreSQL connection"""
    try:
        # Get database URL
        db_url = settings.database.get_pg_db_url()
        print(f"Connecting to: {db_url.replace(settings.database.PG_PASSWORD, '****')}")
        
        # Create connection
        conn = await asyncpg.connect(db_url)
        
        # Test query
        version = await conn.fetchval('SELECT version()')
        print(f"✅ Connected successfully!")
        print(f"PostgreSQL version: {version}")
        
        # Test pgvector extension
        vector_version = await conn.fetchval(
            "SELECT extversion FROM pg_extension WHERE extname = 'vector'"
        )
        if vector_version:
            print(f"✅ pgvector extension installed: v{vector_version}")
        else:
            print("⚠️ pgvector extension not found")
        
        # Close connection
        await conn.close()
        print("✅ Connection closed successfully")
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(test_connection())