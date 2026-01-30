"""
Run this from project root python -m scripts.test_pg_pool
"""

import asyncio
from app.db.utils_db.pg_pool_mngr import pg_pool


async def test_pool():
    """Test PostgreSQL pool manager"""
    try:
        # Initialize pool
        print("Initializing pool...")
        await pg_pool.initialize(component_name="test_component")
        print("✅ Pool initialized")
        
        # Get pool stats
        stats = await pg_pool.get_pool_stats()
        print(f"📊 Pool stats: {stats}")
        
        # Test connection from pool
        print("\nTesting connection acquisition...")
        async with pg_pool.get_connection() as conn:
            result = await conn.fetchval('SELECT 1 + 1')
            print(f"✅ Query result: {result}")
            
            # Test pgvector
            await conn.execute('CREATE EXTENSION IF NOT EXISTS vector')
            vector_test = await conn.fetchval('SELECT $1::vector', [1, 2, 3])
            print(f"✅ pgvector test: {vector_test}")
        
        print("\n📊 Connection released back to pool")
        
        # Health check
        health = await pg_pool.health_check()
        print(f"\n🏥 Health check: {health}")
        
        # Cleanup
        await pg_pool.unregister_component("test_component")
        print("\n✅ Pool test completed successfully!")
        
    except Exception as e:
        print(f"❌ Pool test failed: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(test_pool())