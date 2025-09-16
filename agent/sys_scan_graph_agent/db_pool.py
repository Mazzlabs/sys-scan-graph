"""
Database Connection Pool for SQLite Operations

Provides robust connection pooling for SQLite database operations with:
- Async-compatible connection management
- Configurable pool size and timeouts
- Safe concurrent access patterns
- Proper connection lifecycle management
- Thread-safe operations using ThreadPoolExecutor
"""

import asyncio
import sqlite3
import time
import logging
from typing import Optional, List, Tuple, Any, cast
from contextlib import asynccontextmanager
from concurrent.futures import ThreadPoolExecutor
import os

logger = logging.getLogger(__name__)


class DatabaseConnectionPool:
    """
    Async-compatible connection pool for SQLite operations.

    Provides thread-safe connection management with proper lifecycle handling
    and configurable pool parameters.
    """

    def __init__(self,
                 db_path: str,
                 max_connections: int = 10,
                 connection_timeout: float = 30.0,
                 max_retries: int = 3):
        """
        Initialize the connection pool.

        Args:
            db_path: Path to the SQLite database file
            max_connections: Maximum number of concurrent connections
            connection_timeout: Timeout for connection operations in seconds
            max_retries: Maximum number of retries for failed operations
        """
        self.db_path = db_path
        self.max_connections = max_connections
        self.connection_timeout = connection_timeout
        self.max_retries = max_retries

        # Async queue for managing connections
        self._pool: asyncio.Queue[sqlite3.Connection] = asyncio.Queue()
        self._semaphore = asyncio.Semaphore(max_connections)

        # Thread pool for blocking SQLite operations
        self._executor = ThreadPoolExecutor(max_workers=max_connections, thread_name_prefix="db-pool")

        # Pool state
        self._initialized = False
        self._closed = False

        # Statistics
        self._connections_created = 0
        self._connections_returned = 0
        self._connection_errors = 0

    async def initialize(self) -> None:
        """Initialize the connection pool by creating initial connections."""
        if self._initialized:
            return

        try:
            # Create initial connections
            for _ in range(self.max_connections):
                conn = await self._create_connection()
                await self._pool.put(conn)
                self._connections_created += 1

            self._initialized = True
            logger.info(f"Database connection pool initialized with {self.max_connections} connections to {self.db_path}")

        except Exception as e:
            logger.error(f"Failed to initialize connection pool: {e}")
            await self.close_all()
            raise

    async def _create_connection(self) -> sqlite3.Connection:
        """Create a new database connection."""
        loop = asyncio.get_event_loop()

        def _connect():
            # Enable WAL mode for better concurrent access
            conn = sqlite3.connect(
                self.db_path,
                timeout=self.connection_timeout,
                check_same_thread=False  # Allow multi-threaded access
            )
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA cache_size=1000")  # 1MB cache
            conn.execute("PRAGMA temp_store=MEMORY")
            return conn

        return await loop.run_in_executor(self._executor, _connect)

    async def get_connection(self) -> sqlite3.Connection:
        """
        Get a connection from the pool.

        Returns:
            SQLite connection object

        Raises:
            RuntimeError: If pool is closed or not initialized
            asyncio.TimeoutError: If connection cannot be acquired within timeout
        """
        if self._closed:
            raise RuntimeError("Connection pool is closed")
        if not self._initialized:
            raise RuntimeError("Connection pool not initialized")

        await self._semaphore.acquire()

        try:
            # Wait for a connection with timeout
            conn = await asyncio.wait_for(
                self._pool.get(),
                timeout=self.connection_timeout
            )
            return conn
        except asyncio.TimeoutError:
            self._semaphore.release()
            self._connection_errors += 1
            raise

    async def return_connection(self, conn: sqlite3.Connection) -> None:
        """
        Return a connection to the pool.

        Args:
            conn: SQLite connection to return
        """
        if self._closed:
            # If pool is closed, close the connection
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(self._executor, conn.close)
            return

        try:
            await self._pool.put(conn)
            self._connections_returned += 1
        except Exception as e:
            logger.warning(f"Failed to return connection to pool: {e}")
            self._connection_errors += 1
        finally:
            self._semaphore.release()

    async def execute_query(self,
                           query: str,
                           params: Tuple = (),
                           retries: Optional[int] = None) -> List[Tuple]:
        """
        Execute a query using a pooled connection.

        Args:
            query: SQL query string
            params: Query parameters
            retries: Number of retries on failure (default: max_retries)

        Returns:
            List of result tuples
        """
        if retries is None:
            retries = self.max_retries

        last_error = None
        for attempt in range(retries + 1):
            conn = None
            try:
                conn = await self.get_connection()
                loop = asyncio.get_event_loop()

                def _execute():
                    cursor = cast(sqlite3.Connection, conn).cursor()
                    cursor.execute(query, params)
                    results = cursor.fetchall()
                    cursor.close()
                    return results

                results = await loop.run_in_executor(self._executor, _execute)
                return results

            except Exception as e:
                last_error = e
                self._connection_errors += 1
                if attempt < retries:
                    logger.warning(f"Query attempt {attempt + 1} failed: {e}, retrying...")
                    await asyncio.sleep(0.1 * (2 ** attempt))  # Exponential backoff
                else:
                    logger.error(f"Query failed after {retries + 1} attempts: {e}")

            finally:
                if conn:
                    await self.return_connection(conn)

        raise last_error or RuntimeError("Query execution failed")

    async def execute_many(self,
                          query: str,
                          params_list: List[Tuple],
                          retries: Optional[int] = None) -> int:
        """
        Execute multiple queries in a batch.

        Args:
            query: SQL query string
            params_list: List of parameter tuples
            retries: Number of retries on failure

        Returns:
            Number of affected rows
        """
        if retries is None:
            retries = self.max_retries

        last_error = None
        for attempt in range(retries + 1):
            conn = None
            try:
                conn = await self.get_connection()
                loop = asyncio.get_event_loop()

                def _execute_many():
                    cursor = cast(sqlite3.Connection, conn).cursor()
                    cursor.executemany(query, params_list)
                    cast(sqlite3.Connection, conn).commit()
                    affected = cursor.rowcount
                    cursor.close()
                    return affected

                affected = await loop.run_in_executor(self._executor, _execute_many)
                return affected

            except Exception as e:
                last_error = e
                self._connection_errors += 1
                if attempt < retries:
                    logger.warning(f"Batch execute attempt {attempt + 1} failed: {e}, retrying...")
                    await asyncio.sleep(0.1 * (2 ** attempt))
                else:
                    logger.error(f"Batch execute failed after {retries + 1} attempts: {e}")

            finally:
                if conn:
                    await self.return_connection(conn)

        raise last_error or RuntimeError("Batch execution failed")

    async def get_pool_stats(self) -> dict:
        """Get pool statistics."""
        return {
            'pool_size': self.max_connections,
            'connections_created': self._connections_created,
            'connections_returned': self._connections_returned,
            'connection_errors': self._connection_errors,
            'queue_size': self._pool.qsize() if not self._closed else 0,
            'initialized': self._initialized,
            'closed': self._closed
        }

    async def close_all(self) -> None:
        """Close all connections in the pool."""
        if self._closed:
            return

        self._closed = True
        logger.info("Closing database connection pool...")

        # Close all connections in the pool
        while not self._pool.empty():
            try:
                conn = await asyncio.wait_for(self._pool.get(), timeout=1.0)
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(self._executor, conn.close)
            except Exception as e:
                logger.warning(f"Error closing connection: {e}")

        # Shutdown thread pool
        self._executor.shutdown(wait=True)
        logger.info("Database connection pool closed")


# Global connection pool instance
_pool_instance: Optional[DatabaseConnectionPool] = None


def get_db_pool(db_path: Optional[str] = None,
                max_connections: Optional[int] = None) -> DatabaseConnectionPool:
    """
    Get or create the global database connection pool.

    Args:
        db_path: Database path (default: from AGENT_BASELINE_DB env var)
        max_connections: Max connections (default: from AGENT_DB_POOL_MAX env var)

    Returns:
        DatabaseConnectionPool instance
    """
    global _pool_instance

    if db_path is None:
        db_path = os.environ.get('AGENT_BASELINE_DB', 'agent_baseline.db')

    if max_connections is None:
        max_connections = int(os.environ.get('AGENT_DB_POOL_MAX', '10'))

    if _pool_instance is None or _pool_instance.db_path != db_path:
        if _pool_instance:
            # Close existing pool if database path changed
            asyncio.create_task(_pool_instance.close_all())

        _pool_instance = DatabaseConnectionPool(
            db_path=db_path,
            max_connections=max_connections
        )

    return _pool_instance


@asynccontextmanager
async def get_db_connection(db_path: Optional[str] = None):
    """
    Context manager for getting a database connection from the pool.

    Usage:
        async with get_db_connection() as conn:
            # Use connection
            pass
    """
    pool = get_db_pool(db_path)
    if not pool._initialized:
        await pool.initialize()

    conn = await pool.get_connection()
    try:
        yield conn
    finally:
        await pool.return_connection(conn)


async def initialize_pool(db_path: Optional[str] = None) -> None:
    """Initialize the global database connection pool."""
    pool = get_db_pool(db_path)
    await pool.initialize()


async def close_pool() -> None:
    """Close the global database connection pool."""
    global _pool_instance
    if _pool_instance:
        await _pool_instance.close_all()
        _pool_instance = None


# Utility functions for common database operations
async def ensure_table_exists(table_name: str, create_sql: str, db_path: Optional[str] = None) -> None:
    """Ensure a database table exists."""
    async with get_db_connection(db_path) as conn:
        loop = asyncio.get_event_loop()

        def _create_table():
            cursor = cast(sqlite3.Connection, conn).cursor()
            cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}'")
            if not cursor.fetchone():
                cursor.execute(create_sql)
                cast(sqlite3.Connection, conn).commit()
            cursor.close()

        await loop.run_in_executor(None, _create_table)


async def get_table_row_count(table_name: str, db_path: Optional[str] = None) -> int:
    """Get the number of rows in a table."""
    async with get_db_connection(db_path) as conn:
        loop = asyncio.get_event_loop()

        def _count_rows():
            cursor = cast(sqlite3.Connection, conn).cursor()
            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            count = cursor.fetchone()[0]
            cursor.close()
            return count

        return await loop.run_in_executor(None, _count_rows)