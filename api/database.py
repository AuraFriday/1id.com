"""
1id.com Enrollment API -- Database connection pool

Uses mysql-connector-python with a connection pool for concurrent requests.
"""

import mysql.connector
from mysql.connector import pooling
import config

_connection_pool = None


def get_connection_pool():
  """Get or create the MySQL connection pool (lazy init, thread-safe)."""
  global _connection_pool
  if _connection_pool is None:
    _connection_pool = pooling.MySQLConnectionPool(
      pool_name="oneid_api_pool",
      pool_size=5,
      pool_reset_session=True,
      host=config.MYSQL_HOST,
      port=config.MYSQL_PORT,
      user=config.MYSQL_USER,
      password=config.MYSQL_PASSWORD,
      database=config.MYSQL_DATABASE,
      charset="utf8mb4",
      collation="utf8mb4_unicode_ci",
      autocommit=False,
    )
  return _connection_pool


def get_database_connection():
  """Get a connection from the pool. Caller must close it when done."""
  pool = get_connection_pool()
  return pool.get_connection()


def execute_query_returning_one_row(query, params=None):
  """Execute a SELECT query and return a single row as dict, or None."""
  connection = get_database_connection()
  try:
    cursor = connection.cursor(dictionary=True)
    cursor.execute(query, params)
    row = cursor.fetchone()
    cursor.close()
    return row
  finally:
    connection.close()


def execute_query_returning_all_rows(query, params=None):
  """Execute a SELECT query and return all rows as list of dicts."""
  connection = get_database_connection()
  try:
    cursor = connection.cursor(dictionary=True)
    cursor.execute(query, params)
    rows = cursor.fetchall()
    cursor.close()
    return rows
  finally:
    connection.close()


def execute_insert_or_update(query, params=None):
  """Execute an INSERT/UPDATE/DELETE and commit. Returns lastrowid."""
  connection = get_database_connection()
  try:
    cursor = connection.cursor()
    cursor.execute(query, params)
    connection.commit()
    last_id = cursor.lastrowid
    cursor.close()
    return last_id
  finally:
    connection.close()


def execute_multiple_statements_in_transaction(statements_with_params):
  """
  Execute multiple INSERT/UPDATE/DELETE statements in a single transaction.
  statements_with_params is a list of (query, params) tuples.
  Rolls back on any failure.
  """
  connection = get_database_connection()
  try:
    cursor = connection.cursor()
    for query, params in statements_with_params:
      cursor.execute(query, params)
    connection.commit()
    cursor.close()
  except Exception:
    connection.rollback()
    raise
  finally:
    connection.close()
