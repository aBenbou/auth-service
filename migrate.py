#!/usr/bin/env python3
import os
import sys
import argparse
import datetime
import sqlite3
import psycopg2
import re
from app.config import Config

def get_timestamp():
    """Generate a timestamp for migration files in the format YYYYMMDDHHMMSS"""
    return datetime.datetime.now().strftime("%Y%m%d%H%M%S")

def create_migration(name):
    """Create new migration files with the given name"""
    timestamp = get_timestamp()
    filename = f"{timestamp}-{name.replace(' ', '_').lower()}.sql"
    
    # Create migrations directories if they don't exist
    os.makedirs(os.path.join("migrations", "up"), exist_ok=True)
    os.makedirs(os.path.join("migrations", "down"), exist_ok=True)
    
    # Create up migration file
    up_path = os.path.join("migrations", "up", filename)
    with open(up_path, "w") as f:
        f.write(f"-- Migration: {name}\n")
        f.write(f"-- Created at: {datetime.datetime.now().isoformat()}\n\n")
        f.write("-- Write your UP migration SQL here\n\n")
    
    # Create down migration file
    down_path = os.path.join("migrations", "down", filename)
    with open(down_path, "w") as f:
        f.write(f"-- Migration: {name}\n")
        f.write(f"-- Created at: {datetime.datetime.now().isoformat()}\n\n")
        f.write("-- Write your DOWN migration SQL here\n\n")
    
    print(f"Created migration files:")
    print(f"  - {up_path}")
    print(f"  - {down_path}")

def get_db_connection():
    """Get a database connection based on the configured DATABASE_URI"""
    db_uri = os.getenv('DATABASE_URI', Config.SQLALCHEMY_DATABASE_URI)
    
    if db_uri.startswith('postgresql://') or db_uri.startswith('postgres://'):
        # PostgreSQL connection
        match = re.match(r'postgres(?:ql)?://([^:]+):([^@]+)@([^:]+):(\d+)/([^?]+)', db_uri)
        if match:
            user, password, host, port, dbname = match.groups()
            conn = psycopg2.connect(
                host=host,
                port=port,
                dbname=dbname,
                user=user,
                password=password
            )
            return conn, 'postgresql'
        else:
            raise ValueError(f"Invalid PostgreSQL connection string: {db_uri}")
    else:
        # SQLite connection (for development/testing)
        sqlite_path = db_uri.replace('sqlite:///', '')
        conn = sqlite3.connect(sqlite_path)
        return conn, 'sqlite'

def ensure_migrations_table(conn, db_type):
    """Ensure the migrations tracking table exists"""
    cursor = conn.cursor()
    
    if db_type == 'postgresql':
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS migrations (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """)
    else:  # sqlite
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS migrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """)
    
    conn.commit()
    return cursor

def get_applied_migrations(cursor):
    """Get list of applied migrations"""
    cursor.execute("SELECT name FROM migrations ORDER BY id")
    return [row[0] for row in cursor.fetchall()]

def run_migration(conn, cursor, migration_path, migration_name, db_type):
    """Run a single migration file"""
    with open(migration_path, "r") as f:
        sql = f.read()
    
    if db_type == 'postgresql':
        # For PostgreSQL, execute as a single statement (supports multi-statement scripts)
        cursor.execute(sql)
        # Record the migration
        cursor.execute("INSERT INTO migrations (name) VALUES (%s)", (migration_name,))
    else:  # sqlite
        # Split the SQL into individual statements
        statements = sql.split(';')
        
        # Execute each statement
        for statement in statements:
            # Skip empty statements
            if statement.strip():
                cursor.execute(statement)
        
        # Record the migration
        cursor.execute("INSERT INTO migrations (name) VALUES (?)", (migration_name,))
    
    conn.commit()
    print(f"Applied: {migration_name}")

def remove_migration(conn, cursor, migration_path, migration_name, db_type):
    """Remove a migration from the tracking table"""
    if os.path.exists(migration_path):
        with open(migration_path, "r") as f:
            sql = f.read()
        
        if db_type == 'postgresql':
            # For PostgreSQL, execute as a single statement
            cursor.execute(sql)
            # Remove the migration record
            cursor.execute("DELETE FROM migrations WHERE name = %s", (migration_name,))
        else:  # sqlite
            # Split the SQL into individual statements
            statements = sql.split(';')
            
            # Execute each statement
            for statement in statements:
                # Skip empty statements
                if statement.strip():
                    cursor.execute(statement)
            
            # Remove the migration record
            cursor.execute("DELETE FROM migrations WHERE name = ?", (migration_name,))
        
        conn.commit()
        print(f"Reverted: {migration_name}")
    else:
        print(f"Warning: Down migration file not found for {migration_name}")

def run_migrations(direction, steps=None):
    """Run migrations in the specified direction (up or down)"""
    conn, db_type = get_db_connection()
    cursor = ensure_migrations_table(conn, db_type)
    
    print(f"Using {db_type.upper()} database")
    
    applied_migrations = get_applied_migrations(cursor)
    
    if direction == 'up':
        # Get all migration files
        migration_files = sorted([f for f in os.listdir(os.path.join("migrations", "up")) if f.endswith('.sql')])
        
        # Filter out already applied migrations
        pending_migrations = [f for f in migration_files if f not in applied_migrations]
        
        # Apply step limit if specified
        if steps is not None:
            pending_migrations = pending_migrations[:steps]
        
        # Apply migrations
        for migration in pending_migrations:
            migration_path = os.path.join("migrations", "up", migration)
            run_migration(conn, cursor, migration_path, migration, db_type)
    
    elif direction == 'down':
        # Get applied migrations in reverse order
        migrations_to_revert = list(reversed(applied_migrations))
        
        # Apply step limit if specified
        if steps is not None:
            migrations_to_revert = migrations_to_revert[:steps]
        
        # Revert migrations
        for migration in migrations_to_revert:
            migration_path = os.path.join("migrations", "down", migration)
            remove_migration(conn, cursor, migration_path, migration, db_type)
    
    conn.close()

def main():
    parser = argparse.ArgumentParser(description="Database migration utility")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Create migration command
    create_parser = subparsers.add_parser("create", help="Create a new migration")
    create_parser.add_argument("name", help="Name of the migration")
    
    # Up migration command
    up_parser = subparsers.add_parser("up", help="Run up migrations")
    up_parser.add_argument("--steps", type=int, help="Number of migrations to apply")
    
    # Down migration command
    down_parser = subparsers.add_parser("down", help="Run down migrations")
    down_parser.add_argument("--steps", type=int, help="Number of migrations to revert")
    
    args = parser.parse_args()
    
    if args.command == "create":
        create_migration(args.name)
    elif args.command == "up":
        run_migrations("up", args.steps)
    elif args.command == "down":
        run_migrations("down", args.steps)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()