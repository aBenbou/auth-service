#!/usr/bin/env python3
import sys
import argparse
from app import create_app

# Create the Flask application instance
app = create_app()

def main():
    parser = argparse.ArgumentParser(description="Auth API Server")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Run server command
    run_parser = subparsers.add_parser("run", help="Run the API server")
    run_parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    run_parser.add_argument("--port", type=int, default=5000, help="Port to bind to")
    run_parser.add_argument("--debug", action="store_true", help="Run in debug mode")
    
    # Migration commands
    migrate_parser = subparsers.add_parser("migrate", help="Run database migrations")
    migrate_subparsers = migrate_parser.add_subparsers(dest="migrate_command", help="Migration command")
    
    # Create migration command
    create_parser = migrate_subparsers.add_parser("create", help="Create a new migration")
    create_parser.add_argument("name", help="Name of the migration")
    
    # Up migration command
    up_parser = migrate_subparsers.add_parser("up", help="Run up migrations")
    up_parser.add_argument("--steps", type=int, help="Number of migrations to apply")
    
    # Down migration command
    down_parser = migrate_subparsers.add_parser("down", help="Run down migrations")
    down_parser.add_argument("--steps", type=int, help="Number of migrations to revert")
    
    # Database data migration commands
    data_parser = subparsers.add_parser("db", help="Database data migration commands")
    data_subparsers = data_parser.add_subparsers(dest="db_command", help="Database command")
    
    # SQLite export command
    export_parser = data_subparsers.add_parser("sqlite-export", help="Export data from SQLite to JSON")
    export_parser.add_argument("output_file", help="Output JSON file path")
    export_parser.add_argument("--sqlite-db", default="auth.db", help="Path to SQLite database file (default: auth.db)")
    
    # PostgreSQL import command
    import_parser = data_subparsers.add_parser("postgres-import", help="Import data from JSON to PostgreSQL")
    import_parser.add_argument("input_file", help="Input JSON file path")
    import_parser.add_argument("--postgres-conn", help="PostgreSQL connection string (default: from DATABASE_URI env var)")
    
    args = parser.parse_args()
    
    if args.command == "run" or args.command is None:
        # Run the server
        app.run(
            host=getattr(args, "host", "0.0.0.0"),
            port=getattr(args, "port", 5000),
            debug=getattr(args, "debug", False)
        )
    elif args.command == "migrate":
        # Import the migration script and run the appropriate command
        from migrate import create_migration, run_migrations
        
        if args.migrate_command == "create":
            create_migration(args.name)
        elif args.migrate_command == "up":
            run_migrations("up", args.steps)
        elif args.migrate_command == "down":
            run_migrations("down", args.steps)
        else:
            migrate_parser.print_help()
    elif args.command == "db":
        # Import the database migration utilities
        from utils.db_migration import sqlite_export, postgres_import
        import os
        
        if args.db_command == "sqlite-export":
            sqlite_db = args.sqlite_db
            output_file = args.output_file
            sqlite_export(sqlite_db, output_file)
        elif args.db_command == "postgres-import":
            input_file = args.input_file
            postgres_conn = args.postgres_conn
            if postgres_conn is None:
                # Get from environment
                postgres_conn = os.environ.get('DATABASE_URI')
                if not postgres_conn or not (postgres_conn.startswith('postgresql://') or postgres_conn.startswith('postgres://')):
                    print("Error: PostgreSQL connection string not provided and DATABASE_URI is not set to a PostgreSQL connection")
                    sys.exit(1)
            postgres_import(postgres_conn, input_file)
        else:
            data_parser.print_help()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()