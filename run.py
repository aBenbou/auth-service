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
    else:
        parser.print_help()

if __name__ == "__main__":
    main() 