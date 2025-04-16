#!/usr/bin/env python3
import os
import sys
import json
import sqlite3
import psycopg2
import argparse
from datetime import datetime

def sqlite_export(sqlite_db_path, output_file):
    """Export data from SQLite database to JSON file"""
    # Connect to SQLite database
    conn = sqlite3.connect(sqlite_db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get all table names
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall()]
    
    # Exclude SQLite internal tables
    tables = [table for table in tables if not table.startswith('sqlite_')]
    
    # Export data from each table
    data = {}
    for table in tables:
        cursor.execute(f"SELECT * FROM {table};")
        rows = cursor.fetchall()
        
        # Convert rows to list of dictionaries
        table_data = []
        for row in rows:
            row_dict = {key: row[key] for key in row.keys()}
            # Convert datetime objects to ISO format
            for key, value in row_dict.items():
                if isinstance(value, datetime):
                    row_dict[key] = value.isoformat()
            table_data.append(row_dict)
        
        data[table] = table_data
    
    # Write data to JSON file
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    conn.close()
    print(f"Data exported to {output_file}")
    return data

def postgres_import(postgres_conn_string, input_file):
    """Import data from JSON file to PostgreSQL database"""
    # Connect to PostgreSQL database
    conn = psycopg2.connect(postgres_conn_string)
    cursor = conn.cursor()
    
    # Read data from JSON file
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    # Import data into each table
    for table, rows in data.items():
        if not rows:
            print(f"No data for table {table}, skipping")
            continue
        
        print(f"Importing {len(rows)} rows into {table}")
        
        # Get column names from first row
        columns = list(rows[0].keys())
        placeholders = ', '.join(['%s'] * len(columns))
        columns_str = ', '.join(columns)
        
        # Prepare and execute insert statement for each row
        for row in rows:
            values = [row[col] for col in columns]
            query = f"INSERT INTO {table} ({columns_str}) VALUES ({placeholders})"
            try:
                cursor.execute(query, values)
            except Exception as e:
                print(f"Error importing row into {table}: {e}")
                print(f"Row data: {row}")
                conn.rollback()
                continue
        
        conn.commit()
    
    conn.close()
    print(f"Data imported from {input_file}")

def main():
    parser = argparse.ArgumentParser(description="SQLite to PostgreSQL data migration tool")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # SQLite export command
    export_parser = subparsers.add_parser("sqlite-export", help="Export data from SQLite to JSON")
    export_parser.add_argument("sqlite_db", help="Path to SQLite database file")
    export_parser.add_argument("output_file", help="Output JSON file path")
    
    # PostgreSQL import command
    import_parser = subparsers.add_parser("postgres-import", help="Import data from JSON to PostgreSQL")
    import_parser.add_argument("postgres_conn", help="PostgreSQL connection string")
    import_parser.add_argument("input_file", help="Input JSON file path")
    
    args = parser.parse_args()
    
    if args.command == "sqlite-export":
        sqlite_export(args.sqlite_db, args.output_file)
    elif args.command == "postgres-import":
        postgres_import(args.postgres_conn, args.input_file)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()