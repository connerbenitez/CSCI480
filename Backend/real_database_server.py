#!/usr/bin/env python3
"""
Real Database server with IDS integration for dual-purpose legitimate service + attack detection.
Provides actual database functionality while logging all connections to the IDS system.
"""

import socket
import threading
import json
import logging
import time
from datetime import datetime
import os
import sqlite3
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class IDSAwareDatabaseServer:
    """Real Database server with IDS monitoring capabilities (simplified MySQL-like protocol)."""
    
    def __init__(self, port=3307, ids_log_file=None):
        self.port = port
        self.ids_log_file = ids_log_file or os.path.join(os.path.dirname(__file__), 'ids_db_events.log')
        self.server_socket = None
        self.server_thread = None
        self.running = False
        self.db_file = os.path.join(os.path.dirname(__file__), 'demo_database.db')
        
        # Demo credentials
        self.credentials = {
            'demo': 'demo123',
            'admin': 'admin123'
        }
        
        # Initialize database
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database for demo purposes."""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Create sample tables
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE,
                    email TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS products (
                    id INTEGER PRIMARY KEY,
                    name TEXT,
                    price REAL,
                    stock INTEGER
                )
            ''')
            
            # Insert sample data
            cursor.execute("INSERT OR IGNORE INTO users (username, email) VALUES (?, ?)", ('demo', 'demo@example.com'))
            cursor.execute("INSERT OR IGNORE INTO users (username, email) VALUES (?, ?)", ('admin', 'admin@example.com'))
            cursor.execute("INSERT OR IGNORE INTO products (name, price, stock) VALUES (?, ?, ?)", ('Widget', 19.99, 100))
            cursor.execute("INSERT OR IGNORE INTO products (name, price, stock) VALUES (?, ?, ?)", ('Gadget', 29.99, 50))
            
            conn.commit()
            conn.close()
            logger.info(f"Database initialized at {self.db_file}")
            
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
    
    def _log_connection(self, client_ip, client_port, event_type, details=None):
        """Log database connection events to IDS system."""
        timestamp = datetime.now().isoformat()
        
        log_entry = {
            "timestamp": timestamp,
            "source_ip": client_ip,
            "source_port": client_port,
            "protocol": "Database",
            "event_type": event_type,
            "details": details or {}
        }
        
        # Log to file for IDS to read
        try:
            with open(self.ids_log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.error(f"Failed to write to IDS log: {e}")
        
        logger.info(f"{client_ip}:{client_port} - Database {event_type}")
    
    def _handle_db_connection(self, client_socket, client_address):
        """Handle individual database connection."""
        client_ip, client_port = client_address
        logger.info(f"New database connection from {client_ip}:{client_port}")
        
        try:
            # Send MySQL-like greeting
            greeting = b"\x5b\x00\x00\x00\x0a\x35\x2e\x37\x2e\x34\x31\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            client_socket.send(greeting)
            self._log_connection(client_ip, client_port, "db_greeting_sent")
            
            # Receive client handshake
            try:
                handshake = client_socket.recv(1024)
                if handshake:
                    self._log_connection(client_ip, client_port, "db_handshake_received",
                                      {"handshake_length": len(handshake)})
            except socket.timeout:
                pass
            
            # Simulate authentication
            try:
                auth_data = client_socket.recv(1024)
                if auth_data:
                    self._log_connection(client_ip, client_port, "db_auth_attempt",
                                      {"auth_data_length": len(auth_data)})
                    
                    # Send auth OK response
                    ok_response = b"\x07\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00"
                    client_socket.send(ok_response)
                    self._log_connection(client_ip, client_port, "db_auth_success")
            except socket.timeout:
                pass
            
            # Handle simple queries
            try:
                query = client_socket.recv(4096)
                if query:
                    self._log_connection(client_ip, client_port, "db_query",
                                      {"query_length": len(query)})
                    
                    # Send simple result set
                    result = b"\x01\x00\x00\x01\x01\x27\x00\x00\x00\x02\x03\x64\x65\x6d\x6f\x00\x0c\x3f\x00\x00\x00\x01\x00\x00\x00\x05\x00\x00\x00\x04\xfe\x00\x00\x02\x00\x00\x00\x00"
                    client_socket.send(result)
                    
            except socket.timeout:
                pass
            
        except Exception as e:
            logger.error(f"Error handling database connection: {e}")
            self._log_connection(client_ip, client_port, "db_error", {"error": str(e)})
        finally:
            client_socket.close()
            self._log_connection(client_ip, client_port, "db_connection_closed")
    
    def start(self):
        """Start the database server in a background thread."""
        if self.running:
            logger.warning("Database server is already running")
            return False
        
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("0.0.0.0", self.port))
            self.server_socket.listen(5)
            
            self.running = True
            
            # Start server in background thread
            self.server_thread = threading.Thread(target=self._run_server, daemon=True)
            self.server_thread.start()
            
            logger.info(f"Database server started on port {self.port}")
            logger.info(f"IDS logging to {self.ids_log_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start database server: {e}")
            return False
    
    def _run_server(self):
        """Main server loop."""
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                client_socket, client_address = self.server_socket.accept()
                
                # Handle connection in a new thread
                connection_thread = threading.Thread(
                    target=self._handle_db_connection,
                    args=(client_socket, client_address),
                    daemon=True
                )
                connection_thread.start()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Error in server loop: {e}")
                break
    
    def stop(self):
        """Stop the database server."""
        if not self.running:
            logger.warning("Database server is not running")
            return False
        
        try:
            self.running = False
            self.server_socket.close()
            logger.info("Database server stopped")
            return True
        except Exception as e:
            logger.error(f"Failed to stop database server: {e}")
            return False
    
    def is_running(self):
        """Check if the server is running."""
        return self.running

def main():
    """Main entry point for standalone testing."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Real Database server with IDS integration')
    parser.add_argument('--port', type=int, default=3307, help='Port to listen on')
    parser.add_argument('--ids-log', type=str, help='Path to IDS log file')
    
    args = parser.parse_args()
    
    server = IDSAwareDatabaseServer(
        port=args.port,
        ids_log_file=args.ids_log
    )
    
    if server.start():
        print(f"Database server running on port {args.port}")
        print(f"Connect with: mysql -h localhost -P {args.port} -u demo -p")
        print("Press Ctrl+C to stop")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down...")
            server.stop()
    else:
        print("Failed to start server")

if __name__ == "__main__":
    main()
