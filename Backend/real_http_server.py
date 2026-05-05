#!/usr/bin/env python3
"""
Real HTTP server with IDS integration for dual-purpose legitimate service + attack detection.
Serves actual web content while logging all connections to the IDS system.
"""

import http.server
import socketserver
import threading
import json
import logging
from datetime import datetime
import os
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# IDS integration endpoint
IDS_API_URL = "http://127.0.0.1:5000/api/decoy_event"

class IDSAwareHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP request handler that logs connections to IDS system."""
    
    def __init__(self, *args, **kwargs):
        self.ids_log_file = kwargs.pop('ids_log_file', None)
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        """Override to send logs to IDS system."""
        client_ip = self.client_address[0]
        client_port = self.client_address[1]
        timestamp = datetime.now().isoformat()
        
        log_entry = {
            "timestamp": timestamp,
            "source_ip": client_ip,
            "source_port": client_port,
            "protocol": "HTTP",
            "method": self.command,
            "path": self.path,
            "user_agent": self.headers.get('User-Agent', 'unknown'),
            "event_type": "http_request"
        }
        
        # Log to file for IDS to read
        if self.ids_log_file:
            try:
                with open(self.ids_log_file, 'a') as f:
                    f.write(json.dumps(log_entry) + '\n')
            except Exception as e:
                logger.error(f"Failed to write to IDS log: {e}")
        
        # Also log to console
        logger.info(f"{client_ip}:{client_port} - {self.command} {self.path}")
        
        # Call parent log_message
        super().log_message(format, *args)
    
    def end_headers(self):
        """Add security headers."""
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Server', 'IDS-Monitored-HTTP/1.0')
        super().end_headers()

class RealHTTPServer:
    """Real HTTP server with IDS monitoring capabilities."""
    
    def __init__(self, port=8080, directory=None, ids_log_file=None):
        self.port = port
        self.directory = directory or os.path.join(os.path.dirname(__file__), '..', 'web_content')
        self.ids_log_file = ids_log_file or os.path.join(os.path.dirname(__file__), 'ids_http_events.log')
        self.server = None
        self.server_thread = None
        self.running = False
        
        # Create web content directory if it doesn't exist
        os.makedirs(self.directory, exist_ok=True)
        self._create_default_content()
    
    def _create_default_content(self):
        """Create default web content for the server."""
        index_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IDS Demo Web Server</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
        .status { background: #d4edda; color: #155724; padding: 10px; border-radius: 4px; margin: 20px 0; }
        .info { background: #d1ecf1; color: #0c5460; padding: 10px; border-radius: 4px; margin: 10px 0; }
        footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>IDS Demo Web Server</h1>
        <div class="status">
            <strong>Status:</strong> Online and monitored by IDS
        </div>
        <div class="info">
            <strong>Info:</strong> This is a legitimate web server with IDS integration. All connections are logged for security monitoring.
        </div>
        <h2>Features</h2>
        <ul>
            <li>Real HTTP server serving legitimate content</li>
            <li>All requests logged to IDS system for attack detection</li>
            <li>Dual-purpose: legitimate use + security monitoring</li>
            <li>Can detect suspicious patterns like brute force, scanning, etc.</li>
        </ul>
        <h2>Test Endpoints</h2>
        <ul>
            <li><a href="/api/test">/api/test</a> - Test API endpoint</li>
            <li><a href="/admin">/admin</a> - Admin panel (simulated)</li>
            <li><a href="/login">/login</a> - Login page (simulated)</li>
        </ul>
        <footer>
            IDS Demo Server - All connections monitored | Generated for academic demonstration
        </footer>
    </div>
</body>
</html>"""
        
        with open(os.path.join(self.directory, 'index.html'), 'w') as f:
            f.write(index_html)
        
        logger.info(f"Created default web content in {self.directory}")
    
    def start(self):
        """Start the HTTP server in a background thread."""
        if self.running:
            logger.warning("Server is already running")
            return False
        
        try:
            # Change to the web content directory
            original_dir = os.getcwd()
            os.chdir(self.directory)
            
            # Create handler with IDS logging
            handler = IDSAwareHTTPRequestHandler
            handler.ids_log_file = self.ids_log_file
            
            self.server = socketserver.TCPServer(("", self.port), handler)
            self.server.allow_reuse_address = True
            
            # Start server in background thread
            self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.server_thread.start()
            
            self.running = True
            os.chdir(original_dir)
            
            logger.info(f"HTTP server started on port {self.port}, serving from {self.directory}")
            logger.info(f"IDS logging to {self.ids_log_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start HTTP server: {e}")
            os.chdir(original_dir)
            return False
    
    def stop(self):
        """Stop the HTTP server."""
        if not self.running:
            logger.warning("Server is not running")
            return False
        
        try:
            self.server.shutdown()
            self.server.server_close()
            self.running = False
            logger.info("HTTP server stopped")
            return True
        except Exception as e:
            logger.error(f"Failed to stop HTTP server: {e}")
            return False
    
    def is_running(self):
        """Check if the server is running."""
        return self.running

def main():
    """Main entry point for standalone testing."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Real HTTP server with IDS integration')
    parser.add_argument('--port', type=int, default=8080, help='Port to listen on')
    parser.add_argument('--directory', type=str, help='Directory to serve')
    parser.add_argument('--ids-log', type=str, help='Path to IDS log file')
    
    args = parser.parse_args()
    
    server = RealHTTPServer(
        port=args.port,
        directory=args.directory,
        ids_log_file=args.ids_log
    )
    
    if server.start():
        print(f"HTTP server running on port {args.port}")
        print(f"Access at http://localhost:{args.port}")
        print("Press Ctrl+C to stop")
        
        try:
            while True:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down...")
            server.stop()
    else:
        print("Failed to start server")
        sys.exit(1)

if __name__ == "__main__":
    main()
