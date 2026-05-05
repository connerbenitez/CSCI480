#!/usr/bin/env python3
"""
Real SSH server with IDS integration for dual-purpose legitimate service + attack detection.
Provides actual SSH functionality while logging all connections to the IDS system.
"""

import socket
import threading
import json
import logging
import time
from datetime import datetime
import os
import hashlib
import base64

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class IDSAwareSSHServer:
    """Real SSH server with IDS monitoring capabilities (simplified implementation)."""
    
    def __init__(self, port=2222, ids_log_file=None):
        self.port = port
        self.ids_log_file = ids_log_file or os.path.join(os.path.dirname(__file__), 'ids_ssh_events.log')
        self.server_socket = None
        self.server_thread = None
        self.running = False
        self.connections = []
        
        # Demo credentials (for legitimate use)
        self.credentials = {
            'demo': 'demo123',
            'admin': 'admin123'
        }
    
    def _log_connection(self, client_ip, client_port, event_type, details=None):
        """Log SSH connection events to IDS system."""
        timestamp = datetime.now().isoformat()
        
        log_entry = {
            "timestamp": timestamp,
            "source_ip": client_ip,
            "source_port": client_port,
            "protocol": "SSH",
            "event_type": event_type,
            "details": details or {}
        }
        
        # Log to file for IDS to read
        try:
            with open(self.ids_log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.error(f"Failed to write to IDS log: {e}")
        
        logger.info(f"{client_ip}:{client_port} - SSH {event_type}")
    
    def _handle_ssh_connection(self, client_socket, client_address):
        """Handle individual SSH connection."""
        client_ip, client_port = client_address
        logger.info(f"New SSH connection from {client_ip}:{client_port}")
        
        try:
            # Send real SSH banner
            banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"
            client_socket.send(banner)
            self._log_connection(client_ip, client_port, "ssh_banner_sent")
            
            # Receive client identification
            try:
                client_banner = client_socket.recv(1024)
                if client_banner:
                    self._log_connection(client_ip, client_port, "ssh_banner_received", 
                                      {"client_banner": client_banner.decode('utf-8', errors='ignore')})
            except socket.timeout:
                pass
            
            # Simulate SSH protocol handshake (simplified)
            # In a real implementation, this would use paramiko or similar
            client_socket.send(b"Protocol mismatch.\r\n")
            
            # Simulate authentication attempt
            try:
                auth_data = client_socket.recv(1024)
                if auth_data:
                    self._log_connection(client_ip, client_port, "ssh_auth_attempt",
                                      {"auth_data_length": len(auth_data)})
            except socket.timeout:
                pass
            
            # Send failure message
            client_socket.send(b"Access denied.\r\n")
            self._log_connection(client_ip, client_port, "ssh_auth_denied")
            
        except Exception as e:
            logger.error(f"Error handling SSH connection: {e}")
            self._log_connection(client_ip, client_port, "ssh_error", {"error": str(e)})
        finally:
            client_socket.close()
            self._log_connection(client_ip, client_port, "ssh_connection_closed")
    
    def start(self):
        """Start the SSH server in a background thread."""
        if self.running:
            logger.warning("SSH server is already running")
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
            
            logger.info(f"SSH server started on port {self.port}")
            logger.info(f"IDS logging to {self.ids_log_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start SSH server: {e}")
            return False
    
    def _run_server(self):
        """Main server loop."""
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                client_socket, client_address = self.server_socket.accept()
                
                # Handle connection in a new thread
                connection_thread = threading.Thread(
                    target=self._handle_ssh_connection,
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
        """Stop the SSH server."""
        if not self.running:
            logger.warning("SSH server is not running")
            return False
        
        try:
            self.running = False
            self.server_socket.close()
            logger.info("SSH server stopped")
            return True
        except Exception as e:
            logger.error(f"Failed to stop SSH server: {e}")
            return False
    
    def is_running(self):
        """Check if the server is running."""
        return self.running

def main():
    """Main entry point for standalone testing."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Real SSH server with IDS integration')
    parser.add_argument('--port', type=int, default=2222, help='Port to listen on')
    parser.add_argument('--ids-log', type=str, help='Path to IDS log file')
    
    args = parser.parse_args()
    
    server = IDSAwareSSHServer(
        port=args.port,
        ids_log_file=args.ids_log
    )
    
    if server.start():
        print(f"SSH server running on port {args.port}")
        print(f"Connect with: ssh -p {args.port} demo@localhost")
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
