#!/usr/bin/env python3
"""
Real Industrial protocol server with IDS integration for dual-purpose legitimate service + attack detection.
Provides actual industrial protocol functionality (Modbus-like) while logging all connections to the IDS system.
"""

import socket
import threading
import json
import logging
import time
from datetime import datetime
import os
import struct

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class IDSAwareIndustrialServer:
    """Real Industrial protocol server with IDS monitoring capabilities (Modbus-like)."""
    
    def __init__(self, port=502, ids_log_file=None):
        self.port = port
        self.ids_log_file = ids_log_file or os.path.join(os.path.dirname(__file__), 'ids_industrial_events.log')
        self.server_socket = None
        self.server_thread = None
        self.running = False
        
        # Simulated industrial device registers
        self.registers = {
            1: 100,  # Temperature sensor
            2: 50,   # Pressure sensor
            3: 75,   # Flow rate
            4: 1,    # Pump status (on/off)
            5: 0,    # Valve position
            6: 60,   # Motor speed
            7: 25,   # Tank level
            8: 0,    # Alarm status
        }
    
    def _log_connection(self, client_ip, client_port, event_type, details=None):
        """Log industrial protocol connection events to IDS system."""
        timestamp = datetime.now().isoformat()
        
        log_entry = {
            "timestamp": timestamp,
            "source_ip": client_ip,
            "source_port": client_port,
            "protocol": "Industrial/Modbus",
            "event_type": event_type,
            "details": details or {}
        }
        
        # Log to file for IDS to read
        try:
            with open(self.ids_log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.error(f"Failed to write to IDS log: {e}")
        
        logger.info(f"{client_ip}:{client_port} - Industrial {event_type}")
    
    def _handle_modbus_request(self, data):
        """Handle Modbus-like request and return response."""
        try:
            if len(data) < 8:
                return None
            
            # Parse Modbus TCP header
            transaction_id = struct.unpack('>H', data[0:2])[0]
            protocol_id = struct.unpack('>H', data[2:4])[0]
            length = struct.unpack('>H', data[4:6])[0]
            unit_id = data[6]
            function_code = data[7]
            
            # Handle read holding registers (function code 3)
            if function_code == 3:
                if len(data) >= 10:
                    start_addr = struct.unpack('>H', data[8:10])[0]
                    register_count = struct.unpack('>H', data[10:12])[0]
                    
                    # Build response
                    byte_count = register_count * 2
                    response = struct.pack('>HHHBB', transaction_id, protocol_id, 
                                           byte_count + 3, unit_id, function_code)
                    response += struct.pack('B', byte_count)
                    
                    # Add register values
                    for i in range(register_count):
                        reg_addr = start_addr + i
                        value = self.registers.get(reg_addr, 0)
                        response += struct.pack('>H', value)
                    
                    return response
            
            # Handle write single register (function code 6)
            elif function_code == 6:
                if len(data) >= 12:
                    reg_addr = struct.unpack('>H', data[8:10])[0]
                    reg_value = struct.unpack('>H', data[10:12])[0]
                    
                    # Update register
                    self.registers[reg_addr] = reg_value
                    
                    # Echo back the write
                    response = data[0:12]
                    return response
            
            return None
            
        except Exception as e:
            logger.error(f"Error handling Modbus request: {e}")
            return None
    
    def _handle_industrial_connection(self, client_socket, client_address):
        """Handle individual industrial protocol connection."""
        client_ip, client_port = client_address
        logger.info(f"New industrial connection from {client_ip}:{client_port}")
        
        try:
            self._log_connection(client_ip, client_port, "industrial_connection_established")
            
            # Handle multiple requests
            while self.running:
                try:
                    client_socket.settimeout(5.0)
                    data = client_socket.recv(1024)
                    
                    if not data:
                        break
                    
                    self._log_connection(client_ip, client_port, "industrial_request_received",
                                      {"data_length": len(data)})
                    
                    # Process Modbus request
                    response = self._handle_modbus_request(data)
                    
                    if response:
                        client_socket.send(response)
                        self._log_connection(client_ip, client_port, "industrial_response_sent",
                                          {"response_length": len(response)})
                    else:
                        # Send error response
                        error_response = b"\x00\x00\x00\x00\x03\x01\x83\x02"  # Illegal function
                        client_socket.send(error_response)
                        self._log_connection(client_ip, client_port, "industrial_error_sent")
                        
                except socket.timeout:
                    # Keep alive
                    continue
                except Exception as e:
                    logger.error(f"Error in connection loop: {e}")
                    break
            
        except Exception as e:
            logger.error(f"Error handling industrial connection: {e}")
            self._log_connection(client_ip, client_port, "industrial_error", {"error": str(e)})
        finally:
            client_socket.close()
            self._log_connection(client_ip, client_port, "industrial_connection_closed")
    
    def start(self):
        """Start the industrial protocol server in a background thread."""
        if self.running:
            logger.warning("Industrial server is already running")
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
            
            logger.info(f"Industrial protocol server started on port {self.port}")
            logger.info(f"IDS logging to {self.ids_log_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start industrial server: {e}")
            return False
    
    def _run_server(self):
        """Main server loop."""
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                client_socket, client_address = self.server_socket.accept()
                
                # Handle connection in a new thread
                connection_thread = threading.Thread(
                    target=self._handle_industrial_connection,
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
        """Stop the industrial protocol server."""
        if not self.running:
            logger.warning("Industrial server is not running")
            return False
        
        try:
            self.running = False
            self.server_socket.close()
            logger.info("Industrial protocol server stopped")
            return True
        except Exception as e:
            logger.error(f"Failed to stop industrial server: {e}")
            return False
    
    def is_running(self):
        """Check if the server is running."""
        return self.running

def main():
    """Main entry point for standalone testing."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Real Industrial protocol server with IDS integration')
    parser.add_argument('--port', type=int, default=502, help='Port to listen on')
    parser.add_argument('--ids-log', type=str, help='Path to IDS log file')
    
    args = parser.parse_args()
    
    server = IDSAwareIndustrialServer(
        port=args.port,
        ids_log_file=args.ids_log
    )
    
    if server.start():
        print(f"Industrial protocol server running on port {args.port}")
        print(f"Connect with Modbus TCP client to localhost:{args.port}")
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
