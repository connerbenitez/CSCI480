#!/usr/bin/env python3
"""
Monitor real services (HTTP, SSH, Database, Industrial) and feed their connection logs into the IDS system.
This bridges the gap between legitimate services and the IDS detection system.
"""

import os
import json
import time
import threading
import logging
from datetime import datetime
from typing import Dict, List, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RealServiceMonitor:
    """Monitor real services and feed their logs into the IDS system."""
    
    def __init__(self, backend_dir=None):
        self.backend_dir = backend_dir or os.path.dirname(__file__)
        self.log_files = {
            'HTTP': os.path.join(self.backend_dir, 'ids_http_events.log'),
            'SSH': os.path.join(self.backend_dir, 'ids_ssh_events.log'),
            'Database': os.path.join(self.backend_dir, 'ids_db_events.log'),
            'Industrial': os.path.join(self.backend_dir, 'ids_industrial_events.log')
        }
        self.running = False
        self.monitor_thread = None
        self.event_handlers = []
        
        # Service ports mapping
        self.service_ports = {
            'HTTP': 8888,
            'SSH': 2222,
            'Database': 3307,
            'Industrial': 503
        }
        
        # Track file positions for tailing
        self.file_positions = {}
    
    def add_event_handler(self, handler):
        """Add a callback function to handle events from real services."""
        self.event_handlers.append(handler)
    
    def _read_new_events(self, log_file: str) -> List[Dict]:
        """Read new events from a log file since last read."""
        events = []
        try:
            if not os.path.exists(log_file):
                return events
            
            with open(log_file, 'r') as f:
                # Seek to last known position
                last_pos = self.file_positions.get(log_file, 0)
                f.seek(last_pos)
                
                # Read new lines
                new_lines = f.readlines()
                
                # Update position
                self.file_positions[log_file] = f.tell()
                
                # Parse events
                for line in new_lines:
                    try:
                        event = json.loads(line.strip())
                        events.append(event)
                    except json.JSONDecodeError:
                        continue
        
        except Exception as e:
            logger.error(f"Error reading {log_file}: {e}")
        
        return events
    
    def _monitor_loop(self):
        """Main monitoring loop that reads log files and processes events."""
        logger.info("Real service monitor started")
        
        while self.running:
            try:
                all_events = []
                
                # Read events from all log files
                for service_name, log_file in self.log_files.items():
                    events = self._read_new_events(log_file)
                    if events:
                        logger.info(f"Read {len(events)} new events from {service_name}")
                        for event in events:
                            event['service_name'] = service_name
                            event['service_port'] = self.service_ports.get(service_name)
                        all_events.extend(events)
                
                # Process events through handlers
                if all_events:
                    for handler in self.event_handlers:
                        try:
                            handler(all_events)
                        except Exception as e:
                            logger.error(f"Error in event handler: {e}")
                
                # Sleep before next check
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}")
                time.sleep(5)
        
        logger.info("Real service monitor stopped")
    
    def start(self):
        """Start monitoring real services."""
        if self.running:
            logger.warning("Monitor is already running")
            return False
        
        try:
            # Initialize file positions
            for log_file in self.log_files.values():
                if os.path.exists(log_file):
                    with open(log_file, 'r') as f:
                        f.seek(0, 2)  # Seek to end
                        self.file_positions[log_file] = f.tell()
            
            self.running = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            
            logger.info("Real service monitor started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start monitor: {e}")
            return False
    
    def stop(self):
        """Stop monitoring real services."""
        if not self.running:
            logger.warning("Monitor is not running")
            return False
        
        try:
            self.running = False
            if self.monitor_thread:
                self.monitor_thread.join(timeout=5)
            logger.info("Real service monitor stopped")
            return True
        except Exception as e:
            logger.error(f"Failed to stop monitor: {e}")
            return False
    
    def is_running(self):
        """Check if monitor is running."""
        return self.running
    
    def get_service_status(self) -> Dict:
        """Get status of all monitored services."""
        status = {}
        for service_name, log_file in self.log_files.items():
            status[service_name] = {
                'log_file': log_file,
                'log_exists': os.path.exists(log_file),
                'port': self.service_ports.get(service_name),
                'last_position': self.file_positions.get(log_file, 0)
            }
        return status

# Global instance
REAL_SERVICE_MONITOR = RealServiceMonitor()

def start_real_service_monitor():
    """Start the global real service monitor."""
    return REAL_SERVICE_MONITOR.start()

def stop_real_service_monitor():
    """Stop the global real service monitor."""
    return REAL_SERVICE_MONITOR.stop()

def get_real_service_status():
    """Get status of all real services."""
    return REAL_SERVICE_MONITOR.get_service_status()

if __name__ == "__main__":
    # Test the monitor
    monitor = RealServiceMonitor()
    
    def test_handler(events):
        print(f"Received {len(events)} events:")
        for event in events:
            print(f"  - {event.get('service_name')}: {event.get('source_ip')} -> {event.get('event_type')}")
    
    monitor.add_event_handler(test_handler)
    
    if monitor.start():
        print("Monitor started. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping...")
            monitor.stop()
