#!/usr/bin/env python3
"""
SecureNet-Monitor: Core Network Monitoring Module
Real-time network security monitoring with Scapy
"""

import threading
import time
import sqlite3
from datetime import datetime
from collections import defaultdict, deque
from scapy.all import *
import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NetworkMonitor:
    def __init__(self, interface=None, db_path='security_events.db'):
        self.interface = interface
        self.db_path = db_path
        self.running = False
        self.packet_count = 0
        
        # Threat detection data structures
        self.port_scan_tracker = defaultdict(lambda: defaultdict(set))
        self.connection_tracker = defaultdict(lambda: deque(maxlen=100))
        self.failed_login_tracker = defaultdict(lambda: deque(maxlen=50))
        
        # Detection thresholds
        self.PORT_SCAN_THRESHOLD = 10  # ports scanned from same IP
        self.DDOS_THRESHOLD = 100      # packets per second from same IP
        self.BRUTE_FORCE_THRESHOLD = 5 # failed attempts in time window
        
        # Initialize database
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database for logging security events"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT,
                port INTEGER,
                protocol TEXT,
                severity TEXT NOT NULL,
                description TEXT,
                raw_data TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                total_packets INTEGER,
                threats_detected INTEGER,
                active_connections INTEGER
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info(f"Database initialized: {self.db_path}")

    def log_security_event(self, event_type, source_ip, dest_ip=None, port=None, 
                          protocol=None, severity='MEDIUM', description='', raw_data=''):
        """Log security event to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO security_events 
            (timestamp, event_type, source_ip, destination_ip, port, protocol, severity, description, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            event_type,
            source_ip,
            dest_ip,
            port,
            protocol,
            severity,
            description,
            raw_data
        ))
        
        conn.commit()
        conn.close()
        
        logger.warning(f"{severity} {event_type}: {source_ip} -> {dest_ip}:{port} - {description}")

    def detect_port_scan(self, packet):
        """Detect port scanning attempts"""
        if packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            
            # Track ports accessed by each source IP
            self.port_scan_tracker[src_ip][dst_ip].add(dst_port)
            
            # Check if threshold exceeded
            if len(self.port_scan_tracker[src_ip][dst_ip]) >= self.PORT_SCAN_THRESHOLD:
                ports_scanned = list(self.port_scan_tracker[src_ip][dst_ip])
                description = f"Port scan detected: {len(ports_scanned)} ports scanned"
                
                self.log_security_event(
                    'PORT_SCAN',
                    src_ip,
                    dst_ip,
                    dst_port,
                    'TCP',
                    'HIGH',
                    description,
                    json.dumps({'ports': ports_scanned})
                )
                
                # Reset tracker for this IP pair
                self.port_scan_tracker[src_ip][dst_ip].clear()
                return True
        return False

    def detect_ddos(self, packet):
        """Detect potential DDoS attacks"""
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            current_time = time.time()
            
            # Add timestamp to connection tracker
            self.connection_tracker[src_ip].append(current_time)
            
            # Count packets in last second
            recent_packets = [t for t in self.connection_tracker[src_ip] if current_time - t <= 1.0]
            
            if len(recent_packets) >= self.DDOS_THRESHOLD:
                description = f"Potential DDoS: {len(recent_packets)} packets/second"
                
                self.log_security_event(
                    'DDOS_ATTEMPT',
                    src_ip,
                    packet[IP].dst if packet.haslayer(IP) else None,
                    None,
                    packet[IP].proto if packet.haslayer(IP) else None,
                    'CRITICAL',
                    description,
                    json.dumps({'packets_per_second': len(recent_packets)})
                )
                return True
        return False

    def detect_brute_force(self, packet):
        """Detect brute force login attempts"""
        if packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            
            # Focus on common login ports
            login_ports = [22, 23, 21, 25, 110, 143, 993, 995, 3389]
            
            if dst_port in login_ports:
                current_time = time.time()
                self.failed_login_tracker[src_ip].append(current_time)
                
                # Count attempts in last 5 minutes
                recent_attempts = [t for t in self.failed_login_tracker[src_ip] 
                                 if current_time - t <= 300]
                
                if len(recent_attempts) >= self.BRUTE_FORCE_THRESHOLD:
                    description = f"Brute force attempt: {len(recent_attempts)} attempts on port {dst_port}"
                    
                    self.log_security_event(
                        'BRUTE_FORCE',
                        src_ip,
                        packet[IP].dst,
                        dst_port,
                        'TCP',
                        'HIGH',
                        description,
                        json.dumps({'attempts': len(recent_attempts), 'port': dst_port})
                    )
                    return True
        return False

    def analyze_packet(self, packet):
        """Analyze individual packet for threats"""
        self.packet_count += 1
        
        # Run threat detection algorithms
        threats_detected = []
        
        if self.detect_port_scan(packet):
            threats_detected.append('PORT_SCAN')
            
        if self.detect_ddos(packet):
            threats_detected.append('DDOS')
            
        if self.detect_brute_force(packet):
            threats_detected.append('BRUTE_FORCE')
        
        return threats_detected

    def packet_handler(self, packet):
        """Main packet processing handler"""
        try:
            if packet.haslayer(IP):
                threats = self.analyze_packet(packet)
                
                # Log packet statistics every 1000 packets
                if self.packet_count % 1000 == 0:
                    self.log_network_stats()
                    
        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def log_network_stats(self):
        """Log network statistics to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Count recent threats
        cursor.execute('''
            SELECT COUNT(*) FROM security_events 
            WHERE timestamp > datetime('now', '-1 hour')
        ''')
        recent_threats = cursor.fetchone()[0]
        
        cursor.execute('''
            INSERT INTO network_stats (timestamp, total_packets, threats_detected, active_connections)
            VALUES (?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            self.packet_count,
            recent_threats,
            len(self.connection_tracker)
        ))
        
        conn.commit()
        conn.close()

    def start_monitoring(self):
        """Start network monitoring"""
        self.running = True
        logger.info(f"Starting network monitoring on interface: {self.interface or 'default'}")
        
        try:
            # Start packet capture
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                store=0,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")
        finally:
            self.running = False

    def stop_monitoring(self):
        """Stop network monitoring"""
        self.running = False
        logger.info("Network monitoring stopped")

    def get_recent_events(self, limit=50):
        """Get recent security events from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM security_events 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
        
        events = cursor.fetchall()
        conn.close()
        
        return events

    def get_network_stats(self):
        """Get current network statistics"""
        return {
            'total_packets': self.packet_count,
            'active_connections': len(self.connection_tracker),
            'monitoring_status': 'ACTIVE' if self.running else 'STOPPED'
        }

if __name__ == '__main__':
    # Example usage
    monitor = NetworkMonitor()
    
    try:
        # Start monitoring in a separate thread
        monitor_thread = threading.Thread(target=monitor.start_monitoring)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Keep main thread alive
        while True:
            time.sleep(10)
            stats = monitor.get_network_stats()
            print(f"Packets processed: {stats['total_packets']}, Status: {stats['monitoring_status']}")
            
    except KeyboardInterrupt:
        print("\nStopping network monitor...")
        monitor.stop_monitoring()
        monitor_thread.join(timeout=5)
        print("Network monitor stopped.")
