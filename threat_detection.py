#!/usr/bin/env python3
"""
SecureNet-Monitor: Advanced Threat Detection Algorithms
Implements sophisticated pattern recognition for various network threats
"""

import time
import json
import math
import statistics
from datetime import datetime, timedelta
from collections import defaultdict, deque, Counter
from scapy.all import *
import logging

logger = logging.getLogger(__name__)

class ThreatDetectionEngine:
    def __init__(self):
        # Enhanced tracking structures
        self.port_scan_tracker = defaultdict(lambda: {
            'ports': set(),
            'timestamps': deque(maxlen=1000),
            'patterns': defaultdict(int)
        })
        
        self.ddos_tracker = defaultdict(lambda: {
            'packet_times': deque(maxlen=1000),
            'packet_sizes': deque(maxlen=100),
            'protocols': Counter(),
            'flags': Counter()
        })
        
        self.brute_force_tracker = defaultdict(lambda: {
            'attempts': deque(maxlen=100),
            'success_indicators': [],
            'failure_patterns': Counter(),
            'timing_analysis': deque(maxlen=50)
        })
        
        # Behavioral analysis
        self.baseline_traffic = defaultdict(lambda: {
            'normal_rate': 0,
            'normal_size': 0,
            'established_baseline': False
        })
        
        # Advanced thresholds
        self.thresholds = {
            'port_scan': {
                'ports_per_minute': 15,
                'sequential_ports': 5,
                'stealth_scan_interval': 2.0
            },
            'ddos': {
                'packets_per_second': 100,
                'size_deviation': 3.0,
                'protocol_diversity': 0.8
            },
            'brute_force': {
                'attempts_per_minute': 10,
                'timing_regularity': 0.9,
                'dictionary_patterns': 5
            }
        }

    def analyze_port_scan_patterns(self, src_ip, dst_ip, dst_port, timestamp):
        """Advanced port scan detection with pattern analysis"""
        tracker = self.port_scan_tracker[f"{src_ip}->{dst_ip}"]
        tracker['ports'].add(dst_port)
        tracker['timestamps'].append(timestamp)
        
        # Analyze scanning patterns
        ports_list = sorted(list(tracker['ports']))
        
        # Sequential port scanning detection
        sequential_count = 0
        for i in range(1, len(ports_list)):
            if ports_list[i] - ports_list[i-1] == 1:
                sequential_count += 1
        
        # Timing analysis for stealth scans
        if len(tracker['timestamps']) >= 2:
            intervals = []
            times = list(tracker['timestamps'])[-10:]  # Last 10 timestamps
            for i in range(1, len(times)):
                intervals.append(times[i] - times[i-1])
            
            if intervals:
                avg_interval = statistics.mean(intervals)
                interval_std = statistics.stdev(intervals) if len(intervals) > 1 else 0
        
        # Common port patterns
        common_ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389}
        common_port_hits = len(tracker['ports'].intersection(common_ports))
        
        # Detection logic
        threat_indicators = []
        severity = 'LOW'
        
        if len(tracker['ports']) >= self.thresholds['port_scan']['ports_per_minute']:
            threat_indicators.append('HIGH_PORT_COUNT')
            severity = 'HIGH'
        
        if sequential_count >= self.thresholds['port_scan']['sequential_ports']:
            threat_indicators.append('SEQUENTIAL_SCAN')
            severity = 'MEDIUM' if severity == 'LOW' else severity
        
        if common_port_hits >= 5:
            threat_indicators.append('COMMON_PORTS_TARGETED')
            severity = 'HIGH'
        
        # Stealth scan detection
        if len(intervals) > 5 and avg_interval > self.thresholds['port_scan']['stealth_scan_interval']:
            if interval_std < 0.5:  # Regular intervals indicate automated scanning
                threat_indicators.append('STEALTH_SCAN')
                severity = 'HIGH'
        
        if threat_indicators:
            return {
                'detected': True,
                'type': 'PORT_SCAN',
                'severity': severity,
                'indicators': threat_indicators,
                'details': {
                    'ports_scanned': len(tracker['ports']),
                    'sequential_ports': sequential_count,
                    'common_ports_hit': common_port_hits,
                    'scan_duration': max(tracker['timestamps']) - min(tracker['timestamps']) if len(tracker['timestamps']) > 1 else 0,
                    'average_interval': avg_interval if 'avg_interval' in locals() else 0
                }
            }
        
        return {'detected': False}

    def analyze_ddos_patterns(self, src_ip, packet_size, protocol, tcp_flags, timestamp):
        """Advanced DDoS detection with traffic analysis"""
        tracker = self.ddos_tracker[src_ip]
        tracker['packet_times'].append(timestamp)
        tracker['packet_sizes'].append(packet_size)
        tracker['protocols'][protocol] += 1
        
        if tcp_flags:
            tracker['flags'][tcp_flags] += 1
        
        # Calculate packets per second
        current_time = timestamp
        recent_packets = [t for t in tracker['packet_times'] if current_time - t <= 1.0]
        pps = len(recent_packets)
        
        # Analyze packet size patterns
        if len(tracker['packet_sizes']) >= 10:
            size_mean = statistics.mean(tracker['packet_sizes'])
            size_std = statistics.stdev(tracker['packet_sizes'])
            size_uniformity = size_std / size_mean if size_mean > 0 else 0
        else:
            size_uniformity = 0
        
        # Protocol diversity analysis
        total_protocols = sum(tracker['protocols'].values())
        protocol_entropy = 0
        if total_protocols > 0:
            for count in tracker['protocols'].values():
                if count > 0:
                    p = count / total_protocols
                    protocol_entropy -= p * math.log2(p)
        
        # TCP flags analysis for SYN flood detection
        syn_flood_ratio = 0
        if 'S' in tracker['flags'] and sum(tracker['flags'].values()) > 0:
            syn_flood_ratio = tracker['flags']['S'] / sum(tracker['flags'].values())
        
        # Detection logic
        threat_indicators = []
        severity = 'LOW'
        
        if pps >= self.thresholds['ddos']['packets_per_second']:
            threat_indicators.append('HIGH_PACKET_RATE')
            severity = 'CRITICAL'
        
        if size_uniformity < 0.1 and len(tracker['packet_sizes']) >= 20:
            threat_indicators.append('UNIFORM_PACKET_SIZES')
            severity = 'HIGH' if severity in ['LOW', 'MEDIUM'] else severity
        
        if protocol_entropy < 0.5 and total_protocols > 50:
            threat_indicators.append('LOW_PROTOCOL_DIVERSITY')
            severity = 'HIGH' if severity in ['LOW', 'MEDIUM'] else severity
        
        if syn_flood_ratio > 0.8 and sum(tracker['flags'].values()) > 100:
            threat_indicators.append('SYN_FLOOD')
            severity = 'CRITICAL'
        
        if threat_indicators:
            return {
                'detected': True,
                'type': 'DDOS_ATTACK',
                'severity': severity,
                'indicators': threat_indicators,
                'details': {
                    'packets_per_second': pps,
                    'packet_size_uniformity': size_uniformity,
                    'protocol_entropy': protocol_entropy,
                    'syn_flood_ratio': syn_flood_ratio,
                    'total_packets': len(tracker['packet_times'])
                }
            }
        
        return {'detected': False}

    def analyze_brute_force_patterns(self, src_ip, dst_port, packet_size, timestamp):
        """Advanced brute force detection with behavioral analysis"""
        tracker = self.brute_force_tracker[f"{src_ip}:{dst_port}"]
        tracker['attempts'].append(timestamp)
        tracker['timing_analysis'].append(timestamp)
        
        # Calculate attempts per minute
        current_time = timestamp
        recent_attempts = [t for t in tracker['attempts'] if current_time - t <= 60.0]
        attempts_per_minute = len(recent_attempts)
        
        # Timing regularity analysis
        timing_regularity = 0
        if len(tracker['timing_analysis']) >= 5:
            intervals = []
            times = list(tracker['timing_analysis'])[-10:]
            for i in range(1, len(times)):
                intervals.append(times[i] - times[i-1])
            
            if len(intervals) > 1:
                interval_mean = statistics.mean(intervals)
                interval_std = statistics.stdev(intervals)
                timing_regularity = 1 - (interval_std / interval_mean) if interval_mean > 0 else 0
        
        # Dictionary attack pattern detection
        # Look for patterns in timing that suggest dictionary attacks
        dictionary_indicators = 0
        if len(tracker['timing_analysis']) >= 10:
            # Check for burst patterns (rapid attempts followed by pauses)
            times = list(tracker['timing_analysis'])[-20:]
            bursts = 0
            in_burst = False
            
            for i in range(1, len(times)):
                interval = times[i] - times[i-1]
                if interval < 1.0:  # Fast attempt
                    if not in_burst:
                        bursts += 1
                        in_burst = True
                elif interval > 5.0:  # Long pause
                    in_burst = False
            
            dictionary_indicators = bursts
        
        # Service-specific analysis
        service_risk_multiplier = 1.0
        high_risk_ports = {22: 2.0, 3389: 2.0, 21: 1.5, 23: 1.5}  # SSH, RDP, FTP, Telnet
        if dst_port in high_risk_ports:
            service_risk_multiplier = high_risk_ports[dst_port]
        
        # Detection logic
        threat_indicators = []
        severity = 'LOW'
        
        adjusted_threshold = self.thresholds['brute_force']['attempts_per_minute'] / service_risk_multiplier
        
        if attempts_per_minute >= adjusted_threshold:
            threat_indicators.append('HIGH_ATTEMPT_RATE')
            severity = 'HIGH'
        
        if timing_regularity >= self.thresholds['brute_force']['timing_regularity']:
            threat_indicators.append('AUTOMATED_TIMING')
            severity = 'MEDIUM' if severity == 'LOW' else severity
        
        if dictionary_indicators >= self.thresholds['brute_force']['dictionary_patterns']:
            threat_indicators.append('DICTIONARY_ATTACK_PATTERN')
            severity = 'HIGH'
        
        # Credential stuffing detection (multiple services targeted)
        if len([k for k in self.brute_force_tracker.keys() if k.startswith(src_ip)]) > 3:
            threat_indicators.append('CREDENTIAL_STUFFING')
            severity = 'CRITICAL'
        
        if threat_indicators:
            return {
                'detected': True,
                'type': 'BRUTE_FORCE_ATTACK',
                'severity': severity,
                'indicators': threat_indicators,
                'details': {
                    'attempts_per_minute': attempts_per_minute,
                    'timing_regularity': timing_regularity,
                    'dictionary_indicators': dictionary_indicators,
                    'target_service': self._identify_service(dst_port),
                    'total_attempts': len(tracker['attempts'])
                }
            }
        
        return {'detected': False}

    def _identify_service(self, port):
        """Identify service based on port number"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S', 3389: 'RDP'
        }
        return services.get(port, f'Port-{port}')

    def update_baseline(self, src_ip, packet_rate, packet_size):
        """Update traffic baseline for anomaly detection"""
        baseline = self.baseline_traffic[src_ip]
        
        if not baseline['established_baseline']:
            baseline['normal_rate'] = packet_rate
            baseline['normal_size'] = packet_size
            baseline['established_baseline'] = True
        else:
            # Exponential moving average
            alpha = 0.1
            baseline['normal_rate'] = alpha * packet_rate + (1 - alpha) * baseline['normal_rate']
            baseline['normal_size'] = alpha * packet_size + (1 - alpha) * baseline['normal_size']

    def detect_anomalies(self, src_ip, current_rate, current_size):
        """Detect traffic anomalies based on established baseline"""
        baseline = self.baseline_traffic[src_ip]
        
        if not baseline['established_baseline']:
            return {'detected': False}
        
        rate_deviation = abs(current_rate - baseline['normal_rate']) / baseline['normal_rate'] if baseline['normal_rate'] > 0 else 0
        size_deviation = abs(current_size - baseline['normal_size']) / baseline['normal_size'] if baseline['normal_size'] > 0 else 0
        
        if rate_deviation > 5.0 or size_deviation > 3.0:
            return {
                'detected': True,
                'type': 'TRAFFIC_ANOMALY',
                'severity': 'MEDIUM',
                'details': {
                    'rate_deviation': rate_deviation,
                    'size_deviation': size_deviation,
                    'baseline_rate': baseline['normal_rate'],
                    'current_rate': current_rate
                }
            }
        
        return {'detected': False}

    def cleanup_old_data(self, max_age_hours=24):
        """Clean up old tracking data to prevent memory issues"""
        cutoff_time = time.time() - (max_age_hours * 3600)
        
        # Clean port scan data
        for key in list(self.port_scan_tracker.keys()):
            tracker = self.port_scan_tracker[key]
            tracker['timestamps'] = deque([t for t in tracker['timestamps'] if t > cutoff_time], maxlen=1000)
            if not tracker['timestamps']:
                del self.port_scan_tracker[key]
        
        # Clean DDoS data
        for key in list(self.ddos_tracker.keys()):
            tracker = self.ddos_tracker[key]
            tracker['packet_times'] = deque([t for t in tracker['packet_times'] if t > cutoff_time], maxlen=1000)
            if not tracker['packet_times']:
                del self.ddos_tracker[key]
        
        # Clean brute force data
        for key in list(self.brute_force_tracker.keys()):
            tracker = self.brute_force_tracker[key]
            tracker['attempts'] = deque([t for t in tracker['attempts'] if t > cutoff_time], maxlen=100)
            if not tracker['attempts']:
                del self.brute_force_tracker[key]

    def get_threat_statistics(self):
        """Get current threat detection statistics"""
        return {
            'active_port_scan_sources': len(self.port_scan_tracker),
            'active_ddos_sources': len(self.ddos_tracker),
            'active_brute_force_sources': len(self.brute_force_tracker),
            'baseline_established_ips': len([ip for ip, data in self.baseline_traffic.items() if data['established_baseline']])
        }
