#!/usr/bin/env python3
"""
SecureNet-Monitor: Threat Detection Testing Suite
Tests threat detection accuracy and response times
"""

import time
import threading
import sqlite3
import json
import statistics
from datetime import datetime
from scapy.all import *
from network_monitor import NetworkMonitor
from threat_detection import ThreatDetectionEngine
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ThreatDetectionTester:
    def __init__(self):
        self.threat_engine = ThreatDetectionEngine()
        self.test_results = {
            'port_scan_tests': [],
            'ddos_tests': [],
            'brute_force_tests': [],
            'response_times': [],
            'accuracy_metrics': {}
        }
        
    def create_test_packet(self, src_ip, dst_ip, dst_port, protocol='TCP', flags='S', size=64):
        """Create a test packet for simulation"""
        if protocol == 'TCP':
            packet = IP(src=src_ip, dst=dst_ip) / TCP(dport=dst_port, flags=flags)
        elif protocol == 'UDP':
            packet = IP(src=src_ip, dst=dst_ip) / UDP(dport=dst_port)
        else:
            packet = IP(src=src_ip, dst=dst_ip)
        
        # Add padding to simulate packet size
        if size > len(packet):
            packet = packet / Raw(b'A' * (size - len(packet)))
        
        return packet

    def test_port_scan_detection(self):
        """Test port scan detection accuracy and response time"""
        logger.info("Testing port scan detection...")
        
        test_cases = [
            {
                'name': 'Sequential Port Scan',
                'src_ip': '192.168.1.100',
                'dst_ip': '192.168.1.1',
                'ports': list(range(80, 100)),
                'expected': True
            },
            {
                'name': 'Random Port Scan',
                'src_ip': '10.0.0.50',
                'dst_ip': '10.0.0.1',
                'ports': [22, 80, 443, 3389, 21, 23, 25, 110, 143, 993, 995, 8080, 8443, 3306, 5432],
                'expected': True
            },
            {
                'name': 'Normal Traffic',
                'src_ip': '192.168.1.200',
                'dst_ip': '192.168.1.1',
                'ports': [80, 443],
                'expected': False
            }
        ]
        
        for test_case in test_cases:
            start_time = time.time()
            detected = False
            
            for port in test_case['ports']:
                timestamp = time.time()
                
                # Test detection
                result = self.threat_engine.analyze_port_scan_patterns(
                    test_case['src_ip'],
                    test_case['dst_ip'],
                    port,
                    timestamp
                )
                
                if result['detected']:
                    detected = True
                    break
            
            response_time = time.time() - start_time
            accuracy = detected == test_case['expected']
            
            test_result = {
                'name': test_case['name'],
                'expected': test_case['expected'],
                'detected': detected,
                'accurate': accuracy,
                'response_time': response_time,
                'ports_tested': len(test_case['ports'])
            }
            
            self.test_results['port_scan_tests'].append(test_result)
            self.test_results['response_times'].append(response_time)
            
            logger.info(f"Port Scan Test '{test_case['name']}': {'PASS' if accuracy else 'FAIL'} "
                       f"(Response: {response_time:.3f}s)")

    def test_ddos_detection(self):
        """Test DDoS detection accuracy and response time"""
        logger.info("Testing DDoS detection...")
        
        test_cases = [
            {
                'name': 'High Volume Attack',
                'src_ip': '203.0.113.10',
                'packet_count': 150,
                'interval': 0.005,
                'expected': True
            },
            {
                'name': 'Normal Traffic Burst',
                'src_ip': '10.0.0.100',
                'packet_count': 50,
                'interval': 0.02,
                'expected': False
            }
        ]
        
        for test_case in test_cases:
            start_time = time.time()
            detected = False
            
            for i in range(test_case['packet_count']):
                timestamp = time.time()
                
                # Test detection
                result = self.threat_engine.analyze_ddos_patterns(
                    test_case['src_ip'],
                    64,  # packet size
                    'TCP',
                    'S',
                    timestamp
                )
                
                if result['detected']:
                    detected = True
                    break
                
                time.sleep(test_case['interval'])
            
            response_time = time.time() - start_time
            accuracy = detected == test_case['expected']
            
            test_result = {
                'name': test_case['name'],
                'expected': test_case['expected'],
                'detected': detected,
                'accurate': accuracy,
                'response_time': response_time,
                'packets_sent': test_case['packet_count']
            }
            
            self.test_results['ddos_tests'].append(test_result)
            self.test_results['response_times'].append(response_time)
            
            logger.info(f"DDoS Test '{test_case['name']}': {'PASS' if accuracy else 'FAIL'} "
                       f"(Response: {response_time:.3f}s)")

    def test_brute_force_detection(self):
        """Test brute force detection accuracy and response time"""
        logger.info("Testing brute force detection...")
        
        test_cases = [
            {
                'name': 'SSH Brute Force',
                'src_ip': '203.0.113.50',
                'dst_port': 22,
                'attempts': 15,
                'interval': 2.0,
                'expected': True
            },
            {
                'name': 'Normal Login Attempts',
                'src_ip': '10.0.0.200',
                'dst_port': 22,
                'attempts': 3,
                'interval': 10.0,
                'expected': False
            }
        ]
        
        for test_case in test_cases:
            start_time = time.time()
            detected = False
            
            for i in range(test_case['attempts']):
                timestamp = time.time()
                
                # Test detection
                result = self.threat_engine.analyze_brute_force_patterns(
                    test_case['src_ip'],
                    test_case['dst_port'],
                    64,  # packet size
                    timestamp
                )
                
                if result['detected']:
                    detected = True
                    break
                
                time.sleep(test_case['interval'])
            
            response_time = time.time() - start_time
            accuracy = detected == test_case['expected']
            
            test_result = {
                'name': test_case['name'],
                'expected': test_case['expected'],
                'detected': detected,
                'accurate': accuracy,
                'response_time': response_time,
                'attempts_made': test_case['attempts']
            }
            
            self.test_results['brute_force_tests'].append(test_result)
            self.test_results['response_times'].append(response_time)
            
            logger.info(f"Brute Force Test '{test_case['name']}': {'PASS' if accuracy else 'FAIL'} "
                       f"(Response: {response_time:.3f}s)")

    def test_response_time_performance(self):
        """Test response time under load"""
        logger.info("Testing response time performance...")
        
        response_times = []
        
        # Test 100 rapid detections
        for i in range(100):
            start_time = time.time()
            
            # Simulate port scan detection
            result = self.threat_engine.analyze_port_scan_patterns(
                f"192.168.1.{i % 254 + 1}",
                "192.168.1.1",
                80 + (i % 100),
                time.time()
            )
            
            response_time = time.time() - start_time
            response_times.append(response_time)
        
        avg_response_time = statistics.mean(response_times)
        max_response_time = max(response_times)
        
        logger.info(f"Performance Test Results:")
        logger.info(f"  Average Response Time: {avg_response_time:.6f}s")
        logger.info(f"  Maximum Response Time: {max_response_time:.6f}s")
        
        # Check if sub-second response time requirement is met
        sub_second_performance = max_response_time < 1.0
        
        self.test_results['response_times'].extend(response_times)
        self.test_results['accuracy_metrics']['sub_second_performance'] = sub_second_performance
        
        return sub_second_performance

    def calculate_accuracy_metrics(self):
        """Calculate overall accuracy metrics"""
        all_tests = (self.test_results['port_scan_tests'] + 
                    self.test_results['ddos_tests'] + 
                    self.test_results['brute_force_tests'])
        
        if not all_tests:
            return
        
        total_tests = len(all_tests)
        accurate_tests = sum(1 for test in all_tests if test['accurate'])
        
        accuracy_percentage = (accurate_tests / total_tests) * 100
        
        # Calculate response time statistics
        if self.test_results['response_times']:
            avg_response_time = statistics.mean(self.test_results['response_times'])
            max_response_time = max(self.test_results['response_times'])
        else:
            avg_response_time = 0
            max_response_time = 0
        
        self.test_results['accuracy_metrics'] = {
            'total_tests': total_tests,
            'accurate_tests': accurate_tests,
            'accuracy_percentage': accuracy_percentage,
            'average_response_time': avg_response_time,
            'maximum_response_time': max_response_time,
            'sub_second_performance': max_response_time < 1.0,
            'target_accuracy_met': accuracy_percentage >= 99.0
        }
        
        return self.test_results['accuracy_metrics']

    def generate_test_report(self):
        """Generate comprehensive test report"""
        metrics = self.calculate_accuracy_metrics()
        
        report = {
            'test_summary': {
                'timestamp': datetime.now().isoformat(),
                'total_tests_run': metrics['total_tests'],
                'accuracy_achieved': f"{metrics['accuracy_percentage']:.1f}%",
                'target_accuracy_met': metrics['target_accuracy_met'],
                'average_response_time': f"{metrics['average_response_time']:.6f}s",
                'sub_second_performance': metrics['sub_second_performance']
            },
            'detailed_results': self.test_results
        }
        
        return report

    def run_all_tests(self):
        """Run all threat detection tests"""
        logger.info("Starting comprehensive threat detection testing...")
        
        start_time = time.time()
        
        # Run all test suites
        self.test_port_scan_detection()
        self.test_ddos_detection()
        self.test_brute_force_detection()
        self.test_response_time_performance()
        
        total_time = time.time() - start_time
        
        # Generate and save report
        report = self.generate_test_report()
        report['test_summary']['total_test_time'] = f"{total_time:.2f}s"
        
        # Save report to file
        with open('threat_detection_test_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        logger.info("\n=== THREAT DETECTION TEST RESULTS ===")
        logger.info(f"Total Tests: {report['test_summary']['total_tests_run']}")
        logger.info(f"Accuracy: {report['test_summary']['accuracy_achieved']}")
        logger.info(f"Target Met: {report['test_summary']['target_accuracy_met']}")
        logger.info(f"Avg Response: {report['test_summary']['average_response_time']}")
        logger.info(f"Sub-second: {report['test_summary']['sub_second_performance']}")
        logger.info(f"Test Duration: {report['test_summary']['total_test_time']}")
        logger.info("\nDetailed report saved to: threat_detection_test_report.json")
        
        return report

if __name__ == '__main__':
    # Run the test suite
    tester = ThreatDetectionTester()
    results = tester.run_all_tests()
    
    # Check if requirements are met
    metrics = results['test_summary']
    
    print("\n=== REQUIREMENTS VERIFICATION ===")
    print(f"✓ Threat Detection Accuracy: {metrics['accuracy_achieved']} (Target: 99.2%)")
    print(f"✓ Sub-second Response Times: {metrics['sub_second_performance']} (Target: <1s)")
    
    if float(metrics['accuracy_achieved'].rstrip('%')) >= 99.0 and metrics['sub_second_performance']:
        print("\n🎉 ALL REQUIREMENTS MET! SecureNet-Monitor is ready for deployment.")
    else:
        print("\n⚠️  Some requirements not met. Review test results for optimization.")