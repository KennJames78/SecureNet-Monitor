#!/usr/bin/env python3
"""
SecureNet-Monitor: Flask Web Dashboard
Real-time network security monitoring dashboard with live visualization
"""

from flask import Flask, render_template, jsonify, request
import sqlite3
import json
import threading
import time
from datetime import datetime, timedelta
from network_monitor import NetworkMonitor
from threat_detection import ThreatDetectionEngine
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'securenet_monitor_2025'

# Global instances
network_monitor = None
monitor_thread = None
threat_engine = ThreatDetectionEngine()

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/start_monitoring', methods=['POST'])
def start_monitoring():
    """Start network monitoring"""
    global network_monitor, monitor_thread
    
    try:
        if network_monitor and network_monitor.running:
            return jsonify({'status': 'error', 'message': 'Monitoring already running'})
        
        interface = request.json.get('interface') if request.json else None
        network_monitor = NetworkMonitor(interface=interface)
        
        monitor_thread = threading.Thread(target=network_monitor.start_monitoring)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        return jsonify({'status': 'success', 'message': 'Network monitoring started'})
    except Exception as e:
        logger.error(f"Error starting monitoring: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/stop_monitoring', methods=['POST'])
def stop_monitoring():
    """Stop network monitoring"""
    global network_monitor
    
    try:
        if network_monitor:
            network_monitor.stop_monitoring()
            return jsonify({'status': 'success', 'message': 'Network monitoring stopped'})
        else:
            return jsonify({'status': 'error', 'message': 'No monitoring session active'})
    except Exception as e:
        logger.error(f"Error stopping monitoring: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/status')
def get_status():
    """Get current monitoring status"""
    try:
        if network_monitor:
            stats = network_monitor.get_network_stats()
            threat_stats = threat_engine.get_threat_statistics()
            
            return jsonify({
                'status': 'success',
                'monitoring': stats,
                'threats': threat_stats,
                'timestamp': datetime.now().isoformat()
            })
        else:
            return jsonify({
                'status': 'success',
                'monitoring': {'monitoring_status': 'STOPPED', 'total_packets': 0, 'active_connections': 0},
                'threats': {'active_port_scan_sources': 0, 'active_ddos_sources': 0, 'active_brute_force_sources': 0},
                'timestamp': datetime.now().isoformat()
            })
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/events')
def get_events():
    """Get recent security events"""
    try:
        limit = request.args.get('limit', 50, type=int)
        severity = request.args.get('severity', None)
        event_type = request.args.get('type', None)
        
        conn = sqlite3.connect('security_events.db')
        cursor = conn.cursor()
        
        query = "SELECT * FROM security_events WHERE 1=1"
        params = []
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        events = cursor.fetchall()
        conn.close()
        
        # Convert to list of dictionaries
        event_list = []
        for event in events:
            event_dict = {
                'id': event[0],
                'timestamp': event[1],
                'event_type': event[2],
                'source_ip': event[3],
                'destination_ip': event[4],
                'port': event[5],
                'protocol': event[6],
                'severity': event[7],
                'description': event[8],
                'raw_data': json.loads(event[9]) if event[9] else {}
            }
            event_list.append(event_dict)
        
        return jsonify({'status': 'success', 'events': event_list})
    except Exception as e:
        logger.error(f"Error getting events: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/statistics')
def get_statistics():
    """Get network and threat statistics"""
    try:
        conn = sqlite3.connect('security_events.db')
        cursor = conn.cursor()
        
        # Get event counts by type
        cursor.execute("""
            SELECT event_type, COUNT(*) as count 
            FROM security_events 
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY event_type
        "")
        event_counts = dict(cursor.fetchall())
        
        # Get event counts by severity
        cursor.execute("""
            SELECT severity, COUNT(*) as count 
            FROM security_events 
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY severity
        "")
        severity_counts = dict(cursor.fetchall())
        
        # Get hourly event distribution
        cursor.execute("""
            SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
            FROM security_events 
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY hour
            ORDER BY hour
        "")
        hourly_distribution = dict(cursor.fetchall())
        
        # Get top source IPs
        cursor.execute("""
            SELECT source_ip, COUNT(*) as count
            FROM security_events 
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT 10
        "")
        top_sources = dict(cursor.fetchall())
        
        # Get network statistics
        cursor.execute("""
            SELECT * FROM network_stats 
            ORDER BY timestamp DESC 
            LIMIT 1
        "")
        latest_stats = cursor.fetchone()
        
        conn.close()
        
        network_stats = {}
        if latest_stats:
            network_stats = {
                'total_packets': latest_stats[2],
                'threats_detected': latest_stats[3],
                'active_connections': latest_stats[4],
                'last_updated': latest_stats[1]
            }
        
        return jsonify({
            'status': 'success',
            'statistics': {
                'event_counts': event_counts,
                'severity_counts': severity_counts,
                'hourly_distribution': hourly_distribution,
                'top_sources': top_sources,
                'network_stats': network_stats
            }
        })
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/live_feed')
def get_live_feed():
    """Get live feed of recent events for real-time updates"""
    try:
        # Get events from the last 30 seconds
        conn = sqlite3.connect('security_events.db')
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM security_events 
            WHERE timestamp > datetime('now', '-30 seconds')
            ORDER BY timestamp DESC
        "")
        events = cursor.fetchall()
        conn.close()
        
        # Convert to list of dictionaries
        event_list = []
        for event in events:
            event_dict = {
                'id': event[0],
                'timestamp': event[1],
                'event_type': event[2],
                'source_ip': event[3],
                'destination_ip': event[4],
                'port': event[5],
                'protocol': event[6],
                'severity': event[7],
                'description': event[8]
            }
            event_list.append(event_dict)
        
        return jsonify({'status': 'success', 'events': event_list})
    except Exception as e:
        logger.error(f"Error getting live feed: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/export_events')
def export_events():
    """Export security events to JSON"""
    try:
        days = request.args.get('days', 1, type=int)
        
        conn = sqlite3.connect('security_events.db')
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM security_events 
            WHERE timestamp > datetime('now', '-{} days')
            ORDER BY timestamp DESC
        "".format(days))
        
        events = cursor.fetchall()
        conn.close()
        
        # Convert to list of dictionaries
        event_list = []
        for event in events:
            event_dict = {
                'id': event[0],
                'timestamp': event[1],
                'event_type': event[2],
                'source_ip': event[3],
                'destination_ip': event[4],
                'port': event[5],
                'protocol': event[6],
                'severity': event[7],
                'description': event[8],
                'raw_data': json.loads(event[9]) if event[9] else {}
            }
            event_list.append(event_dict)
        
        return jsonify({
            'status': 'success',
            'export_timestamp': datetime.now().isoformat(),
            'total_events': len(event_list),
            'events': event_list
        })
    except Exception as e:
        logger.error(f"Error exporting events: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/clear_events', methods=['POST'])
def clear_events():
    """Clear old security events"""
    try:
        days = request.json.get('days', 7) if request.json else 7
        
        conn = sqlite3.connect('security_events.db')
        cursor = conn.cursor()
        
        cursor.execute("""
            DELETE FROM security_events 
            WHERE timestamp < datetime('now', '-{} days')
        "".format(days))
        
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()
        
        return jsonify({
            'status': 'success',
            'message': f'Deleted {deleted_count} old events',
            'deleted_count': deleted_count
        })
    except Exception as e:
        logger.error(f"Error clearing events: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    # Initialize database
    monitor = NetworkMonitor()
    
    # Run Flask app
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
