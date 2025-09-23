#!/usr/bin/env python3
"""
Setup script for SecureNet-Monitor
Network Security Monitoring Dashboard
"""

import os
import sys
import subprocess
import platform
from pathlib import Path


def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required")
        print(f"Current version: {sys.version}")
        sys.exit(1)
    print(f"✅ Python version: {sys.version.split()[0]}")


def check_system_requirements():
    """Check system requirements"""
    print("\n🔍 Checking system requirements...")
    
    # Check if running as root/admin (required for packet capture)
    if platform.system() != "Windows":
        if os.geteuid() != 0:
            print("⚠️  Warning: Root privileges required for packet capture")
            print("   Run with: sudo python setup.py")
    
    # Check available network interfaces
    try:
        import netifaces
        interfaces = netifaces.interfaces()
        print(f"✅ Network interfaces available: {len(interfaces)}")
    except ImportError:
        print("⚠️  Network interface check skipped (netifaces not installed)")


def install_dependencies():
    """Install Python dependencies"""
    print("\n📦 Installing Python dependencies...")
    
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ])
        print("✅ Dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        sys.exit(1)


def setup_database():
    """Initialize the database"""
    print("\n🗄️  Setting up database...")
    
    try:
        from database import init_database
        init_database()
        print("✅ Database initialized successfully")
    except Exception as e:
        print(f"❌ Error setting up database: {e}")
        sys.exit(1)


def create_directories():
    """Create necessary directories"""
    print("\n📁 Creating directories...")
    
    directories = [
        'logs',
        'reports',
        'config',
        'static/css',
        'static/js',
        'templates'
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✅ Created: {directory}")


def setup_configuration():
    """Setup default configuration"""
    print("\n⚙️  Setting up configuration...")
    
    config_content = '''# SecureNet-Monitor Configuration
# Network Security Monitoring Dashboard

# Network monitoring settings
INTERFACE = 'eth0'  # Change to your network interface
NETWORK_RANGE = '192.168.1.0/24'  # Change to your network range

# Threat detection thresholds
PORT_SCAN_THRESHOLD = 10  # Ports scanned per minute
DDOS_THRESHOLD = 1000     # Packets per second
BRUTE_FORCE_THRESHOLD = 5 # Failed attempts per minute

# Database settings
DATABASE_PATH = 'security_monitor.db'
LOG_RETENTION_DAYS = 30

# Web interface settings
WEB_HOST = '0.0.0.0'
WEB_PORT = 5000
DEBUG_MODE = False

# Logging settings
LOG_LEVEL = 'INFO'
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
'''
    
    config_path = Path('config/config.py')
    if not config_path.exists():
        with open(config_path, 'w') as f:
            f.write(config_content)
        print("✅ Default configuration created")
    else:
        print("✅ Configuration file already exists")


def run_tests():
    """Run basic tests to verify installation"""
    print("\n🧪 Running installation tests...")
    
    try:
        # Test imports
        import scapy
        import flask
        import sqlite3
        print("✅ Core modules import successfully")
        
        # Test database connection
        import sqlite3
        conn = sqlite3.connect('security_monitor.db')
        conn.close()
        print("✅ Database connection test passed")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False
    
    return True


def print_completion_message():
    """Print setup completion message"""
    print("\n" + "=" * 60)
    print("🎉 SecureNet-Monitor Setup Complete!")
    print("=" * 60)
    print()
    print("Next steps:")
    print("1. Review configuration in config/config.py")
    print("2. Update network interface and range settings")
    print("3. Start the monitoring system:")
    print("   sudo python app.py")
    print()
    print("4. Access the web dashboard:")
    print("   http://localhost:5000")
    print()
    print("For help and documentation:")
    print("- README.md")
    print("- logs/ directory for troubleshooting")
    print("=" * 60)


def main():
    """Main setup function"""
    print("🚀 SecureNet-Monitor Setup")
    print("Network Security Monitoring Dashboard")
    print("=" * 50)
    
    try:
        check_python_version()
        check_system_requirements()
        install_dependencies()
        create_directories()
        setup_database()
        setup_configuration()
        
        if run_tests():
            print_completion_message()
        else:
            print("❌ Setup completed with errors. Check logs for details.")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n❌ Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Setup failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()