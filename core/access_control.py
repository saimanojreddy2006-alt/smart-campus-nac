"""
Authentication Packet Capture and Access Control Engine
Handles packet capture simulation, MAC filtering, role-based access, and intrusion detection
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict
import hashlib


class PacketCapture:
    """Simulates capturing authentication packets from network"""
    
    def __init__(self):
        self.packets = []
        self.mac_vendor_db = {
            "AA:BB:CC": "Apple Inc.",
            "DD:EE:FF": "Cisco Systems",
            "GG:HH:II": "Samsung Electronics",
            "ZZ:YY:XX": "Dell Inc.",
            "PP:QQ:RR": "Intel Corporate",
            "00:11:22": "Hewlett Packard",
            "11:22:33": "Microsoft Corporation"
        }
    
    def simulate_packet_capture(self, df):
        """
        Convert dataframe records to packet-like structures
        Each packet contains: timestamp, src_mac, dst_mac, src_ip, dst_ip, protocol, auth_data
        """
        packets = []
        
        for _, row in df.iterrows():
            packet = {
                'timestamp': row.get('timestamp', datetime.now()),
                'src_mac': row.get('mac_address', ''),
                'dst_mac': 'FF:FF:FF:FF:FF:FF',  # Broadcast for auth
                'src_ip': row.get('source_ip', ''),
                'dst_ip': row.get('destination_ip', ''),
                'src_port': row.get('source_port', 0),
                'dst_port': row.get('destination_port', 0),
                'protocol': row.get('protocol', 'TCP'),
                'auth_method': row.get('auth_method', ''),
                'username': row.get('username', ''),
                'login_status': row.get('login_status', ''),
                'user_role': row.get('user_role', ''),
                'os': row.get('os', ''),
                'session_id': row.get('radius_acct_session_id', ''),
                'nas_ip': row.get('radius_nas_ip', ''),
                'failure_reason': row.get('failure_reason', '')
            }
            packets.append(packet)
        
        self.packets = packets
        return packets
    
    def get_mac_vendor(self, mac_address):
        """Lookup vendor from MAC address prefix"""
        if not mac_address or mac_address == '':
            return "Unknown"
        
        prefix = mac_address.upper()[:8]
        for oui, vendor in self.mac_vendor_db.items():
            if prefix.startswith(oui.replace(":", "")):
                return vendor
        return "Unknown Vendor"
    
    def get_packet_summary(self):
        """Get summary of captured packets"""
        if not self.packets:
            return {}
        
        total = len(self.packets)
        protocols = {}
        auth_methods = {}
        
        for p in self.packets:
            protocols[p['protocol']] = protocols.get(p['protocol'], 0) + 1
            auth_methods[p['auth_method']] = auth_methods.get(p['auth_method'], 0) + 1
        
        return {
            'total_packets': total,
            'protocols': protocols,
            'auth_methods': auth_methods,
            'unique_macs': len(set(p['src_mac'] for p in self.packets if p['src_mac'])),
            'unique_ips': len(set(p['src_ip'] for p in self.packets if p['src_ip']))
        }


class MACAddressManager:
    """Manages MAC address filtering - allowed vs blocked devices"""
    
    def __init__(self, allowed_macs=None):
        self.allowed_macs = set(allowed_macs or [])
        self.blocked_macs = set()
        self.mac_metadata = {}  # Store device info
    
    def load_from_dataframe(self, df):
        """Load all MACs from dataframe and categorize"""
        all_macs = df['mac_address'].unique()
        
        for mac in all_macs:
            if mac not in self.mac_metadata:
                self.mac_metadata[mac] = {
                    'first_seen': None,
                    'last_seen': None,
                    'login_count': 0,
                    'failed_count': 0,
                    'os': None,
                    'usernames': set()
                }
            
            # Update metadata from dataframe
            mac_data = df[df['mac_address'] == mac]
            self.mac_metadata[mac]['login_count'] = len(mac_data)
            self.mac_metadata[mac]['failed_count'] = len(mac_data[mac_data['login_status'] == 'failed'])
            
            # Get OS
            if 'os' in mac_data.columns:
                self.mac_metadata[mac]['os'] = mac_data['os'].mode().iloc[0] if not mac_data['os'].mode().empty else 'Unknown'
            
            # Get usernames
            self.mac_metadata[mac]['usernames'] = set(mac_data['username'].unique())
    
    def check_mac_status(self, mac_address):
        """Check if MAC is allowed, blocked, or unknown"""
        if mac_address in self.blocked_macs:
            return "BLOCKED"
        elif mac_address in self.allowed_macs:
            return "ALLOWED"
        else:
            return "UNKNOWN"
    
    def block_mac(self, mac_address, reason="Manual block"):
        """Block a MAC address"""
        if mac_address in self.allowed_macs:
            self.allowed_macs.remove(mac_address)
        self.blocked_macs.add(mac_address)
        
        if mac_address in self.mac_metadata:
            self.mac_metadata[mac_address]['blocked'] = True
            self.mac_metadata[mac_address]['block_reason'] = reason
    
    def unblock_mac(self, mac_address):
        """Unblock a MAC address"""
        if mac_address in self.blocked_macs:
            self.blocked_macs.remove(mac_address)
        
        if mac_address in self.mac_metadata:
            self.mac_metadata[mac_address]['blocked'] = False
    
    def get_device_registry(self):
        """Get complete device registry with status"""
        registry = []
        
        for mac, metadata in self.mac_metadata.items():
            status = self.check_mac_status(mac)
            
            registry.append({
                'mac_address': mac,
                'status': status,
                'login_count': metadata.get('login_count', 0),
                'failed_count': metadata.get('failed_count', 0),
                'success_rate': ((metadata.get('login_count', 0) - metadata.get('failed_count', 0)) / 
                               max(metadata.get('login_count', 1), 1) * 100),
                'os': metadata.get('os', 'Unknown'),
                'usernames': ', '.join(metadata.get('usernames', set())),
                'is_suspicious': metadata.get('failed_count', 0) > 5
            })
        
        return pd.DataFrame(registry)


class AccessRuleEngine:
    """Implements faculty/student/guest access rules"""
    
    def __init__(self, access_policies=None):
        self.access_policies = access_policies or {
            "faculty": {
                "start_hour": 0,
                "end_hour": 23,
                "allowed_ports": [22, 80, 443, 3389, 8080, 20, 21, 25, 53, 110, 143, 993, 995],
                "allowed_destinations": ["ANY"],
                "max_failed_attempts": 10,
                "description": "Faculty has full network access 24/7"
            },
            "student": {
                "start_hour": 8,
                "end_hour": 18,
                "allowed_ports": [80, 443, 22, 8080, 20, 21, 53],
                "allowed_destinations": ["ANY"],
                "max_failed_attempts": 5,
                "description": "Student access during business hours"
            },
            "guest": {
                "start_hour": 10,
                "end_hour": 16,
                "allowed_ports": [80, 443],
                "allowed_destinations": ["ANY"],
                "max_failed_attempts": 3,
                "description": "Guest internet-only access during limited hours"
            }
        }
    
    def check_time_access(self, user_role, hour):
        """Check if user role has access at current hour"""
        if user_role not in self.access_policies:
            return True  # Unknown role - allow
        
        policy = self.access_policies[user_role]
        start = policy["start_hour"]
        end = policy["end_hour"]
        
        return start <= hour <= end
    
    def check_port_access(self, user_role, port):
        """Check if port is allowed for user role"""
        if user_role not in self.access_policies:
            return True
        
        policy = self.access_policies[user_role]
        allowed_ports = policy["allowed_ports"]
        
        return port in allowed_ports or 80 in allowed_ports  # Allow DNS (53) implicitly
    
    def check_destination_access(self, user_role, dest_ip):
        """Check if destination IP is allowed"""
        if user_role not in self.access_policies:
            return True
        
        policy = self.access_policies[user_role]
        
        # Check if destination is internal or external
        if dest_ip.startswith("192.168.") or dest_ip.startswith("10."):
            return True  # Internal always allowed
        
        # External destinations depend on policy
        allowed_dests = policy.get("allowed_destinations", ["ANY"])
        
        if "ANY" in allowed_dests:
            return True
        
        return False
    
    def evaluate_access(self, row):
        """Comprehensive access evaluation for a single authentication"""
        decisions = []
        role = row.get('user_role', 'unknown')
        hour = row.get('timestamp', datetime.now()).hour if isinstance(row.get('timestamp'), datetime) else 12
        port = row.get('destination_port', 0)
        dest_ip = row.get('destination_ip', '')
        mac = row.get('mac_address', '')
        
        # Check MAC status
        if mac not in self.access_policies and False:  # This would use MAC manager
            decisions.append("BLOCKED: Unknown Device")
        
        # Time-based check
        if not self.check_time_access(role, hour):
            decisions.append(f"BLOCKED: Time restriction ({role} allowed {self.access_policies[role]['start_hour']}-{self.access_policies[role]['end_hour']})")
        
        # Port check
        if port and not self.check_port_access(role, port):
            decisions.append(f"BLOCKED: Port {port} not allowed for {role}")
        
        # Destination check
        if dest_ip and not self.check_destination_access(role, dest_ip):
            decisions.append(f"BLOCKED: Destination {dest_ip} not allowed for {role}")
        
        # Login status check
        if row.get('login_status') == 'failed':
            decisions.append(f"DENIED: Authentication failed - {row.get('failure_reason', 'Unknown')}")
        
        if decisions:
            return " | ".join(decisions)
        return "ACCESS GRANTED"
    
    def get_role_summary(self):
        """Get summary of all access policies"""
        summary = []
        for role, policy in self.access_policies.items():
            summary.append({
                'role': role,
                'start_hour': policy['start_hour'],
                'end_hour': policy['end_hour'],
                'allowed_ports': len(policy.get('allowed_ports', [])),
                'max_failed': policy.get('max_failed_attempts', 0),
                'description': policy.get('description', '')
            })
        return pd.DataFrame(summary)


class IntrusionDetectionSystem:
    """Detects intrusion patterns in authentication data"""
    
    def __init__(self, dataframe):
        self.df = dataframe
    
    def detect_brute_force(self, threshold=3):
        """Detect brute force attempts - multiple failed logins from same source"""
        failed = self.df[self.df['login_status'] == 'failed']
        
        # Group by MAC
        mac_failures = failed.groupby('mac_address').size()
        brute_force_macs = mac_failures[mac_failures >= threshold]
        
        # Group by username
        user_failures = failed.groupby('username').size()
        brute_force_users = user_failures[user_failures >= threshold]
        
        # Group by source IP
        if 'source_ip' in failed.columns:
            ip_failures = failed.groupby('source_ip').size()
            brute_force_ips = ip_failures[ip_failures >= threshold]
        else:
            brute_force_ips = pd.Series()
        
        return {
            'suspicious_macs': brute_force_macs.to_dict(),
            'suspicious_users': brute_force_users.to_dict(),
            'suspicious_ips': brute_force_ips.to_dict(),
            'total_threats': len(brute_force_macs) + len(brute_force_users)
        }
    
    def detect_port_scanning(self, threshold=10):
        """Detect port scanning - many unique ports accessed in short time"""
        if 'source_ip' not in self.df.columns or 'destination_port' not in self.df.columns:
            return {'suspicious_ips': {}, 'total_threats': 0}
        
        # Group by source IP, count unique destination ports
        port_scans = self.df.groupby('source_ip')['destination_port'].nunique()
        scanners = port_scans[port_scans >= threshold]
        
        return {
            'suspicious_ips': scanners.to_dict(),
            'total_threats': len(scanners)
        }
    
    def detect_credential_stuffing(self, threshold=5):
        """Detect credential stuffing - same failed login for multiple users from same IP"""
        if 'source_ip' not in self.df.columns or 'username' not in self.df.columns:
            return {'suspicious_ips': {}, 'total_threats': 0}
        
        failed = self.df[self.df['login_status'] == 'failed']
        
        # Find IPs with multiple usernames
        ip_users = failed.groupby('source_ip')['username'].nunique()
        suspicious_ips = ip_users[ip_users >= threshold]
        
        return {
            'suspicious_ips': suspicious_ips.to_dict(),
            'total_threats': len(suspicious_ips)
        }
    
    def detect_impossible_travel(self, time_window_minutes=30, max_distance_km=100):
        """Detect impossible travel - same user from distant locations in short time"""
        # This would require geoIP data - simplified version
        return {'alerts': [], 'total_threats': 0}
    
    def detect_time_based_anomaly(self, role):
        """Detect access attempts outside allowed time windows"""
        if 'timestamp' not in self.df.columns or 'user_role' not in self.df.columns:
            return {'anomalies': [], 'total_threats': 0}
        
        policies = {
            'faculty': (0, 23),
            'student': (8, 18),
            'guest': (10, 16)
        }
        
        if role not in policies:
            return {'anomalies': [], 'total_threats': 0}
        
        start, end = policies[role]
        
        role_df = self.df[self.df['user_role'] == role]
        role_df = role_df.copy()
        role_df['hour'] = pd.to_datetime(role_df['timestamp']).dt.hour
        
        anomalies = role_df[(role_df['hour'] < start) | (role_df['hour'] > end)]
        
        return {
            'anomalies': anomalies[['username', 'mac_address', 'timestamp', 'hour']].to_dict('records'),
            'total_threats': len(anomalies)
        }
    
    def detect_mac_spoofing(self):
        """Detect potential MAC spoofing - same username with different MACs"""
        if 'username' not in self.df.columns or 'mac_address' not in self.df.columns:
            return {'suspicious_pairs': [], 'total_threats': 0}
        
        user_macs = self.df.groupby('username')['mac_address'].nunique()
        spoofed = user_macs[user_macs > 1]
        
        return {
            'suspicious_users': spoofed.to_dict(),
            'total_threats': len(spoofed)
        }
    
    def generate_threat_report(self):
        """Generate comprehensive threat detection report"""
        threats = []
        
        # Brute force
        brute_force = self.detect_brute_force()
        for mac, count in brute_force['suspicious_macs'].items():
            threats.append({
                'type': 'Brute Force',
                'indicator': mac,
                'severity': 'HIGH' if count > 5 else 'MEDIUM',
                'count': count
            })
        
        # Port scanning
        port_scan = self.detect_port_scanning()
        for ip, count in port_scan['suspicious_ips'].items():
            threats.append({
                'type': 'Port Scanning',
                'indicator': ip,
                'severity': 'MEDIUM',
                'ports_scanned': count
            })
        
        # Credential stuffing
        cred_stuff = self.detect_credential_stuffing()
        for ip, count in cred_stuff['suspicious_ips'].items():
            threats.append({
                'type': 'Credential Stuffing',
                'indicator': ip,
                'severity': 'HIGH',
                'users_affected': count
            })
        
        # MAC spoofing
        mac_spoof = self.detect_mac_spoofing()
        for user, count in mac_spoof['suspicious_users'].items():
            threats.append({
                'type': 'MAC Spoofing',
                'indicator': user,
                'severity': 'MEDIUM',
                'mac_count': count
            })
        
        return pd.DataFrame(threats)


class AuthenticationAnalyzer:
    """Comprehensive authentication analysis combining all components"""
    
    def __init__(self, dataframe):
        self.df = dataframe
        self.packet_capture = PacketCapture()
        self.mac_manager = MACAddressManager()
        self.access_rules = AccessRuleEngine()
        self.ids = IntrusionDetectionSystem(dataframe)
    
    def analyze(self):
        """Run full authentication analysis"""
        # Capture packets
        self.packet_capture.simulate_packet_capture(self.df)
        
        # Load MAC metadata
        self.mac_manager.load_from_dataframe(self.df)
        
        # Apply access policies
        self.df['access_decision'] = self.df.apply(
            lambda row: self.access_rules.evaluate_access(row), axis=1
        )
        
        # Generate threat report
        threat_report = self.ids.generate_threat_report()
        
        # Get device registry
        device_registry = self.mac_manager.get_device_registry()
        
        return {
            'packet_summary': self.packet_capture.get_packet_summary(),
            'device_registry': device_registry,
            'threat_report': threat_report,
            'access_policy_summary': self.access_rules.get_role_summary(),
            'access_decisions': self.df['access_decision'].value_counts()
        }


class AccessControlEngine:
    """Main access control engine for applying policies to authentication data"""
    
    def __init__(self, dataframe):
        self.df = dataframe.copy()
        self.access_rules = AccessRuleEngine()
    
    def apply_policies(self):
        """Apply access control policies to the dataframe"""
        # Apply access decisions based on rules
        self.df['access_decision'] = self.df.apply(
            lambda row: self.access_rules.evaluate_access(row), axis=1
        )
        return self.df

