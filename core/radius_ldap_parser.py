"""
RADIUS/LDAP Log Parser for Smart Campus NAC
Parses authentication logs with RADIUS and LDAP attributes
"""

import pandas as pd
import re
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)


class RADIUSLogParser:
    """Parser for RADIUS authentication logs"""
    
    # Common RADIUS log patterns
    RADIUS_PATTERNS = {
        'access_request': r'(?P<timestamp>[\d\-: ]+)\s+(?P<nas_ip>\d+\.\d+\.\d+\.\d+)\s+\[(?P<nas_name>[\w\-]+)\]\s+Access-Request\s+(?P<username>\w+)\s+.*',
        'access_accept': r'(?P<timestamp>[\d\-: ]+)\s+(?P<nas_ip>\d+\.\d+\.\d+\.\d+)\s+\[(?P<nas_name>[\w\-]+)\]\s+Access-Accept\s+(?P<username>\w+)\s+.*',
        'access_reject': r'(?P<timestamp>[\d\-: ]+)\s+(?P<nas_ip>\d+\.\d+\.\d+\.\d+)\s+\[(?P<nas_name>[\w\-]+)\]\s+Access-Reject\s+(?P<username>\w+)\s+.*',
        'accounting_start': r'Acct-Status-Type = Start.*User-Name = (?P<username>\w+).*Acct-Session-Id = (?P<session_id>[\w]+)',
        'accounting_stop': r'Acct-Status-Type = Stop.*User-Name = (?P<username>\w+).*Acct-Session-Time = (?P<session_time>\d+)'
    }
    
    # RADIUS attribute mappings
    RADIUS_ATTR_CODES = {
        1: "User-Name",
        2: "User-Password", 
        4: "NAS-IP-Address",
        5: "NAS-Port",
        6: "Service-Type",
        7: "Framed-Protocol",
        8: "Framed-IP-Address",
        30: "NAS-Port-Type",
        31: "Port-Limit",
        41: "Acct-Session-Time",
        44: "Acct-Terminate-Cause"
    }
    
    def __init__(self):
        self.log_data = []
    
    def parse_log_line(self, line):
        """Parse a single RADIUS log line"""
        for pattern_name, pattern in self.RADIUS_PATTERNS.items():
            match = re.match(pattern, line, re.IGNORECASE)
            if match:
                return {
                    'log_type': pattern_name,
                    'timestamp': match.group('timestamp'),
                    'username': match.group('username'),
                    'nas_ip': match.group('nas_ip'),
                    'nas_name': match.group('nas_name')
                }
        return None
    
    def parse_dict_attribute(self, attr_string):
        """Parse RADIUS dictionary attribute format: Attr-Name = Value"""
        attributes = {}
        for line in attr_string.split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                attributes[key.strip()] = value.strip()
        return attributes
    
    def calculate_session_duration(self, start_time, stop_time):
        """Calculate session duration in seconds"""
        try:
            start = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
            stop = datetime.strptime(stop_time, "%Y-%m-%d %H:%M:%S")
            return (stop - start).seconds
        except:
            return 0
    
    def parse_csv_dataframe(self, df):
        """Parse enhanced CSV dataframe with RADIUS attributes"""
        if df is None or df.empty:
            return None
        
        # Validate required columns
        required_cols = ['username', 'mac_address', 'login_status']
        missing = [c for c in required_cols if c not in df.columns]
        if missing:
            logging.warning(f"Missing columns: {missing}")
        
        # Add parsed RADIUS info
        parsed_data = []
        
        for _, row in df.iterrows():
            entry = dict(row)
            
            # Add RADIUS attribute descriptions
            if 'ldap_result_code' in row:
                entry['auth_result'] = self._get_auth_result_description(
                    row.get('login_status'),
                    row.get('ldap_result_code'),
                    row.get('failure_reason')
                )
            
            # Determine authentication source
            entry['auth_source'] = self._determine_auth_source(row)
            
            parsed_data.append(entry)
        
        return pd.DataFrame(parsed_data)
    
    def _get_auth_result_description(self, status, ldap_code=None, failure_reason=None):
        """Get human-readable auth result description"""
        if status == 'success':
            return "Authentication Successful"
        
        if failure_reason:
            return failure_reason
        
        if ldap_code:
            ldap_messages = {
                49: "Invalid Credentials",
                50: "Insufficient Access Rights",
                51: "Server Busy",
                52: "Server Unavailable"
            }
            return ldap_messages.get(ldap_code, f"LDAP Error {ldap_code}")
        
        return "Authentication Failed"
    
    def _determine_auth_source(self, row):
        """Determine the authentication source/method"""
        auth_method = row.get('auth_method', '')
        auth_protocol = row.get('auth_protocol', '')
        
        if 'LDAP' in str(auth_method):
            return f"LDAP ({auth_protocol})"
        elif 'RADIUS' in str(auth_method):
            return f"RADIUS ({auth_protocol})"
        elif 'Certificate' in str(auth_method):
            return f"Certificate ({auth_protocol})"
        elif 'Biometric' in str(auth_method):
            return f"Biometric ({auth_protocol})"
        elif 'Captive' in str(auth_method):
            return "Captive Portal"
        else:
            return "Local Authentication"


class LDAPLogParser:
    """Parser for LDAP authentication logs"""
    
    # LDAP result codes
    LDAP_RESULT_CODES = {
        0: "Success",
        1: "Operations Error",
        2: "Protocol Error",
        3: "Time Limit Exceeded",
        4: "Size Limit Exceeded",
        5: "Compare False",
        6: "Compare True",
        7: "Auth Method Not Supported",
        8: "Strong Auth Required",
        10: "Referral",
        11: "Admin Limit Exceeded",
        12: "Unavailable Critical Extension",
        13: "Confidentiality Required",
        14: "SASL Bind In Progress",
        32: "No Such Object",
        33: "Alias Problem",
        34: "Invalid DN Syntax",
        35: "Alias Dereference Problem",
        36: "Inappropriate Authentication",
        37: "Insufficient Access Rights",
        48: "Inappropriate Authentication",
        49: "Invalid Credentials",
        50: "Insufficient Access Rights",
        51: "Busy",
        52: "Unavailable",
        53: "Unwilling To Perform",
        54: "Loop Detect",
        64: "Naming Violation",
        65: "Object Class Violation",
        66: "Not Allowed On Non-Leaf",
        67: "Not Allowed On RDN",
        68: "Entry Already Exists",
        69: "Object Class Mods Prohibited",
        70: "Results Too Large",
        71: "Effects Multiple DSAs"
    }
    
    # LDAP operation types
    LDAP_OPERATIONS = {
        'BIND': 'Bind Request',
        'SEARCH': 'Search Request',
        'ADD': 'Add Request',
        'MODIFY': 'Modify Request',
        'DELETE': 'Delete Request',
        'MODRDN': 'Modify DN Request',
        'COMPARE': 'Compare Request',
        'ABANDON': 'Abandon Request',
        'EXTENDED': 'Extended Request'
    }
    
    def __init__(self):
        self.parsed_logs = []
    
    def parse_ldap_log_line(self, line):
        """Parse a single LDAP log line"""
        # Example: "2024-01-15 10:30:45 - INFO - BIND - uid=john,ou=people,dc=example,dc=com - SUCCESS"
        pattern = r'(?P<timestamp>[\d\-: ]+)\s+-\s+(?P<level>\w+)\s+-\s+(?P<operation>\w+)\s+-\s+(?P<dn>[\w=,]+)\s+-\s+(?P<result>\w+)'
        match = re.match(pattern, line)
        
        if match:
            return {
                'timestamp': match.group('timestamp'),
                'level': match.group('level'),
                'operation': self.LDAP_OPERATIONS.get(match.group('operation'), match.group('operation')),
                'distinguished_name': match.group('dn'),
                'result': match.group('result'),
                'result_code': self._get_result_code(match.group('result'))
            }
        return None
    
    def _get_result_code(self, result):
        """Map result string to numeric code"""
        result_map = {
            'SUCCESS': 0,
            'OPERATIONS_ERROR': 1,
            'PROTOCOL_ERROR': 2,
            'INVALID_CREDENTIALS': 49,
            'INSUFFICIENT_ACCESS': 50,
            'BUSY': 51,
            'UNAVAILABLE': 52,
            'UNWILLING_TO_PERFORM': 53
        }
        return result_map.get(result.upper(), -1)
    
    def parse_csv_dataframe(self, df):
        """Parse enhanced CSV dataframe with LDAP attributes"""
        if df is None or df.empty:
            return None
        
        parsed_data = []
        
        for _, row in df.iterrows():
            entry = dict(row)
            
            # Add LDAP result description
            if 'ldap_result_code' in row:
                entry['ldap_result_description'] = self.LDAP_RESULT_CODES.get(
                    row['ldap_result_code'], 
                    f"Unknown ({row['ldap_result_code']})"
                )
            
            # Add operation type based on auth method
            if 'LDAP' in str(row.get('auth_method', '')):
                entry['ldap_operation'] = 'BIND'
            else:
                entry['ldap_operation'] = 'N/A'
            
            parsed_data.append(entry)
        
        return pd.DataFrame(parsed_data)
    
    def get_bind_stats(self, df):
        """Get LDAP bind statistics"""
        if df is None or 'ldap_result_code' not in df.columns:
            return {}
        
        total = len(df)
        successful = len(df[df['ldap_result_code'] == 0])
        failed = total - successful
        
        return {
            'total_binds': total,
            'successful': successful,
            'failed': failed,
            'success_rate': (successful / total * 100) if total > 0 else 0
        }


class UnifiedAuthLogParser:
    """Unified parser for both RADIUS and LDAP authentication logs"""
    
    def __init__(self):
        self.radius_parser = RADIUSLogParser()
        self.ldap_parser = LDAPLogParser()
    
    def parse_dataframe(self, df):
        """Parse authentication dataframe and add RADIUS/LDAP context"""
        if df is None or df.empty:
            return df
        
        # Parse with both parsers
        df = self.radius_parser.parse_csv_dataframe(df)
        df = self.ldap_parser.parse_csv_dataframe(df)
        
        # Add network segment info
        df = self._add_network_segment(df)
        
        return df
    
    def _add_network_segment(self, df):
        """Add network segment based on source IP"""
        def get_segment(ip):
            if pd.isna(ip):
                return "Unknown"
            if ip.startswith("192.168.1"):
                return "Faculty"
            elif ip.startswith("192.168.2"):
                return "Student"
            elif ip.startswith("192.168.3"):
                return "Guest"
            elif ip.startswith("192.168.4"):
                return "IoT"
            else:
                return "External"
        
        if 'source_ip' in df.columns:
            df['network_segment'] = df['source_ip'].apply(get_segment)
        
        return df
    
    def get_authentication_summary(self, df):
        """Get comprehensive authentication summary"""
        summary = {
            'total_attempts': len(df),
            'successful': len(df[df['login_status'] == 'success']),
            'failed': len(df[df['login_status'] == 'failed']),
            'success_rate': 0
        }
        
        if summary['total_attempts'] > 0:
            summary['success_rate'] = summary['successful'] / summary['total_attempts'] * 100
        
        # By auth method
        if 'auth_method' in df.columns:
            summary['by_auth_method'] = df.groupby('auth_method')['login_status'].value_counts().to_dict()
        
        # By network segment
        if 'network_segment' in df.columns:
            summary['by_segment'] = df.groupby('network_segment')['login_status'].value_counts().to_dict()
        
        # LDAP stats
        if 'ldap_result_code' in df.columns:
            ldap_stats = self.ldap_parser.get_bind_stats(df)
            summary['ldap_stats'] = ldap_stats
        
        return summary

