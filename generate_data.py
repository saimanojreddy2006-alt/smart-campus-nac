"""
Enhanced Data Generator for Smart Campus NAC
Generates authentication logs with RADIUS/LDAP-style network details
"""

import pandas as pd
import random
from datetime import datetime, timedelta

# Base data
users = ["raj", "anita", "guest1", "guest2", "admin", "user1", "user2"]
macs = [
    "AA:BB:CC:11:22:33",
    "DD:EE:FF:22:33:44",
    "GG:HH:II:44:55:66",
    "ZZ:YY:XX:99:88:77",
    "PP:QQ:RR:12:34:56"
]
os_types = ["Windows", "MacOS", "Linux", "Android"]
roles = ["student", "faculty", "guest"]

# Network segments (from config)
network_segments = {
    "faculty": {"cidr": "192.168.1.0/24", "color": "#2ECC71"},
    "student": {"cidr": "192.168.2.0/24", "color": "#3498DB"},
    "guest": {"cidr": "192.168.3.0/24", "color": "#F39C12"},
    "iot": {"cidr": "192.168.4.0/24", "color": "#9B59B6"}
}

# Common ports and protocols
common_ports = {
    "HTTP": (80, "TCP"),
    "HTTPS": (443, "TCP"),
    "SSH": (22, "TCP"),
    "RDP": (3389, "TCP"),
    "DNS": (53, "UDP"),
    "NTP": (123, "UDP"),
    "SMB": (445, "TCP"),
    "LDAP": (389, "TCP"),
    "LDAPS": (636, "TCP"),
    "RADIUS": (1812, "UDP"),
    "HTTP-alt": (8080, "TCP"),
    "FTP": (21, "TCP"),
    "SMTP": (25, "TCP"),
    "IMAP": (143, "TCP"),
    "POP3": (110, "TCP")
}

# RADIUS attribute types (for authentication logging)
RADIUS_ATTRS = {
    1: "User-Name",
    2: "User-Password",
    3: "CHAP-Password",
    4: "NAS-IP-Address",
    5: "NAS-Port",
    6: "Service-Type",
    7: "Framed-Protocol",
    8: "Framed-IP-Address",
    9: "Framed-Netmask",
    10: "Route",
    11: "Reply-Message",
    12: "Callback-Number",
    13: "Callback-ID",
    14: "Expiration",
    15: "Framed-Route",
    16: "Framed-IP-Netmask",
    17: "NAS-Identifier",
    18: "Proxy-State",
    19: "Login-LAT-Service",
    20: "Login-LAT-Node",
    21: "Login-LAT-Group",
    22: "Framed Appletalk Zone",
    23: "Acct-Session-Id",
    24: "Acct-Multi-Session-Id",
    25: "Acct-Link-Count",
    26: "Vendor-Specific",
    27: "Session-Timeout",
    28: "Idle-Timeout",
    29: "Termination-Action",
    30: "NAS-Port-Type",
    31: "Port-Limit",
    32: "Login-IP-Host",
    33: "Tunnel-Type",
    34: "Tunnel-Medium-Type",
    35: "Tunnel-Client-Endpt",
    36: "Tunnel-Server-Endpt",
    37: "Acct-Status-Type",
    38: "Acct-Delay-Time",
    39: "Acct-Input-Octets",
    40: "Acct-Output-Octets",
    41: "Acct-Session-Time",
    42: "Acct-Input-Packets",
    43: "Acct-Output-Packets",
    44: "Acct-Terminate-Cause",
    45: "Acct-Multi-Session-Id",
    46: "Acct-Link-Count",
    47: "Acct-Input-Gigawords",
    48: "Acct-Output-Gigawords"
}

# LDAP result codes
LDAP_RESULT_CODES = {
    0: "success",
    1: "operationsError",
    2: "protocolError",
    3: "timeLimitExceeded",
    4: "sizeLimitExceeded",
    5: "compareFalse",
    6: "compareTrue",
    7: "authMethodNotSupported",
    8: "strongAuthRequired",
    10: "referral",
    11: "adminLimitExceeded",
    12: "unavailableCriticalExtension",
    13: "confidentialityRequired",
    14: "saslBindInProgress",
    49: "invalidCredentials",
    50: "insufficientAccessRights",
    51: "busy",
    52: "unavailable",
    53: "unwillingToPerform",
    54: "loopDetect",
    64: "namingViolation",
    65: "objectClassViolation",
    68: "entryAlreadyExists",
     69: "objectClassModsProhibited"
}

def generate_ip_for_role(role, mac_index):
    """Generate IP address based on role (network segment)"""
    segment = network_segments.get(role, network_segments["guest"])
    cidr = segment["cidr"]
    # Extract base IP from CIDR
    base_ip = cidr.split("/")[0].rsplit(".", 1)[0]
    # Generate last octet based on MAC index
    last_octet = (mac_index * 7) % 254 + 1
    return f"{base_ip}.{last_octet}"

def generate_destination_ip():
    """Generate a random destination IP (internal or external)"""
    # 70% internal, 30% external
    if random.random() < 0.7:
        # Internal network
        segment = random.choice(list(network_segments.values()))
        base_ip = segment["cidr"].split("/")[0].rsplit(".", 1)[0]
        return f"{base_ip}.{random.randint(1, 254)}"
    else:
        # External (Google DNS, Cloudflare, etc.)
        external = ["8.8.8.8", "1.1.1.1", "208.67.222.222", "9.9.9.9"]
        return random.choice(external)

def get_port_protocol():
    """Get random port and protocol based on common usage"""
    # Weighted selection - more common ports have higher weight
    weights = [30, 25, 15, 5, 5, 3, 3, 2, 2, 1, 2, 1, 1, 1, 1]
    service = random.choices(list(common_ports.keys()), weights=weights)[0]
    port, protocol = common_ports[service]
    return port, protocol

def get_authentication_method(user_role, os_type):
    """Determine authentication method based on user role and OS"""
    if user_role == "faculty":
        methods = ["LDAP", "RADIUS", "Certificate", "Biometric"]
    elif user_role == "student":
        methods = ["LDAP", "RADIUS", "OTP", "Password"]
    else:  # guest
        methods = ["Captive Portal", "RADIUS", "OTP"]
    return random.choice(methods)

def get_auth_protocol(auth_method):
    """Map authentication method to protocol"""
    protocols = {
        "LDAP": "LDAPv3",
        "RADIUS": "RADIUS",
        "Certificate": "EAP-TLS",
        "Biometric": "EAP-AKA",
        "OTP": "EAP-OTP",
        "Password": "PAP/CHAP",
        "Captive Portal": "HTTP"
    }
    return protocols.get(auth_method, "PAP")

def generate_auth_log_entry(timestamp, entry_num):
    """Generate a single authentication log entry with RADIUS/LDAP details"""
    
    # Base authentication data
    username = random.choice(users)
    mac_address = random.choice(macs)
    mac_index = macs.index(mac_address)
    os_type = random.choice(os_types)
    user_role = random.choice(roles)
    
    # Determine login status with weighted probability
    # Higher failure rate for guests and students
    if user_role == "guest":
        status_weights = [0.7, 0.3]
    elif user_role == "student":
        status_weights = [0.75, 0.25]
    else:  # faculty
        status_weights = [0.9, 0.1]
    
    login_status = random.choices(["success", "failed"], weights=status_weights)[0]
    
    # Network details
    source_ip = generate_ip_for_role(user_role, mac_index)
    dest_ip = generate_destination_ip()
    port, protocol = get_port_protocol()
    
    # Authentication details
    auth_method = get_authentication_method(user_role, os_type)
    auth_protocol = get_auth_protocol(auth_method)
    
    # RADIUS/LDAP specific fields
    if random.random() < 0.7:  # 70% have RADIUS info
        radius_acct_session_id = f"0000{entry_num:06d}"
        radius_nas_ip = f"192.168.0.{random.randint(1, 10)}"
        radius_nas_port = random.randint(1, 4096)
        nas_port_type = random.choice(["Virtual", "Async", "Sync", "ISDN", "Wireless"])
        framed_ip = source_ip if random.random() > 0.3 else ""
        service_type = random.choice(["Login-User", "Framed-User", "Callback-Login-User", "Callback-Framed-User"])
    else:
        radius_acct_session_id = ""
        radius_nas_ip = ""
        radius_nas_port = 0
        nas_port_type = ""
        framed_ip = ""
        service_type = ""
    
    # LDAP specific fields (when authentication fails or uses LDAP)
    if auth_method == "LDAP" or login_status == "failed":
        ldap_bind_dn = f"uid={username},ou=people,dc=campus,dc=edu"
        ldap_search_base = f"ou=people,dc=campus,dc=edu"
        ldap_filter = f"(uid={username})"
        if random.random() < 0.3:
            ldap_result_code = random.choice([49, 50, 51])  # Common failure codes
            ldap_result_msg = LDAP_RESULT_CODES.get(ldap_result_code, "unknown")
        else:
            ldap_result_code = 0
            ldap_result_msg = "success"
    else:
        ldap_bind_dn = ""
        ldap_search_base = ""
        ldap_filter = ""
        ldap_result_code = 0
        ldap_result_msg = ""
    
    # Additional security fields
    if login_status == "failed":
        failure_reason = random.choice([
            "Invalid credentials",
            "Account locked",
            "Password expired",
            "MAC not authorized",
            "Time-based restriction",
            "Policy violation",
            "Certificate expired",
            "IP not in allowed range"
        ])
    else:
        failure_reason = ""
    
    # Session info
    session_timeout = random.choice([1800, 3600, 7200, 14400]) if login_status == "success" else 0
    idle_timeout = 900
    
    # Build entry
    entry = {
        # Core authentication fields
        "timestamp": timestamp,
        "username": username,
        "mac_address": mac_address,
        "os": os_type,
        "user_role": user_role,
        "login_status": login_status,
        
        # Network layer fields (for firewall)
        "source_ip": source_ip,
        "destination_ip": dest_ip,
        "source_port": random.randint(1024, 65535),
        "destination_port": port,
        "protocol": protocol,
        
        # Authentication method info
        "auth_method": auth_method,
        "auth_protocol": auth_protocol,
        
        # RADIUS attributes
        "radius_acct_session_id": radius_acct_session_id,
        "radius_nas_ip": radius_nas_ip,
        "radius_nas_port": radius_nas_port,
        "radius_nas_port_type": nas_port_type,
        "radius_framed_ip": framed_ip,
        "radius_service_type": service_type,
        
        # LDAP attributes
        "ldap_bind_dn": ldap_bind_dn,
        "ldap_search_base": ldap_search_base,
        "ldap_filter": ldap_filter,
        "ldap_result_code": ldap_result_code,
        "ldap_result_message": ldap_result_msg,
        
        # Session info
        "session_timeout": session_timeout,
        "idle_timeout": idle_timeout,
        
        # Failure details
        "failure_reason": failure_reason
    }
    
    return entry

def generate_logs(count=1000, days_back=5):
    """Generate enhanced authentication logs"""
    
    data = []
    start_time = datetime.now() - timedelta(days=days_back)
    
    for i in range(count):
        timestamp = start_time + timedelta(minutes=i * int(1440 * days_back / count))
        entry = generate_auth_log_entry(timestamp, i)
        data.append(entry)
    
    df = pd.DataFrame(data)
    
    return df

def save_logs(df, filename="data/auth_logs.csv"):
    """Save logs to CSV"""
    df.to_csv(filename, index=False)
    print(f"Generated {len(df)} log entries with RADIUS/LDAP attributes.")
    print(f"Saved to {filename}")
    
    # Print summary
    print("\n=== Data Summary ===")
    print(f"Unique users: {df['username'].nunique()}")
    print(f"Unique MACs: {df['mac_address'].nunique()}")
    print(f"Unique roles: {df['user_role'].unique().tolist()}")
    print(f"Login success rate: {(df['login_status'] == 'success').mean()*100:.1f}%")
    print(f"\nProtocols: {df['protocol'].value_counts().to_dict()}")
    print(f"Auth methods: {df['auth_method'].value_counts().to_dict()}")
    print(f"Network segments: {df['source_ip'].str.rsplit('.', n=1).str[0].value_counts().to_dict()}")

if __name__ == "__main__":
    # Generate 2000 entries over 7 days
    df = generate_logs(count=2000, days_back=7)
    save_logs(df)

