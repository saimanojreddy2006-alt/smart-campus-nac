# Configuration for Smart Campus NAC

ALLOWED_MACS = [
    "AA:BB:CC:11:22:33",
    "DD:EE:FF:22:33:44"
]

ACCESS_POLICIES = {
    "faculty": {"start_hour": 0, "end_hour": 23},
    "student": {"start_hour": 8, "end_hour": 18},
    "guest": {"start_hour": 10, "end_hour": 16}
}

FAILED_LOGIN_THRESHOLD = 2

# Firewall Rules Configuration
FIREWALL_RULES = {
    "allow_internal": {
        "description": "Allow all internal network traffic",
        "source": "192.168.0.0/16",
        "destination": "192.168.0.0/16",
        "action": "ALLOW",
        "protocol": "ANY",
        "port": "ANY",
        "priority": 100
    },
    "allow_faculty_full": {
        "description": "Faculty members have full network access",
        "source": "192.168.1.0/24",
        "destination": "ANY",
        "action": "ALLOW",
        "protocol": "ANY",
        "port": "ANY",
        "priority": 50,
        "time_restriction": "00:00 - 23:59"
    },
    "allow_student_standard": {
        "description": "Student access during business hours",
        "source": "192.168.2.0/24",
        "destination": "ANY",
        "action": "ALLOW",
        "protocol": "TCP",
        "port": "80,443,22",
        "priority": 60,
        "time_restriction": "08:00 - 18:00"
    },
    "allow_guest_limited": {
        "description": "Guest internet access only",
        "source": "192.168.3.0/24",
        "destination": "ANY",
        "action": "ALLOW",
        "protocol": "TCP",
        "port": "80,443",
        "priority": 70,
        "time_restriction": "10:00 - 16:00"
    },
    "block_unknown_mac": {
        "description": "Block unknown MAC addresses",
        "source": "ANY",
        "destination": "ANY",
        "action": "DENY",
        "protocol": "ANY",
        "port": "ANY",
        "priority": 200,
        "condition": "Unknown MAC Address"
    },
    "block_bruteforce": {
        "description": "Block IP after multiple failed attempts",
        "source": "ANY",
        "destination": "ANY",
        "action": "DENY",
        "protocol": "ANY",
        "port": "ANY",
        "priority": 150,
        "condition": "Failed Login Threshold > 5"
    },
    "block_suspicious_ips": {
        "description": "Block known suspicious IP ranges",
        "source": "10.0.0.0/8",
        "destination": "ANY",
        "action": "DENY",
        "protocol": "ANY",
        "port": "ANY",
        "priority": 180
    },
    "allow_dns": {
        "description": "Allow DNS queries",
        "source": "ANY",
        "destination": "8.8.8.8",
        "action": "ALLOW",
        "protocol": "UDP",
        "port": "53",
        "priority": 10
    },
    "allow_ntp": {
        "description": "Allow NTP synchronization",
        "source": "ANY",
        "destination": "ANY",
        "action": "ALLOW",
        "protocol": "UDP",
        "port": "123",
        "priority": 20
    },
    "block_all": {
        "description": "Default deny all",
        "source": "ANY",
        "destination": "ANY",
        "action": "DENY",
        "protocol": "ANY",
        "port": "ANY",
        "priority": 1000
    }
}

# Network Segments
NETWORK_SEGMENTS = {
    "Faculty Network": {"cidr": "192.168.1.0/24", "color": "#2ECC71"},
    "Student Network": {"cidr": "192.168.2.0/24", "color": "#3498DB"},
    "Guest Network": {"cidr": "192.168.3.0/24", "color": "#F39C12"},
    "IoT Network": {"cidr": "192.168.4.0/24", "color": "#9B59B6"},
    "Management Network": {"cidr": "192.168.100.0/24", "color": "#E74C3C"}
}
