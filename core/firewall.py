"""
Firewall Engine - Network Access Control Firewall Implementation
Evaluates traffic against firewall rules defined in config
"""

import ipaddress
import pandas as pd
from datetime import datetime, time
from config.config import FIREWALL_RULES, NETWORK_SEGMENTS, ALLOWED_MACS


class FirewallEngine:
    """Firewall engine for evaluating network access requests"""
    
    def __init__(self, dataframe=None):
        self.df = dataframe
        self.rules = FIREWALL_RULES
        self.network_segments = NETWORK_SEGMENTS
        self.allowed_macs = ALLOWED_MACS
        self.blocked_ips = set()  # Dynamic blocking for brute force
        self.blocked_macs = set()  # Dynamic blocking for unknown devices
    
    def _parse_cidr(self, cidr_str):
        """Parse CIDR notation or return None for ANY"""
        if cidr_str == "ANY" or cidr_str is None:
            return None
        try:
            return ipaddress.ip_network(cidr_str, strict=False)
        except ValueError:
            return None
    
    def _ip_in_network(self, ip_str, cidr_str):
        """Check if IP is in the given CIDR network"""
        if cidr_str == "ANY":
            return True
        try:
            ip = ipaddress.ip_address(ip_str)
            network = self._parse_cidr(cidr_str)
            if network:
                return ip in network
            return False
        except ValueError:
            return False
    
    def _check_port(self, port, allowed_ports):
        """Check if port is allowed"""
        if allowed_ports == "ANY":
            return True
        try:
            allowed = [int(p.strip()) for p in allowed_ports.split(",")]
            return int(port) in allowed
        except ValueError:
            return False
    
    def _check_protocol(self, protocol, allowed_protocol):
        """Check if protocol is allowed"""
        if allowed_protocol == "ANY":
            return True
        return protocol.upper() == allowed_protocol.upper()
    
    def _check_time_restriction(self, time_restriction, current_hour=None):
        """Check if current time falls within the time restriction"""
        if time_restriction is None or time_restriction == "ANY":
            return True
        
        # Parse time restriction (e.g., "08:00 - 18:00")
        try:
            start_time, end_time = time_restriction.split(" - ")
            start_hour = int(start_time.split(":")[0])
            end_hour = int(end_time.split(":")[0])
            
            if current_hour is None:
                current_hour = datetime.now().hour
            
            return start_hour <= current_hour <= end_hour
        except (ValueError, AttributeError):
            return True
    
    def _evaluate_rule(self, rule, source_ip=None, dest_ip=None, protocol=None, port=None, 
                       mac_address=None, user_role=None, current_hour=None):
        """Evaluate a single firewall rule"""
        
        # Check source IP
        if rule.get("source") and source_ip:
            if not self._ip_in_network(source_ip, rule["source"]):
                return None  # Rule doesn't apply
        
        # Check destination IP
        if rule.get("destination") and dest_ip:
            if not self._ip_in_network(dest_ip, rule["destination"]):
                return None  # Rule doesn't apply
        
        # Check protocol
        if rule.get("protocol") and protocol:
            if not self._check_protocol(protocol, rule["protocol"]):
                return None  # Rule doesn't apply
        
        # Check port
        if rule.get("port") and port:
            if not self._check_port(port, rule["port"]):
                return None  # Rule doesn't apply
        
        # Check time restriction
        if rule.get("time_restriction"):
            if not self._check_time_restriction(rule["time_restriction"], current_hour):
                return None  # Rule doesn't apply
        
        # Check condition (for special rules like unknown MAC)
        if rule.get("condition"):
            if "Unknown MAC" in rule["condition"]:
                if mac_address and mac_address in self.allowed_macs:
                    return None  # Known MAC, rule doesn't apply
            if "Failed Login" in rule["condition"]:
                # This is handled dynamically
                pass
        
        # Rule matches!
        return {
            "rule_name": rule.get("description", "Unnamed Rule"),
            "action": rule.get("action", "DENY"),
            "priority": rule.get("priority", 999),
            "matched": True
        }
    
    def check_access(self, source_ip=None, dest_ip=None, protocol="TCP", port=80,
                    mac_address=None, user_role=None, current_hour=None):
        """
        Check if access should be allowed based on firewall rules
        Returns: (decision, matched_rule, details)
        """
        
        # Check dynamic blocks first
        if source_ip and source_ip in self.blocked_ips:
            return ("DENY", {"rule_name": "Dynamic Block - Brute Force", 
                           "priority": 1}, "IP blocked due to suspicious activity")
        
        if mac_address and mac_address in self.blocked_macs:
            return ("DENY", {"rule_name": "Dynamic Block - Unknown Device",
                           "priority": 1}, "Device blocked")
        
        # Sort rules by priority (lower = higher priority)
        sorted_rules = sorted(self.rules.items(), key=lambda x: x[1].get("priority", 999))
        
        # Evaluate each rule in priority order
        for rule_name, rule in sorted_rules:
            result = self._evaluate_rule(
                rule, source_ip, dest_ip, protocol, port,
                mac_address, user_role, current_hour
            )
            
            if result:
                decision = result["action"]
                details = f"{result['rule_name']} (Priority: {result['priority']})"
                
                if decision == "ALLOW":
                    return ("ALLOW", result, details)
                else:
                    return ("DENY", result, details)
        
        # Default: deny if no rules match
        return ("DENY", {"rule_name": "Default Deny", "priority": 1000}, "No matching rule found")
    
    def get_matching_rules(self, source_ip=None, dest_ip=None, protocol=None, port=None):
        """Get all rules that would match the given traffic"""
        matches = []
        
        for rule_name, rule in self.rules.items():
            result = self._evaluate_rule(rule, source_ip, dest_ip, protocol, port)
            if result:
                matches.append({
                    "rule_name": rule_name,
                    **rule
                })
        
        return sorted(matches, key=lambda x: x.get("priority", 999))
    
    def block_ip(self, ip_address):
        """Dynamically block an IP address"""
        self.blocked_ips.add(ip_address)
        return f"IP {ip_address} has been blocked"
    
    def unblock_ip(self, ip_address):
        """Remove an IP from the blocked list"""
        if ip_address in self.blocked_ips:
            self.blocked_ips.remove(ip_address)
            return f"IP {ip_address} has been unblocked"
        return f"IP {ip_address} was not blocked"
    
    def block_mac(self, mac_address):
        """Dynamically block a MAC address"""
        self.blocked_macs.add(mac_address)
        return f"MAC {mac_address} has been blocked"
    
    def unblock_mac(self, mac_address):
        """Remove a MAC from the blocked list"""
        if mac_address in self.blocked_macs:
            self.blocked_macs.remove(mac_address)
            return f"MAC {mac_address} has been unblocked"
        return f"MAC {mac_address} was not blocked"
    
    def get_blocked_ips(self):
        """Get all blocked IP addresses"""
        return list(self.blocked_ips)
    
    def get_blocked_macs(self):
        """Get all blocked MAC addresses"""
        return list(self.blocked_macs)
    
    def apply_brute_force_protection(self, failed_attempts_df, threshold=5):
        """Block IPs with failed login attempts exceeding threshold"""
        blocked_count = 0
        for mac, count in failed_attempts_df.items():
            if count >= threshold:
                # In a real system, we'd need to map MAC to IP
                # For now, we'll add to blocked_macs based on detection
                self.blocked_macs.add(mac)
                blocked_count += 1
        return blocked_count
    
    def get_rules_summary(self):
        """Get summary of all firewall rules"""
        summary = []
        for rule_name, rule in self.rules.items():
            summary.append({
                "name": rule_name,
                "description": rule.get("description", ""),
                "action": rule.get("action", "DENY"),
                "priority": rule.get("priority", 999),
                "source": rule.get("source", "ANY"),
                "destination": rule.get("destination", "ANY"),
                "protocol": rule.get("protocol", "ANY"),
                "port": rule.get("port", "ANY"),
                "time_restriction": rule.get("time_restriction", "ANY")
            })
        return sorted(summary, key=lambda x: x["priority"])
    
    def analyze_network_segment(self, segment_name):
        """Analyze traffic for a specific network segment"""
        if segment_name not in self.network_segments:
            return None
        
        segment = self.network_segments[segment_name]
        cidr = segment["cidr"]
        
        # Find rules applicable to this segment
        applicable_rules = []
        for rule_name, rule in self.rules.items():
            if rule.get("source") and self._ip_in_network(cidr.split("/")[0], rule["source"]):
                applicable_rules.append({
                    "rule_name": rule_name,
                    "action": rule.get("action"),
                    "description": rule.get("description")
                })
        
        return {
            "segment_name": segment_name,
            "cidr": cidr,
            "color": segment.get("color"),
            "applicable_rules": applicable_rules
        }
    
    def simulate_traffic(self, test_cases):
        """Simulate traffic scenarios and return expected decisions"""
        results = []
        
        for test_case in test_cases:
            decision, rule, details = self.check_access(
                source_ip=test_case.get("source_ip"),
                dest_ip=test_case.get("dest_ip"),
                protocol=test_case.get("protocol", "TCP"),
                port=test_case.get("port", 80),
                mac_address=test_case.get("mac_address"),
                user_role=test_case.get("user_role")
            )
            
            results.append({
                "test_case": test_case.get("description", "Test"),
                "source_ip": test_case.get("source_ip", "N/A"),
                "dest_ip": test_case.get("dest_ip", "N/A"),
                "protocol": test_case.get("protocol", "TCP"),
                "port": test_case.get("port", 80),
                "decision": decision,
                "matched_rule": rule.get("rule_name") if rule else "None",
                "details": details
            })
        
        return pd.DataFrame(results)
    
    def get_rule_statistics(self):
        """Get statistics about firewall rules"""
        total_rules = len(self.rules)
        allow_rules = len([r for r in self.rules.values() if r.get("action") == "ALLOW"])
        deny_rules = len([r for r in self.rules.values() if r.get("action") == "DENY"])
        
        rules_with_time = len([r for r in self.rules.values() if r.get("time_restriction")])
        
        return {
            "total_rules": total_rules,
            "allow_rules": allow_rules,
            "deny_rules": deny_rules,
            "rules_with_time_restriction": rules_with_time,
            "blocked_ips_count": len(self.blocked_ips),
            "blocked_macs_count": len(self.blocked_macs)
        }


class FirewallDashboardHelper:
    """Helper class for rendering firewall UI in dashboard"""
    
    @staticmethod
    def format_rule_for_display(rule_dict):
        """Format a rule dictionary for better display"""
        return {
            "Priority": rule_dict.get("priority", "N/A"),
            "Rule Name": rule_dict.get("name", "N/A"),
            "Action": rule_dict.get("action", "N/A"),
            "Source": rule_dict.get("source", "ANY"),
            "Destination": rule_dict.get("destination", "ANY"),
            "Protocol": rule_dict.get("protocol", "ANY"),
            "Port": rule_dict.get("port", "ANY"),
            "Time Restriction": rule_dict.get("time_restriction", "ANY"),
            "Description": rule_dict.get("description", "")
        }
    
    @staticmethod
    def get_color_for_action(action):
        """Get color code for action type"""
        colors = {
            "ALLOW": "#2ECC71",  # Green
            "DENY": "#E74C3C"   # Red
        }
        return colors.get(action, "#95A5A6")

