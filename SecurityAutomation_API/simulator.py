"""
Security Event Simulator - Generates realistic security events for demo mode.

Consolidates all 6 event generators from the Kubernetes pod simulators:
  HSPS: database, api, webui
  STAR: database, api, webui

When DATA_SOURCE=simulated, these generators run inside the API and produce
the same events that would normally come from pods in AKS.
"""

import random
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict


# =============================================================================
# HSPS Database Security Event Generator
# =============================================================================
class HspsDatabaseEventGenerator:
    def __init__(self):
        self.app_type = "database"
        self.system = "HSPS"
        self.event_types = [
            "auth_failure", "privilege_escalation", "data_exfiltration",
            "sql_injection", "connection_spike", "failed_login",
            "unusual_query_pattern", "brute_force_attack"
        ]
        self.usernames = [
            "admin", "dbadmin", "pharmacy_user", "readonly_user",
            "backup_service", "reporting_user", "api_service"
        ]
        self.suspicious_usernames = [
            "root", "sa", "postgres", "mysql", "oracle",
            "' OR '1'='1", "admin'--", "test", "guest"
        ]
        self.ip_addresses = ["10.0.1.100", "10.0.1.101", "10.0.1.102", "192.168.1.50", "172.16.0.10"]
        self.suspicious_ips = ["185.220.101.1", "45.142.212.61", "198.51.100.42", "203.0.113.5", "192.0.2.100"]
        self.sql_injection_patterns = [
            "' OR '1'='1", "'; DROP TABLE users--", "UNION SELECT * FROM passwords",
            "1' AND 1=1--", "admin'--", "' OR 1=1#"
        ]

    def generate_event(self) -> Dict:
        event_type = random.choice(self.event_types)
        base = {"app_type": self.app_type, "app_system": self.system, "source": f"hsps-database-pod-{random.randint(0,1)}"}

        if event_type == "auth_failure":
            return {**base, "event_type": "auth_failure", "severity": "medium",
                    "username": random.choice(self.usernames + self.suspicious_usernames),
                    "source_ip": random.choice(self.ip_addresses + self.suspicious_ips),
                    "reason": random.choice(["invalid_credentials", "expired_password", "account_locked", "invalid_certificate", "missing_mfa"]),
                    "timestamp": datetime.utcnow().isoformat(), "database": "hsps_pharmacy", "attempt_count": random.randint(1, 10)}
        elif event_type == "privilege_escalation":
            return {**base, "event_type": "privilege_escalation", "severity": "high",
                    "username": random.choice(self.usernames),
                    "source_ip": random.choice(self.ip_addresses + self.suspicious_ips),
                    "attempted_action": random.choice(["ALTER USER SET ROLE admin", "GRANT ALL PRIVILEGES", "CREATE USER WITH SUPERUSER"]),
                    "current_role": "user", "target_role": "admin", "timestamp": datetime.utcnow().isoformat(), "blocked": random.choice([True, False])}
        elif event_type == "data_exfiltration":
            return {**base, "event_type": "data_exfiltration", "severity": "critical",
                    "username": random.choice(self.usernames), "source_ip": random.choice(self.ip_addresses),
                    "destination_ip": random.choice(self.suspicious_ips),
                    "bytes_transferred": random.randint(10000000, 1000000000), "records_accessed": random.randint(1000, 100000),
                    "tables": random.sample(["patients", "medications", "prescriptions", "billing"], k=random.randint(1, 3)),
                    "timestamp": datetime.utcnow().isoformat(), "duration_seconds": random.randint(60, 3600)}
        elif event_type == "sql_injection":
            return {**base, "event_type": "sql_injection", "severity": "high",
                    "source_ip": random.choice(self.suspicious_ips),
                    "injection_pattern": random.choice(self.sql_injection_patterns),
                    "target_table": random.choice(["users", "patients", "medications"]),
                    "blocked": True, "timestamp": datetime.utcnow().isoformat(),
                    "waf_rule_triggered": f"SQL_INJECTION_{random.randint(1000, 9999)}"}
        elif event_type == "connection_spike":
            return {**base, "event_type": "connection_spike", "severity": "medium",
                    "baseline_connections": random.randint(20, 50), "current_connections": random.randint(200, 500),
                    "spike_percentage": random.randint(300, 1000), "timestamp": datetime.utcnow().isoformat(),
                    "potential_ddos": random.choice([True, False])}
        elif event_type == "failed_login":
            return {**base, "event_type": "failed_login", "severity": "low",
                    "username": random.choice(self.suspicious_usernames),
                    "source_ip": random.choice(self.suspicious_ips),
                    "failure_reason": random.choice(["invalid_password", "user_not_found", "account_disabled"]),
                    "attempt_number": random.randint(1, 20), "timestamp": datetime.utcnow().isoformat()}
        elif event_type == "unusual_query_pattern":
            return {**base, "event_type": "unusual_query_pattern", "severity": "medium",
                    "username": random.choice(self.usernames), "source_ip": random.choice(self.ip_addresses),
                    "query_pattern": random.choice(["SELECT * FROM information_schema.tables", "SELECT * FROM pg_shadow",
                                                     "COPY (SELECT * FROM patients) TO '/tmp/data.csv'"]),
                    "execution_time_ms": random.uniform(5000, 30000), "rows_affected": random.randint(10000, 1000000),
                    "timestamp": datetime.utcnow().isoformat(),
                    "flagged_reason": random.choice(["full_table_scan", "excessive_rows", "system_table_access", "data_export_attempt"])}
        else:  # brute_force_attack
            return {**base, "event_type": "brute_force_attack", "severity": "high",
                    "target_username": random.choice(self.usernames), "source_ip": random.choice(self.suspicious_ips),
                    "attempt_count": random.randint(50, 500), "time_window_seconds": random.randint(60, 600),
                    "success_count": 0, "timestamp": datetime.utcnow().isoformat(), "blocked": True}


# =============================================================================
# HSPS API Security Event Generator
# =============================================================================
class HspsApiEventGenerator:
    def __init__(self):
        self.app_type = "api"
        self.system = "HSPS"
        self.event_types = [
            "rate_limit_exceeded", "auth_failure", "validation_error", "sql_injection",
            "xss_attempt", "command_injection", "api_key_abuse", "unusual_access_pattern",
            "payload_size_exceeded", "ddos_attempt"
        ]
        self.endpoints = ["/api/v1/prescriptions", "/api/v1/medications", "/api/v1/inventory",
                          "/api/v1/orders", "/api/v1/patients", "/api/v1/admin/users", "/api/v1/admin/config"]
        self.suspicious_ips = ["185.220.101.1", "45.142.212.61", "198.51.100.42", "203.0.113.5", "192.0.2.100", "91.213.8.235"]
        self.ip_addresses = ["10.0.1.100", "10.0.1.101", "10.0.1.102", "192.168.1.50", "172.16.0.10"]

    def generate_event(self) -> Dict:
        event_type = random.choice(self.event_types)
        base = {"app_type": self.app_type, "app_system": self.system, "source": f"hsps-api-pod-{random.randint(0,2)}"}

        if event_type == "rate_limit_exceeded":
            return {**base, "event_type": "rate_limit_exceeded", "severity": "medium",
                    "endpoint": random.choice(self.endpoints), "source_ip": random.choice(self.ip_addresses + self.suspicious_ips),
                    "requests_per_minute": random.randint(100, 1000), "limit": 60, "timestamp": datetime.utcnow().isoformat(), "action_taken": "throttled"}
        elif event_type == "auth_failure":
            return {**base, "event_type": "auth_failure", "severity": "medium",
                    "endpoint": random.choice(self.endpoints), "source_ip": random.choice(self.suspicious_ips),
                    "reason": random.choice(["invalid_api_key", "expired_token", "missing_credentials", "invalid_signature", "revoked_key"]),
                    "timestamp": datetime.utcnow().isoformat(), "attempt_count": random.randint(1, 20)}
        elif event_type == "sql_injection":
            return {**base, "event_type": "sql_injection", "severity": "critical",
                    "endpoint": random.choice(self.endpoints), "source_ip": random.choice(self.suspicious_ips),
                    "injection_pattern": random.choice(["' OR '1'='1", "'; DROP TABLE medications--", "UNION SELECT * FROM users"]),
                    "parameter": random.choice(["patient_id", "search", "id", "filter"]),
                    "blocked": True, "timestamp": datetime.utcnow().isoformat(), "waf_rule": f"SQL_INJECTION_{random.randint(1000, 9999)}"}
        elif event_type == "xss_attempt":
            return {**base, "event_type": "xss_attempt", "severity": "high",
                    "endpoint": random.choice(self.endpoints), "source_ip": random.choice(self.suspicious_ips),
                    "xss_payload": random.choice(["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"]),
                    "blocked": True, "timestamp": datetime.utcnow().isoformat(), "waf_rule": f"XSS_PROTECTION_{random.randint(1000, 9999)}"}
        elif event_type == "command_injection":
            return {**base, "event_type": "command_injection", "severity": "critical",
                    "endpoint": random.choice(self.endpoints), "source_ip": random.choice(self.suspicious_ips),
                    "command_pattern": random.choice(["; cat /etc/passwd", "| whoami", "&& ls -la", "; rm -rf /"]),
                    "blocked": True, "timestamp": datetime.utcnow().isoformat()}
        elif event_type == "api_key_abuse":
            return {**base, "event_type": "api_key_abuse", "severity": "high",
                    "api_key": f"key_{random.randint(1000, 9999)}",
                    "source_ips": random.sample(self.ip_addresses + self.suspicious_ips, k=random.randint(3, 6)),
                    "requests_from_multiple_ips": random.randint(50, 200), "timestamp": datetime.utcnow().isoformat(), "action_taken": "key_suspended"}
        elif event_type == "ddos_attempt":
            return {**base, "event_type": "ddos_attempt", "severity": "critical",
                    "target_endpoint": random.choice(self.endpoints),
                    "requests_per_second": random.randint(1000, 10000), "timestamp": datetime.utcnow().isoformat(),
                    "mitigation_active": True, "attack_vector": random.choice(["http_flood", "slowloris", "syn_flood"])}
        else:  # validation_error, unusual_access_pattern, payload_size_exceeded
            return {**base, "event_type": event_type, "severity": random.choice(["low", "medium"]),
                    "endpoint": random.choice(self.endpoints), "source_ip": random.choice(self.ip_addresses + self.suspicious_ips),
                    "timestamp": datetime.utcnow().isoformat(), "details": f"Simulated {event_type} event"}


# =============================================================================
# HSPS WebUI Security Event Generator
# =============================================================================
class HspsWebUIEventGenerator:
    def __init__(self):
        self.app_type = "webui"
        self.system = "HSPS"
        self.event_types = [
            "xss_detection", "csrf_failure", "bot_detection", "file_upload_attempt",
            "geolocation_mismatch", "session_hijacking", "clickjacking_attempt",
            "form_tampering", "suspicious_navigation"
        ]
        self.xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>",
                             "javascript:alert(document.cookie)", "<iframe src='evil.com'></iframe>"]
        self.suspicious_files = ["malware.exe", "payload.php", "shell.jsp", "backdoor.aspx", "exploit.sh"]
        self.locations = [
            {"city": "New York", "country": "US"}, {"city": "London", "country": "UK"},
            {"city": "Moscow", "country": "RU"}, {"city": "Beijing", "country": "CN"}, {"city": "Lagos", "country": "NG"}
        ]

    def _rand_ip(self):
        return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

    def generate_event(self) -> Dict:
        event_type = random.choice(self.event_types)
        base = {"app_type": self.app_type, "app_system": self.system, "source": f"hsps-webui-pod-{random.randint(0,1)}"}

        if event_type == "xss_detection":
            return {**base, "event_type": "xss_detection", "severity": "high",
                    "payload": random.choice(self.xss_payloads),
                    "input_field": random.choice(["search", "comment", "name", "description"]),
                    "page": random.choice(["/prescriptions", "/medications", "/patients"]),
                    "user_id": f"user_{random.randint(100, 999)}", "ip_address": self._rand_ip(),
                    "blocked": True, "timestamp": datetime.utcnow().isoformat()}
        elif event_type == "csrf_failure":
            return {**base, "event_type": "csrf_failure", "severity": "high",
                    "form_action": random.choice(["/submit-prescription", "/update-medication", "/delete-order"]),
                    "received_token": random.choice(["missing", "invalid", "expired"]),
                    "user_id": f"user_{random.randint(100, 999)}", "ip_address": self._rand_ip(),
                    "referer": random.choice(["http://evil.com", "http://phishing-site.com", "missing"]),
                    "blocked": True, "timestamp": datetime.utcnow().isoformat()}
        elif event_type == "bot_detection":
            return {**base, "event_type": "bot_detection", "severity": "medium",
                    "indicators": random.sample(["rapid_clicking", "no_mouse_movement", "automated_form_filling", "suspicious_user_agent"], k=random.randint(2, 3)),
                    "user_agent": random.choice(["Mozilla/5.0 (compatible; bot/1.0)", "Python-urllib/3.8", "curl/7.68.0"]),
                    "ip_address": self._rand_ip(), "pages_visited": random.randint(50, 500),
                    "timestamp": datetime.utcnow().isoformat(), "action_taken": "captcha_challenge"}
        elif event_type == "file_upload_attempt":
            return {**base, "event_type": "file_upload_attempt", "severity": "critical",
                    "filename": random.choice(self.suspicious_files),
                    "file_size_bytes": random.randint(1000, 10000000),
                    "user_id": f"user_{random.randint(100, 999)}", "ip_address": self._rand_ip(),
                    "malware_detected": random.choice([True, False]), "status": "blocked", "timestamp": datetime.utcnow().isoformat()}
        elif event_type == "session_hijacking":
            return {**base, "event_type": "session_hijacking", "severity": "critical",
                    "session_id": f"session_{random.randint(1000, 9999)}",
                    "original_ip": self._rand_ip(), "new_ip": self._rand_ip(),
                    "session_token_reuse": True, "timestamp": datetime.utcnow().isoformat(), "action_taken": "session_terminated"}
        elif event_type == "geolocation_mismatch":
            prev = random.choice(self.locations)
            curr = random.choice([l for l in self.locations if l != prev])
            return {**base, "event_type": "geolocation_mismatch", "severity": "medium",
                    "user_id": f"user_{random.randint(100, 999)}",
                    "previous_location": prev, "current_location": curr,
                    "distance_km": random.randint(1000, 15000), "impossible_travel": random.choice([True, False]),
                    "timestamp": datetime.utcnow().isoformat(), "action_taken": "additional_verification_required"}
        else:  # clickjacking_attempt, form_tampering, suspicious_navigation
            return {**base, "event_type": event_type, "severity": random.choice(["medium", "high"]),
                    "user_id": f"user_{random.randint(100, 999)}", "ip_address": self._rand_ip(),
                    "blocked": True, "timestamp": datetime.utcnow().isoformat(),
                    "details": f"Simulated {event_type} event"}


# =============================================================================
# STAR Database Security Event Generator (pharmacy-specific)
# =============================================================================
class StarDatabaseEventGenerator:
    def __init__(self):
        self.app_type = "star-database"
        self.system = "STAR"
        self.event_types = [
            "auth_failure", "privilege_escalation", "prescription_data_access",
            "patient_phi_exfiltration", "controlled_substance_query", "sql_injection",
            "dea_number_access", "failed_login", "unusual_query_pattern",
            "inventory_tampering", "after_hours_access", "brute_force_attack"
        ]
        self.usernames = ["pharmacist_jdoe", "tech_msmith", "pharmacy_manager", "inventory_clerk",
                          "billing_service", "reporting_user", "pos_terminal_1", "rx_processing"]
        self.suspicious_usernames = ["root", "sa", "postgres", "' OR '1'='1", "admin'--", "test"]
        self.ip_addresses = ["10.0.1.100", "10.0.1.101", "10.0.1.102", "192.168.1.50", "172.16.0.10"]
        self.suspicious_ips = ["185.220.101.1", "45.142.212.61", "198.51.100.42", "203.0.113.5", "192.0.2.100"]
        self.medications = ["Oxycodone", "Hydrocodone", "Adderall", "Xanax", "Morphine", "Fentanyl"]

    def generate_event(self) -> Dict:
        event_type = random.choice(self.event_types)
        base = {"app_type": self.app_type, "app_system": self.system, "source": f"star-database-pod-{random.randint(0,1)}"}

        if event_type == "prescription_data_access":
            return {**base, "event_type": "prescription_data_access", "severity": "high",
                    "username": random.choice(self.usernames), "source_ip": random.choice(self.ip_addresses),
                    "prescription_id": f"RX{random.randint(100000, 999999)}", "patient_id": f"PT{random.randint(10000, 99999)}",
                    "medication": random.choice(self.medications),
                    "access_reason": random.choice(["lookup", "modification", "deletion", "export"]),
                    "timestamp": datetime.utcnow().isoformat(), "authorized": random.choice([True, False]), "controlled_substance": True}
        elif event_type == "patient_phi_exfiltration":
            return {**base, "event_type": "patient_phi_exfiltration", "severity": "critical",
                    "username": random.choice(self.usernames), "source_ip": random.choice(self.ip_addresses),
                    "destination_ip": random.choice(self.suspicious_ips),
                    "patient_records_accessed": random.randint(100, 10000),
                    "data_types": random.sample(["ssn", "dob", "address", "insurance", "medical_history", "prescriptions"], k=random.randint(2, 4)),
                    "bytes_transferred": random.randint(1000000, 100000000),
                    "timestamp": datetime.utcnow().isoformat(), "hipaa_violation": True, "blocked": random.choice([True, False])}
        elif event_type == "controlled_substance_query":
            return {**base, "event_type": "controlled_substance_query", "severity": "medium",
                    "username": random.choice(self.usernames), "source_ip": random.choice(self.ip_addresses),
                    "drug_schedule": random.choice(["Schedule II", "Schedule III", "Schedule IV"]),
                    "query_type": random.choice(["inventory_check", "dispense_history", "bulk_export", "audit_report"]),
                    "records_returned": random.randint(10, 5000), "timestamp": datetime.utcnow().isoformat(),
                    "requires_dea_authorization": True, "flagged": random.random() < 0.3}
        elif event_type == "dea_number_access":
            return {**base, "event_type": "dea_number_access", "severity": "high",
                    "username": random.choice(self.usernames), "source_ip": random.choice(self.ip_addresses),
                    "dea_number": f"A{random.choice(['B', 'F', 'M'])}{random.randint(1000000, 9999999)}",
                    "access_type": random.choice(["view", "modify", "export", "verify"]),
                    "timestamp": datetime.utcnow().isoformat(), "authorized": random.choice([True, False]), "audit_required": True}
        elif event_type == "inventory_tampering":
            return {**base, "event_type": "inventory_tampering", "severity": "critical",
                    "username": random.choice(self.usernames), "source_ip": random.choice(self.ip_addresses),
                    "medication": random.choice(["Oxycodone 30mg", "Hydrocodone 10mg", "Adderall XR 20mg", "Alprazolam 2mg"]),
                    "action": random.choice(["quantity_adjustment", "deletion", "manual_override", "backdated_entry"]),
                    "quantity_change": random.randint(-500, -10), "timestamp": datetime.utcnow().isoformat(),
                    "requires_investigation": True, "discrepancy_detected": True}
        elif event_type == "after_hours_access":
            return {**base, "event_type": "after_hours_access", "severity": "medium",
                    "username": random.choice(self.usernames), "source_ip": random.choice(self.ip_addresses),
                    "access_time": "02:47 AM", "day_of_week": random.choice(["Saturday", "Sunday", "Monday"]),
                    "tables_accessed": random.sample(["prescriptions", "controlled_substances", "patient_records", "dea_logs"], k=random.randint(1, 3)),
                    "timestamp": datetime.utcnow().isoformat(), "flagged_for_review": True}
        elif event_type == "auth_failure":
            return {**base, "event_type": "auth_failure", "severity": "medium",
                    "username": random.choice(self.usernames + self.suspicious_usernames),
                    "source_ip": random.choice(self.ip_addresses + self.suspicious_ips),
                    "reason": random.choice(["invalid_credentials", "expired_password", "account_locked"]),
                    "timestamp": datetime.utcnow().isoformat(), "database": "star_pharmacy"}
        elif event_type == "sql_injection":
            return {**base, "event_type": "sql_injection", "severity": "high",
                    "source_ip": random.choice(self.suspicious_ips),
                    "injection_pattern": random.choice(["' OR '1'='1", "'; DROP TABLE prescriptions--", "UNION SELECT * FROM patient_records"]),
                    "blocked": True, "timestamp": datetime.utcnow().isoformat()}
        elif event_type == "brute_force_attack":
            return {**base, "event_type": "brute_force_attack", "severity": "high",
                    "source_ip": random.choice(self.suspicious_ips), "target_username": random.choice(self.usernames),
                    "attempts": random.randint(50, 500), "timestamp": datetime.utcnow().isoformat(),
                    "blocked": random.choice([True, False]),
                    "attack_pattern": random.choice(["dictionary_attack", "credential_stuffing", "password_spraying"])}
        else:  # privilege_escalation, failed_login, unusual_query_pattern
            return {**base, "event_type": event_type, "severity": random.choice(["low", "medium", "high"]),
                    "username": random.choice(self.usernames), "source_ip": random.choice(self.ip_addresses),
                    "timestamp": datetime.utcnow().isoformat(), "details": f"Simulated {event_type} event"}


# =============================================================================
# STAR API Security Event Generator (pharmacy-specific)
# =============================================================================
class StarApiEventGenerator:
    def __init__(self):
        self.app_type = "star-api"
        self.system = "STAR"
        self.event_types = [
            "rate_limit_exceeded", "auth_failure", "sql_injection", "xss_attempt",
            "command_injection", "api_key_abuse", "ddos_attempt",
            "prescription_fraud_attempt", "dea_verification_failure",
            "controlled_substance_override", "insurance_claim_manipulation"
        ]
        self.endpoints = ["/api/v1/prescriptions", "/api/v1/prescriptions/fill", "/api/v1/prescriptions/refill",
                          "/api/v1/controlled-substances", "/api/v1/inventory", "/api/v1/patients",
                          "/api/v1/insurance/verify", "/api/v1/insurance/claims", "/api/v1/dea/verify",
                          "/api/v1/pharmacists", "/api/v1/pos/transaction"]
        self.suspicious_ips = ["185.220.101.1", "45.142.212.61", "198.51.100.42", "203.0.113.5", "192.0.2.100", "91.213.8.235"]
        self.ip_addresses = ["10.0.1.100", "10.0.1.101", "10.0.1.102", "192.168.1.50", "172.16.0.10"]

    def generate_event(self) -> Dict:
        event_type = random.choice(self.event_types)
        base = {"app_type": self.app_type, "app_system": self.system, "source": f"star-api-pod-{random.randint(0,2)}"}

        if event_type == "prescription_fraud_attempt":
            return {**base, "event_type": "prescription_fraud_attempt", "severity": "critical",
                    "endpoint": "/api/v1/prescriptions/fill", "source_ip": random.choice(self.suspicious_ips),
                    "prescription_id": f"RX{random.randint(100000, 999999)}", "patient_id": f"PT{random.randint(10000, 99999)}",
                    "medication": random.choice(["Oxycodone 30mg", "Hydrocodone 10mg", "Adderall XR 30mg"]),
                    "fraud_indicators": random.sample(["forged_signature", "altered_quantity", "invalid_dea_number",
                                                        "duplicate_prescription", "out_of_state_prescriber", "excessive_early_refill"], k=random.randint(2, 4)),
                    "timestamp": datetime.utcnow().isoformat(), "blocked": True, "reported_to_authorities": random.choice([True, False])}
        elif event_type == "dea_verification_failure":
            return {**base, "event_type": "dea_verification_failure", "severity": "high",
                    "endpoint": "/api/v1/dea/verify", "source_ip": random.choice(self.ip_addresses),
                    "dea_number": f"A{random.choice(['B', 'F', 'M'])}{random.randint(1000000, 9999999)}",
                    "prescriber_name": random.choice(["Dr. Smith", "Dr. Johnson", "Dr. Williams"]),
                    "failure_reason": random.choice(["dea_number_expired", "dea_number_invalid", "dea_number_suspended", "prescriber_not_authorized"]),
                    "controlled_substance": random.choice(["Schedule II", "Schedule III", "Schedule IV"]),
                    "timestamp": datetime.utcnow().isoformat(), "prescription_rejected": True}
        elif event_type == "controlled_substance_override":
            return {**base, "event_type": "controlled_substance_override", "severity": "critical",
                    "endpoint": "/api/v1/prescriptions/fill", "source_ip": random.choice(self.ip_addresses),
                    "user": random.choice(["pharmacist_jdoe", "tech_msmith", "pharmacy_manager"]),
                    "medication": random.choice(["Oxycodone 30mg", "Morphine Sulfate 15mg", "Fentanyl Patch 50mcg"]),
                    "override_type": random.choice(["quantity_limit_override", "early_refill_override", "prior_authorization_bypass"]),
                    "original_quantity": random.randint(30, 90), "overridden_quantity": random.randint(120, 240),
                    "timestamp": datetime.utcnow().isoformat(), "flagged_for_audit": True}
        elif event_type == "insurance_claim_manipulation":
            return {**base, "event_type": "insurance_claim_manipulation", "severity": "high",
                    "endpoint": "/api/v1/insurance/claims", "source_ip": random.choice(self.ip_addresses),
                    "claim_id": f"CLM{random.randint(1000000, 9999999)}", "patient_id": f"PT{random.randint(10000, 99999)}",
                    "manipulation_type": random.choice(["billing_code_upcoding", "quantity_inflation", "duplicate_claim_submission"]),
                    "original_amount": round(random.uniform(50, 500), 2), "modified_amount": round(random.uniform(500, 2000), 2),
                    "insurance_provider": random.choice(["BlueCross", "Aetna", "UnitedHealthcare", "Cigna"]),
                    "timestamp": datetime.utcnow().isoformat(), "claim_rejected": True}
        elif event_type == "ddos_attempt":
            return {**base, "event_type": "ddos_attempt", "severity": "critical",
                    "target_endpoint": random.choice(self.endpoints),
                    "requests_per_second": random.randint(1000, 10000), "timestamp": datetime.utcnow().isoformat(),
                    "attack_type": random.choice(["syn_flood", "http_flood", "slowloris"]), "mitigation_active": True}
        else:  # rate_limit_exceeded, auth_failure, sql_injection, xss_attempt, command_injection, api_key_abuse
            severity_map = {"rate_limit_exceeded": "medium", "auth_failure": "medium", "sql_injection": "critical",
                            "xss_attempt": "high", "command_injection": "critical", "api_key_abuse": "high"}
            return {**base, "event_type": event_type, "severity": severity_map.get(event_type, "medium"),
                    "endpoint": random.choice(self.endpoints), "source_ip": random.choice(self.suspicious_ips),
                    "blocked": True, "timestamp": datetime.utcnow().isoformat()}


# =============================================================================
# STAR WebUI Security Event Generator
# =============================================================================
class StarWebUIEventGenerator:
    def __init__(self):
        self.app_type = "star-webui"
        self.system = "STAR"
        self.event_types = [
            "xss_detection", "csrf_failure", "bot_detection", "file_upload_attempt",
            "geolocation_mismatch", "session_hijacking", "clickjacking_attempt",
            "form_tampering", "suspicious_navigation"
        ]
        self.xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>",
                             "javascript:alert(document.cookie)", "<svg onload=alert(1)>"]
        self.suspicious_files = ["malware.exe", "payload.php", "shell.jsp", "backdoor.aspx"]
        self.locations = [
            {"city": "New York", "country": "US"}, {"city": "London", "country": "UK"},
            {"city": "Moscow", "country": "RU"}, {"city": "Beijing", "country": "CN"}, {"city": "Lagos", "country": "NG"}
        ]

    def _rand_ip(self):
        return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

    def generate_event(self) -> Dict:
        event_type = random.choice(self.event_types)
        base = {"app_type": self.app_type, "app_system": self.system, "source": f"star-webui-pod-{random.randint(0,1)}"}

        if event_type == "xss_detection":
            return {**base, "event_type": "xss_detection", "severity": "high",
                    "payload": random.choice(self.xss_payloads),
                    "input_field": random.choice(["search", "comment", "name", "prescription_notes"]),
                    "page": random.choice(["/prescriptions", "/controlled-substances", "/patients", "/pos"]),
                    "user_id": f"user_{random.randint(100, 999)}", "ip_address": self._rand_ip(),
                    "blocked": True, "timestamp": datetime.utcnow().isoformat()}
        elif event_type == "session_hijacking":
            return {**base, "event_type": "session_hijacking", "severity": "critical",
                    "session_id": f"session_{random.randint(1000, 9999)}",
                    "original_ip": self._rand_ip(), "new_ip": self._rand_ip(),
                    "session_token_reuse": True, "timestamp": datetime.utcnow().isoformat(), "action_taken": "session_terminated"}
        elif event_type == "file_upload_attempt":
            return {**base, "event_type": "file_upload_attempt", "severity": "critical",
                    "filename": random.choice(self.suspicious_files), "file_size_bytes": random.randint(1000, 10000000),
                    "user_id": f"user_{random.randint(100, 999)}", "ip_address": self._rand_ip(),
                    "malware_detected": random.choice([True, False]), "status": "blocked", "timestamp": datetime.utcnow().isoformat()}
        elif event_type == "geolocation_mismatch":
            prev = random.choice(self.locations)
            curr = random.choice([l for l in self.locations if l != prev])
            return {**base, "event_type": "geolocation_mismatch", "severity": "medium",
                    "user_id": f"user_{random.randint(100, 999)}",
                    "previous_location": prev, "current_location": curr,
                    "distance_km": random.randint(1000, 15000), "impossible_travel": random.choice([True, False]),
                    "timestamp": datetime.utcnow().isoformat()}
        else:  # csrf_failure, bot_detection, clickjacking_attempt, form_tampering, suspicious_navigation
            return {**base, "event_type": event_type, "severity": random.choice(["medium", "high"]),
                    "user_id": f"user_{random.randint(100, 999)}", "ip_address": self._rand_ip(),
                    "blocked": True, "timestamp": datetime.utcnow().isoformat(),
                    "details": f"Simulated {event_type} event"}


# =============================================================================
# Simulator Engine - manages all generators and event storage
# =============================================================================
class SimulatorEngine:
    """Runs all 6 event generators and stores events in memory, mimicking the Security Portal."""

    def __init__(self):
        self.generators = [
            HspsDatabaseEventGenerator(),
            HspsApiEventGenerator(),
            HspsWebUIEventGenerator(),
            StarDatabaseEventGenerator(),
            StarApiEventGenerator(),
            StarWebUIEventGenerator(),
        ]
        self.events: List[Dict] = []
        self.max_events = 10000
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.started_at = datetime.utcnow()

    def start(self, interval_seconds: float = 0.5):
        """Start background event generation."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._generate_loop, args=(interval_seconds,), daemon=True)
        self._thread.start()

    def stop(self):
        """Stop background event generation."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _generate_loop(self, interval: float):
        """Background loop that generates events from random generators."""
        while self._running:
            # Each tick, 1-3 generators fire an event
            count = random.randint(1, 3)
            generators = random.sample(self.generators, k=min(count, len(self.generators)))
            for gen in generators:
                event = gen.generate_event()
                event["id"] = f"evt-{len(self.events) + 1}-{random.randint(1000, 9999)}"
                event["received_at"] = datetime.utcnow().isoformat()
                with self._lock:
                    self.events.append(event)
                    if len(self.events) > self.max_events:
                        self.events = self.events[-self.max_events:]
            time.sleep(interval)

    def get_events(self, limit: int = 100, severity: str = None, event_type: str = None) -> Dict:
        """Get events, matching the Security Portal /api/events response format."""
        with self._lock:
            filtered = list(self.events)

        if severity:
            filtered = [e for e in filtered if e.get("severity") == severity]
        if event_type:
            filtered = [e for e in filtered if e.get("event_type") == event_type]

        return {
            "events": filtered[-limit:],
            "count": len(filtered),
            "total": len(self.events),
            "timestamp": datetime.utcnow().isoformat()
        }

    def get_stats(self) -> Dict:
        """Get stats, matching the Security Portal /api/stats response format."""
        with self._lock:
            events_copy = list(self.events)

        by_type = defaultdict(int)
        by_severity = defaultdict(int)
        by_app = defaultdict(int)

        for event in events_copy:
            by_type[event.get("event_type", "unknown")] += 1
            by_severity[event.get("severity", "unknown")] += 1
            by_app[event.get("app_type", "unknown")] += 1

        return {
            "total_events": len(events_copy),
            "critical_events": by_severity.get("critical", 0),
            "events_by_type": dict(by_type),
            "events_by_severity": dict(by_severity),
            "events_by_application": dict(by_app),
            "timestamp": datetime.utcnow().isoformat()
        }

    def get_applications(self) -> Dict:
        """Get simulated application status, matching the /api/kubernetes/applications response."""
        apps = [
            {"id": "hsps-database-simulator", "name": "hsps-database-simulator", "namespace": "hsps", "system": "HSPS",
             "status": "running", "podCount": 2, "replicas": 2, "readyReplicas": 2},
            {"id": "hsps-api-simulator", "name": "hsps-api-simulator", "namespace": "hsps", "system": "HSPS",
             "status": "running", "podCount": 3, "replicas": 3, "readyReplicas": 3},
            {"id": "hsps-webui-simulator", "name": "hsps-webui-simulator", "namespace": "hsps", "system": "HSPS",
             "status": "running", "podCount": 2, "replicas": 2, "readyReplicas": 2},
            {"id": "security-portal", "name": "security-portal", "namespace": "hsps", "system": "HSPS",
             "status": "running", "podCount": 1, "replicas": 1, "readyReplicas": 1},
            {"id": "star-database-simulator", "name": "star-database-simulator", "namespace": "star", "system": "STAR",
             "status": "running", "podCount": 2, "replicas": 2, "readyReplicas": 2},
            {"id": "star-api-simulator", "name": "star-api-simulator", "namespace": "star", "system": "STAR",
             "status": "running", "podCount": 3, "replicas": 3, "readyReplicas": 3},
            {"id": "star-webui-simulator", "name": "star-webui-simulator", "namespace": "star", "system": "STAR",
             "status": "running", "podCount": 2, "replicas": 2, "readyReplicas": 2},
            {"id": "star-security-portal", "name": "star-security-portal", "namespace": "star", "system": "STAR",
             "status": "running", "podCount": 1, "replicas": 1, "readyReplicas": 1},
        ]
        return {"applications": apps, "count": len(apps)}
