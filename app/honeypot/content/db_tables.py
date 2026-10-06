# SYNTHETIC DATA – Honeypot Nexus
# Fake database tables for safe in-memory viewer (never executed as SQL).

FAKE_TABLES = {
    "users": [
        {"id": 1, "username": "admin", "email": "admin@securecorp.example", "role": "SuperAdmin", "status": "active"},
        {"id": 2, "username": "jsmith", "email": "jsmith@securecorp.example", "role": "SecOps", "status": "active"},
        {"id": 3, "username": "developer", "email": "dev@securecorp.example", "role": "Engineer", "status": "active"},
        {"id": 4, "username": "backup_svc", "email": "svc@securecorp.example", "role": "ServiceAccount", "status": "active"},
        {"id": 5, "username": "billing_user", "email": "billing@securecorp.example", "role": "Finance", "status": "suspended"}
    ],
    "employees": [
        {"id": 101, "name": "Alice Miller", "dept": "Core Engineering", "phone": "555-0142", "office": "Bldg 3"},
        {"id": 102, "name": "Bob Vance", "dept": "Logistics & Fleet", "phone": "555-0188", "office": "Bldg 1"},
        {"id": 103, "name": "Charlie Davis", "dept": "Identity Management", "phone": "555-0199", "office": "Bldg 4"},
        {"id": 104, "name": "Diana Ross", "dept": "Human Capital", "phone": "555-0123", "office": "Bldg 2"}
    ],
    "transactions": [
        {"tx_id": "TX-9901", "amount": "$45,000.00", "vendor": "Cloud Infra Inc", "status": "Approved", "date": "2024-03-01"},
        {"tx_id": "TX-9902", "amount": "$12,400.00", "vendor": "Hardware Solutions", "status": "Approved", "date": "2024-03-02"},
        {"tx_id": "TX-9903", "amount": "$3,200.00", "vendor": "SaaS Subscription", "status": "Pending", "date": "2024-03-04"}
    ],
    "api_keys": [
        {"key_id": "AK-01", "name": "Stripe Gateway", "preview": "HNX-FAKE-sk_live_...9a1b", "created": "2023-11-01"},
        {"key_id": "AK-02", "name": "AWS Production", "preview": "HNX-FAKE-AKIA...5e2c", "created": "2023-12-15"},
        {"key_id": "AK-03", "name": "SendGrid Mailer", "preview": "HNX-FAKE-SG...7f3a", "created": "2024-01-10"}
    ],
    "system_logs": [
        {"time": "2024-03-05 08:12:00", "facility": "AUTH", "level": "INFO", "message": "Admin session established from intranet"},
        {"time": "2024-03-05 08:30:14", "facility": "BACKUP", "level": "INFO", "message": "Hourly database snapshot completed successfully"},
        {"time": "2024-03-05 09:01:22", "facility": "CRON", "level": "INFO", "message": "Certificate check completed: valid for 180 days"}
    ]
}
