# SYNTHETIC DATA – Honeypot Nexus
# Synthetic API fixtures and lures.

API_USERS = [
    {"id": 1, "username": "admin", "email": "admin@securecorp.example", "role": "admin", "last_login": "2024-03-05T08:12:00Z"},
    {"id": 2, "username": "jsmith", "email": "jsmith@securecorp.example", "role": "analyst", "last_login": "2024-03-05T07:45:00Z"},
    {"id": 3, "username": "developer", "email": "dev@securecorp.example", "role": "dev", "last_login": "2024-03-04T19:30:00Z"},
    {"id": 4, "username": "backup_svc", "email": "svc@securecorp.example", "role": "service", "last_login": "2024-03-05T06:00:00Z"},
    {"id": 5, "username": "alice", "email": "alice@securecorp.example", "role": "user", "last_login": "2024-03-05T08:00:00Z"},
    {"id": 6, "username": "bob", "email": "bob@securecorp.example", "role": "user", "last_login": "2024-03-04T16:20:00Z"}
]

API_CONFIG = {
    "app_name": "SecureCorp Core Portal",
    "version": "2.4.1-staging",
    "environment": "internal",
    "db_host": "db-internal.securecorp.example",
    "db_password": "HNX-FAKE-P@ssw0rd!DB2024",
    "jwt_issuer": "https://auth.securecorp.example",
    "s3_bucket": "securecorp-prod-backups-internal"
}

API_BACKUP_LIST = [
    {"file": "database_backup_20240301.sql.gz", "size": "42.1MB", "url": "/files/download?path=/backups/database_backup.sql"},
    {"file": "database_backup_20240302.sql.gz", "size": "42.8MB", "url": "/files/download?path=/backups/database_backup.sql"},
    {"file": "database_backup_20240303.sql.gz", "size": "43.0MB", "url": "/files/download?path=/backups/database_backup.sql"}
]

API_TOKENS = [
    {"token_id": "tok_01", "name": "CI/CD Pipeline Service", "secret": "HNX-FAKE-tok_live_89123847a9b8"},
    {"token_id": "tok_02", "name": "Payment Gateway Hook", "secret": "HNX-FAKE-tok_sec_109283019284"},
    {"token_id": "tok_03", "name": "Kubernetes Cluster Ingress", "secret": "HNX-FAKE-tok_k8s_781290384712"}
]
