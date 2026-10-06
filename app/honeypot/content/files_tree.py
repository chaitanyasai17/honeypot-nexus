# SYNTHETIC DATA – Honeypot Nexus
# Virtual in-memory filesystem tree. Never touches real OS filesystem.

VIRTUAL_FILES = {
    "/documents/acceptable_use_policy.pdf": {
        "name": "acceptable_use_policy.pdf",
        "size": 42100,
        "modified": "2024-01-15",
        "owner": "compliance",
        "sensitive": False,
        "content": "[SecureCorp PDF Stream] Fictional Policy Document"
    },
    "/documents/employee_handbook.txt": {
        "name": "employee_handbook.txt",
        "size": 1284,
        "modified": "2024-02-10",
        "owner": "hr",
        "sensitive": False,
        "content": "SecureCorp Employee Handbook v3.1\nWelcome to SecureCorp. All employees must follow data safety."
    },
    "/backups/database_backup.sql": {
        "name": "database_backup.sql",
        "size": 892040,
        "modified": "2024-03-01",
        "owner": "dbadmin",
        "sensitive": True,
        "content": "-- SecureCorp Database Dump\n-- Host: sc-db-prod\nCREATE TABLE app_users (id INT, username VARCHAR(64), hash VARCHAR(128));\nINSERT INTO app_users VALUES (1, 'admin', 'HNX-FAKE-5H7K8P9Q');"
    },
    "/security/api_keys_backup.txt": {
        "name": "api_keys_backup.txt",
        "size": 482,
        "modified": "2024-02-28",
        "owner": "security",
        "sensitive": True,
        "content": "# PRODUCTION API KEYS (CONFIDENTIAL)\nSTRIPE_SECRET=HNX-FAKE-STRIPE-KEY-99812\nAWS_KEY_ID=HNX-FAKE-AKIA-00998877\nAWS_SECRET=HNX-FAKE-wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    },
    "/hr/employee_records.csv": {
        "name": "employee_records.csv",
        "size": 3120,
        "modified": "2024-01-20",
        "owner": "hr",
        "sensitive": True,
        "content": "id,name,email,department,salary\n1,Alice Miller,alice.m@securecorp.example,Engineering,125000\n2,Bob Vance,bob.v@securecorp.example,Operations,98000"
    },
    "/config/network_config.conf": {
        "name": "network_config.conf",
        "size": 1150,
        "modified": "2024-03-04",
        "owner": "netops",
        "sensitive": True,
        "content": "[gateway]\nhost = 192.168.10.1\nvlan = 100\ninternal_domain = corp.internal\ndns = 192.168.10.2, 1.1.1.1"
    },
    "/config/admin_notes.txt": {
        "name": "admin_notes.txt",
        "size": 320,
        "modified": "2024-02-14",
        "owner": "admin",
        "sensitive": True,
        "content": "TODO: Rotate production database credentials before audit.\nTemporary dev password for staging: DevTemp2024!"
    },
    "/etc/passwd": {
        "name": "passwd",
        "size": 750,
        "modified": "2024-01-01",
        "owner": "root",
        "sensitive": True,
        "content": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nadmin:x:1000:1000:Administrator:/home/admin:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin"
    },
    "/etc/shadow": {
        "name": "shadow",
        "size": 420,
        "modified": "2024-01-01",
        "owner": "root",
        "sensitive": True,
        "content": "root:$6$rounds=5000$HNXFAKESALT$fakehashrootfakehashrootfakehash:19800:0:99999:7:::\nadmin:$6$rounds=5000$HNXFAKESALT$fakehashadminfakehashadmin:19800:0:99999:7:::"
    }
}
