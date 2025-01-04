# Text_Clustering
To run the code run the following command:
```bash
python main.py
```
The output format is like:
[  
  {  
    "title": "SSTI vulnerability in EOL Apache",  
    "endpoint": "/apache",  
    "tag": "group_0",  
    "description": "An end-of-life Apache version is prone to server-side template injection attacks.",  
    "cve": "null",  
    "severity": "medium",  
    "sensor": "ToolC"  
  },  
  {  
    "title": "Obsolete Apache vulnerable to template injection",  
    "endpoint": "/apache",  
    "tag": "group_0",  
    "description": "Obsolete version 2.2.x can be exploited via SSTI, leading to arbitrary code execution.",  
    "cve": "CVE-2025-1234",  
    "severity": "high",  
    "sensor": "ToolD"  
  },  
  {  
    "title": "Server-Side Template Injection in old Apache",  
    "endpoint": "/apache",  
    "tag": "group_0",  
    "description": "Apache 2.2.x is vulnerable to server-side template injection, potentially leading to RCE.",  
    "cve": "CVE-2025-1234",  
    "severity": "high",  
    "sensor": "ToolA"  
  },  
  {  
    "title": "Apache 2.2.9 with SSTI flaw",  
    "endpoint": "/apache",  
    "tag": "group_0",  
    "description": "Outdated Apache release allows server-side template injection if template engine is misconfigured.",  
    "cve": "null",  
    "severity": "critical",  
    "sensor": "ToolB"  
  },  
  {  
    "title": "Weak encryption in api encrypt",  
    "endpoint": "/api/encrypt",  
    "tag": "group_1",  
    "description": "Encryption mechanism in /api/encrypt is weak. allowing potential data exposure.",  
    "cve": "null",  
    "severity": "medium",  
    "sensor": "ToolD"  
  },  
  {  
    "title": "Cache poisoning in /assets",  
    "endpoint": "/assets",  
    "tag": "group_2",  
    "description": "Malicious cache injection is possible in /assets, enabling attackers to serve rogue content.",  
    "cve": "CVE-2028-0002",  
    "severity": "high",  
    "sensor": "ToolC"  
  },  
  {  
    "title": "CSRF vulnerability in cart checkout",  
    "endpoint": "/cart",  
    "tag": "group_3",  
    "description": "Cart checkout page is susceptible to CSRF attacks through unprotected forms.",  
    "cve": "null",  
    "severity": "medium",  
    "sensor": "ToolB"  
  },  
  {  
    "title": "CSRF in cart checkout",  
    "endpoint": "/cart",  
    "tag": "group_3",  
    "description": "A CSRF vulnerability in the cart checkout flow can allow malicious form submissions.",  
    "cve": "null",  
    "severity": "medium",  
    "sensor": "ToolA"  
  },  
  {  
    "title": "Comments injection flaw",  
    "endpoint": "/comments",  
    "tag": "group_4",  
    "description": "The /comments section is vulnerable to injection of arbitrary code via user content.",  
    "cve": "null",  
    "severity": "high",  
    "sensor": "ToolC"  
  },  
  {  
    "title": "Comment injection in comments",  
    "endpoint": "/comments",  
    "tag": "group_4",  
    "description": "Comment injection flaw at /comments endpoint allows attacker-supplied commands.",  
    "cve": "null",  
    "severity": "high",  
    "sensor": "ToolB"  
  },  
  {  
    "title": "Comment injection vulnerability",  
    "endpoint": "/comments",  
    "tag": "group_4",  
    "description": "Malicious users can inject code into comments leading to remote script execution.",  
    "cve": "CVE-2025-0002",  
    "severity": "high",  
    "sensor": "ToolA"  
  },  
  {  
    "title": "Config information disclosure",  
    "endpoint": "/config",  
    "tag": "group_5",  
    "description": "Leaking configuration data at /config can give attackers insights into the system.",  
    "cve": "null",  
    "severity": "medium",  
    "sensor": "ToolC"  
  },  
  {  
    "title": "Public config leads to info disclosure",  
    "endpoint": "/config",  
    "tag": "group_5",  
    "description": "Sensitive data in config is exposed, leading to information disclosure issues.",  
    "cve": "CVE-2022-5555",  
    "severity": "high",  
    "sensor": "ToolB"  
  },  
  {  
    "title": "Misconfigured config endpoint",  
    "endpoint": "/config",  
    "tag": "group_5",  
    "description": "A critical misconfiguration in /config reveals sensitive credentials and secrets.",  
    "cve": "CVE-2022-5555",  
    "severity": "critical",  
    "sensor": "ToolD"  
  },  
  {  
    "title": "Remote Code Execution at /config",  
    "endpoint": "/config",  
    "tag": "group_6",  
    "description": "Attackers can achieve code execution on the server via /config if not patched.",  
    "cve": "null",  
    "severity": "high",  
    "sensor": "ToolD"  
  },  
  {  
    "title": "RCE vulnerability in /config",  
    "endpoint": "/config",  
    "tag": "group_7",  
    "description": "A flaw in /config triggers remote code execution with crafted payloads.",  
    "cve": "CVE-2027-1002",  
    "severity": "high",  
    "sensor": "ToolC"  
  },  
  {  
    "title": "Directory Traversal in files",  
    "endpoint": "/files",  
    "tag": "group_8",  
    "description": "Attackers can manipulate file paths to access unauthorized directories in /files endpoint.",  
    "cve": "CVE-2024-0001",  
    "severity": "high",  
    "sensor": "ToolC"  
  },  
  .  
  .  
  .  
