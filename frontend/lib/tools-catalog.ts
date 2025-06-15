/**
 * UniVex Tool Catalog — 145+ agent tools across 8 security categories.
 * This file is the single source of truth for the Tools Dashboard.
 */

export type ToolCategory =
  | 'Recon'
  | 'Web'
  | 'Exploitation'
  | 'Post-Exploitation'
  | 'Active Directory'
  | 'Cloud'
  | 'Proxy'
  | 'Network';

export interface ToolParameter {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'select';
  required: boolean;
  description: string;
  default?: string | number | boolean;
  options?: string[];
  placeholder?: string;
}

export interface ToolDefinition {
  id: string;
  name: string;
  category: ToolCategory;
  description: string;
  parameters: ToolParameter[];
  tags: string[];
  mcp_tool?: string;
}

export const TOOL_CATALOG: ToolDefinition[] = [
  // ─── Recon ───────────────────────────────────────────────────────────────
  {
    id: 'subdomain_takeover',
    name: 'Subdomain Takeover',
    category: 'Recon',
    description: 'Detect subdomain takeover vulnerabilities via CNAME fingerprinting.',
    tags: ['dns', 'subdomain', 'takeover'],
    parameters: [
      { name: 'domain', type: 'string', required: true, description: 'Target domain', placeholder: 'example.com' },
      { name: 'wordlist', type: 'string', required: false, description: 'Custom wordlist path' },
    ],
  },
  {
    id: 'dangling_cname',
    name: 'Dangling CNAME Detect',
    category: 'Recon',
    description: 'Find dangling CNAME records pointing to unclaimed cloud services.',
    tags: ['dns', 'cname', 'cloud'],
    parameters: [
      { name: 'domain', type: 'string', required: true, description: 'Target domain', placeholder: 'example.com' },
    ],
  },
  {
    id: 'dns_zone_transfer',
    name: 'DNS Zone Transfer',
    category: 'Recon',
    description: 'Attempt DNS zone transfer (AXFR) against domain name servers.',
    tags: ['dns', 'zone-transfer', 'axfr'],
    parameters: [
      { name: 'domain', type: 'string', required: true, description: 'Target domain', placeholder: 'example.com' },
      { name: 'nameserver', type: 'string', required: false, description: 'Specific nameserver IP' },
    ],
  },
  {
    id: 'dns_cache_snoop',
    name: 'DNS Cache Snooping',
    category: 'Recon',
    description: 'Snoop DNS resolver cache for previously visited domains.',
    tags: ['dns', 'cache', 'osint'],
    parameters: [
      { name: 'resolver', type: 'string', required: true, description: 'DNS resolver IP', placeholder: '8.8.8.8' },
      { name: 'domains', type: 'string', required: true, description: 'Comma-separated domain list' },
    ],
  },
  {
    id: 'js_endpoint_extract',
    name: 'JS Endpoint Extractor',
    category: 'Recon',
    description: 'Extract API endpoints and sensitive paths from JavaScript files.',
    tags: ['js', 'recon', 'endpoints'],
    parameters: [
      { name: 'url', type: 'string', required: true, description: 'Target URL', placeholder: 'https://example.com' },
      { name: 'depth', type: 'number', required: false, description: 'Crawl depth', default: 2 },
    ],
  },
  {
    id: 'js_secret_finder',
    name: 'JS Secret Finder',
    category: 'Recon',
    description: 'Hunt for hardcoded API keys, tokens, and secrets in JavaScript.',
    tags: ['js', 'secrets', 'recon'],
    parameters: [
      { name: 'url', type: 'string', required: true, description: 'Target URL or JS file URL', placeholder: 'https://example.com' },
    ],
  },
  {
    id: 'js_lib_vuln',
    name: 'JS Library Vulnerability Scanner',
    category: 'Recon',
    description: 'Detect vulnerable JavaScript libraries (jQuery, lodash, etc.) via version fingerprinting.',
    tags: ['js', 'libraries', 'cve'],
    parameters: [
      { name: 'url', type: 'string', required: true, description: 'Target URL', placeholder: 'https://example.com' },
    ],
  },
  {
    id: 'source_map_analyze',
    name: 'Source Map Analyzer',
    category: 'Recon',
    description: 'Download and reconstruct source from .js.map files.',
    tags: ['js', 'sourcemap', 'recon'],
    parameters: [
      { name: 'url', type: 'string', required: true, description: 'Base URL or .js.map URL', placeholder: 'https://example.com/app.js.map' },
    ],
  },
  {
    id: 'dom_sink_analyzer',
    name: 'DOM Sink Analyzer',
    category: 'Recon',
    description: 'Identify DOM-based XSS sinks in JavaScript code.',
    tags: ['js', 'dom', 'xss'],
    parameters: [
      { name: 'url', type: 'string', required: true, description: 'Target URL', placeholder: 'https://example.com' },
    ],
  },
  {
    id: 'wayback_urls',
    name: 'Wayback URLs',
    category: 'Recon',
    description: 'Fetch historical URLs from Wayback Machine / Common Crawl.',
    tags: ['osint', 'wayback', 'urls'],
    parameters: [
      { name: 'domain', type: 'string', required: true, description: 'Target domain', placeholder: 'example.com' },
      { name: 'from_year', type: 'number', required: false, description: 'Start year', placeholder: '2020' },
    ],
  },
  {
    id: 'gau',
    name: 'GAU (Get All URLs)',
    category: 'Recon',
    description: 'Fetch known URLs from multiple passive sources (AlienVault, Wayback, URLScan).',
    tags: ['osint', 'urls', 'passive'],
    parameters: [
      { name: 'domain', type: 'string', required: true, description: 'Target domain', placeholder: 'example.com' },
      { name: 'providers', type: 'string', required: false, description: 'Providers (wayback,alienvault,urlscan)', default: 'wayback,alienvault' },
    ],
  },
  {
    id: 'paramspider',
    name: 'ParamSpider',
    category: 'Recon',
    description: 'Mine URLs with parameters for injection testing.',
    tags: ['parameters', 'urls', 'recon'],
    parameters: [
      { name: 'domain', type: 'string', required: true, description: 'Target domain', placeholder: 'example.com' },
      { name: 'level', type: 'select', required: false, description: 'Crawl aggressiveness', options: ['low', 'medium', 'high'], default: 'medium' },
    ],
  },
  {
    id: 'katana_crawler',
    name: 'Katana Crawler',
    category: 'Recon',
    description: 'Next-generation web crawler with JavaScript rendering.',
    tags: ['crawler', 'js', 'recon'],
    parameters: [
      { name: 'url', type: 'string', required: true, description: 'Target URL', placeholder: 'https://example.com' },
      { name: 'depth', type: 'number', required: false, description: 'Crawl depth', default: 3 },
      { name: 'js_crawl', type: 'boolean', required: false, description: 'Enable JS crawling', default: true },
    ],
  },
  {
    id: 'web_archive_search',
    name: 'Web Archive Search',
    category: 'Recon',
    description: 'Search web archive for cached versions and deleted content.',
    tags: ['osint', 'archive', 'recon'],
    parameters: [
      { name: 'url', type: 'string', required: true, description: 'Target URL', placeholder: 'https://example.com' },
    ],
  },
  {
    id: 'shodan_search',
    name: 'Shodan Search',
    category: 'Recon',
    description: 'Search Shodan for internet-exposed hosts, services, and vulnerabilities.',
    tags: ['shodan', 'osint', 'exposure'],
    parameters: [
      { name: 'query', type: 'string', required: true, description: 'Shodan dork query', placeholder: 'org:"example" port:443' },
      { name: 'limit', type: 'number', required: false, description: 'Max results', default: 100 },
    ],
  },
  {
    id: 'shodan_host',
    name: 'Shodan Host Lookup',
    category: 'Recon',
    description: 'Retrieve detailed host information from Shodan by IP.',
    tags: ['shodan', 'osint', 'host'],
    parameters: [
      { name: 'ip', type: 'string', required: true, description: 'Target IP address', placeholder: '1.2.3.4' },
    ],
  },
  {
    id: 'censys_search',
    name: 'Censys Search',
    category: 'Recon',
    description: 'Search Censys for hosts, certificates, and services.',
    tags: ['censys', 'osint', 'certificates'],
    parameters: [
      { name: 'query', type: 'string', required: true, description: 'Censys query', placeholder: 'parsed.names: example.com' },
      { name: 'index', type: 'select', required: false, description: 'Search index', options: ['hosts', 'certificates', 'websites'], default: 'hosts' },
    ],
  },
  {
    id: 'fofa_search',
    name: 'FOFA Search',
    category: 'Recon',
    description: 'Search FOFA for internet assets and exposed services.',
    tags: ['fofa', 'osint', 'china'],
    parameters: [
      { name: 'query', type: 'string', required: true, description: 'FOFA dork', placeholder: 'domain="example.com"' },
    ],
  },
  {
    id: 'passive_dns',
    name: 'Passive DNS Lookup',
    category: 'Recon',
    description: 'Historical DNS resolution data from passive DNS providers.',
    tags: ['dns', 'passive', 'osint'],
    parameters: [
      { name: 'domain', type: 'string', required: true, description: 'Target domain', placeholder: 'example.com' },
    ],
  },

  // ─── Web ─────────────────────────────────────────────────────────────────
  {
    id: 'waf_detect',
    name: 'WAF Detect',
    category: 'Web',
    description: 'Fingerprint Web Application Firewalls from 55+ known signatures.',
    tags: ['waf', 'fingerprint', 'bypass'],
    parameters: [
      { name: 'url', type: 'string', required: true, description: 'Target URL', placeholder: 'https://example.com' },
    ],
  },
  {
    id: 'waf_bypass',
    name: 'WAF Bypass Generator',
    category: 'Web',
    description: 'Generate WAF bypass payloads tailored to the detected WAF vendor.',
    tags: ['waf', 'bypass', 'payloads'],
    parameters: [
      { name: 'url', type: 'string', required: true, description: 'Target URL', placeholder: 'https://example.com' },
      { name: 'attack_type', type: 'select', required: true, description: 'Attack type', options: ['sqli', 'xss', 'rce', 'path_traversal', 'ssrf'], default: 'sqli' },
      { name: 'waf_vendor', type: 'string', required: false, description: 'Known WAF vendor (optional)' },
    ],
  },
  {
    id: 'payload_encoder',
    name: 'Payload Encoder',
    category: 'Web',
    description: 'Encode payloads using multiple obfuscation techniques.',
    tags: ['encoding', 'bypass', 'payloads'],
    parameters: [
      { name: 'payload', type: 'string', required: true, description: 'Payload to encode', placeholder: "<script>alert(1)</script>" },
      { name: 'encoding', type: 'select', required: true, description: 'Encoding method', options: ['url', 'double_url', 'html', 'unicode', 'base64', 'hex'], default: 'url' },
    ],
  },
  {
    id: 'xss_scan',
    name: 'XSS Scanner',
    category: 'Web',
    description: 'Automated XSS detection with reflected, stored, and DOM-based payloads.',
    tags: ['xss', 'injection', 'web'],
    parameters: [
      { name: 'url', type: 'string', required: true, description: 'Target URL', placeholder: 'https://example.com/search?q=' },
      { name: 'param', type: 'string', required: false, description: 'Parameter name to test' },
      { name: 'dom_based', type: 'boolean', required: false, description: 'Test DOM-based XSS', default: true },
    ],
  },
  {
    id: 'sqli_scan',
    name: 'SQL Injection Scanner',
    category: 'Web',
    description: 'Detect and exploit SQL injection vulnerabilities via SQLMap integration.',
    tags: ['sqli', 'injection', 'database'],
    parameters: [
      { name: 'url', type: 'string', required: true, description: 'Target URL with parameters', placeholder: 'https://example.com/item?id=1' },
      { name: 'technique', type: 'select', required: false, description: 'SQLi technique', options: ['BEUSTQ', 'B', 'E', 'U', 'S', 'T', 'Q'], default: 'BEUSTQ' },
      { name: 'level', type: 'number', required: false, description: 'Test level (1-5)', default: 1 },
      { name: 'risk', type: 'number', required: false, description: 'Risk level (1-3)', default: 1 },
    ],
  },
  {
    id: 'csrf_detect',
    name: 'CSRF Detection',
    category: 'Web',
    description: 'Detect Cross-Site Request Forgery vulnerabilities and weak CSRF protection.',
    tags: ['csrf', 'web', 'auth'],
    parameters: [
      { name: 'url', type: 'string', required: true, description: 'Target URL', placeholder: 'https://example.com' },
      { name: 'method', type: 'select', required: false, description: 'HTTP method', options: ['POST', 'PUT', 'DELETE', 'PATCH'], default: 'POST' },
    ],
  },
  {
    id: 'ssrf_scan',
    name: 'SSRF Scanner',
    category: 'Web',
    description: 'Detect Server-Side Request Forgery vulnerabilities with OOB callbacks.',
    tags: ['ssrf', 'injection', 'cloud'],
    parameters: [
      { name: 'url', type: 'string', required: true, description: 'Target URL', placeholder: 'https://example.com/fetch?url=' },
      { name: 'callback_url', type: 'string', required: false, description: 'OOB callback URL (optional)' },
    ],
  },
  {
    id: 'idor_scan',
    name: 'IDOR Scanner',
    category: 'Web',
    description: 'Test for Insecure Direct Object References by fuzzing object identifiers.',
    tags: ['idor', 'access-control', 'web'],
    parameters: [
      { name: 'url', type: 'string', required: true, description: 'Target URL with object ID', placeholder: 'https://example.com/api/user/123' },
      { name: 'id_param', type: 'string', required: false, description: 'ID parameter name', default: 'id' },
      { name: 'range', type: 'number', required: false, description: 'ID range to test', default: 100 },
    ],
  },
  {
    id: 'jwt_attack',
    name: 'JWT Attacker',
    category: 'Web',
    description: 'Attack JWT tokens: algorithm confusion, none algorithm, key cracking.',
    tags: ['jwt', 'auth', 'cryptography'],
    parameters: [
      { name: 'token', type: 'string', required: true, description: 'JWT token to attack', placeholder: 'eyJ...' },
      { name: 'attack', type: 'select', required: true, description: 'Attack type', options: ['alg_none', 'alg_confusion', 'brute_force', 'kid_injection'], default: 'alg_none' },
      { name: 'secret_wordlist', type: 'string', required: false, description: 'Wordlist for brute force' },
    ],
  },
  {
    id: 'graphql_recon',
    name: 'GraphQL Recon',
    category: 'Web',
    description: 'Introspect GraphQL schemas, find hidden queries, and test for injection.',
    tags: ['graphql', 'api', 'recon'],
    parameters: [
      { name: 'url', type: 'string', required: true, description: 'GraphQL endpoint', placeholder: 'https://example.com/graphql' },
      { name: 'introspect', type: 'boolean', required: false, description: 'Enable introspection', default: true },
    ],
  },
  {
    id: 'api_security_scan',
    name: 'API Security Scanner',
    category: 'Web',
    description: 'Test REST APIs for OWASP API Top 10 vulnerabilities.',
    tags: ['api', 'rest', 'owasp'],
    parameters: [
      { name: 'base_url', type: 'string', required: true, description: 'API base URL', placeholder: 'https://api.example.com/v1' },
      { name: 'spec_url', type: 'string', required: false, description: 'OpenAPI spec URL (optional)' },
      { name: 'auth_header', type: 'string', required: false, description: 'Authorization header value' },
    ],
  },
  {
    id: 'auth_bypass',
    name: 'Auth Bypass Tester',
    category: 'Web',
    description: 'Test authentication bypass techniques (header manipulation, type juggling, path confusion).',
    tags: ['auth', 'bypass', 'web'],
    parameters: [
      { name: 'url', type: 'string', required: true, description: 'Protected endpoint URL', placeholder: 'https://example.com/admin' },
      { name: 'techniques', type: 'select', required: false, description: 'Bypass technique', options: ['all', 'headers', 'type_juggling', 'path_confusion', 'parameter_pollution'], default: 'all' },
    ],
  },
  {
    id: 'cms_scan',
    name: 'CMS Scanner',
    category: 'Web',
    description: 'Detect and audit WordPress, Joomla, Drupal, and Magento installations.',
    tags: ['cms', 'wordpress', 'drupal'],
    parameters: [
      { name: 'url', type: 'string', required: true, description: 'Target URL', placeholder: 'https://example.com' },
      { name: 'cms', type: 'select', required: false, description: 'Known CMS (auto-detect if blank)', options: ['auto', 'wordpress', 'joomla', 'drupal', 'magento'], default: 'auto' },
    ],
  },
  {
    id: 'upload_bypass',
    name: 'Upload Bypass',
    category: 'Web',
    description: 'Bypass file upload restrictions using MIME confusion, double extensions, and null bytes.',
    tags: ['upload', 'bypass', 'web'],
    parameters: [
      { name: 'url', type: 'string', required: true, description: 'Upload endpoint URL', placeholder: 'https://example.com/upload' },
      { name: 'shell_type', type: 'select', required: false, description: 'Webshell type', options: ['php', 'jsp', 'asp', 'aspx'], default: 'php' },
    ],
  },
  {
    id: 'oauth_attack',
    name: 'OAuth Attacker',
    category: 'Web',
    description: 'Test OAuth 2.0 flows for token leakage, open redirects, and PKCE bypass.',
    tags: ['oauth', 'auth', 'token'],
    parameters: [
      { name: 'authorization_url', type: 'string', required: true, description: 'OAuth authorization URL', placeholder: 'https://example.com/oauth/authorize' },
      { name: 'client_id', type: 'string', required: false, description: 'Client ID' },
      { name: 'redirect_uri', type: 'string', required: false, description: 'Redirect URI' },
    ],
  },
  {
    id: 'ffuf_fuzz',
    name: 'FFuf Fuzzer',
    category: 'Web',
    description: 'High-speed web fuzzer for directory/file discovery and parameter fuzzing.',
    tags: ['fuzzing', 'directories', 'web'],
    parameters: [
      { name: 'url', type: 'string', required: true, description: 'Target URL with FUZZ placeholder', placeholder: 'https://example.com/FUZZ' },
      { name: 'wordlist', type: 'string', required: false, description: 'Wordlist path', default: '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt' },
      { name: 'extensions', type: 'string', required: false, description: 'File extensions (comma-separated)', placeholder: 'php,html,js' },
      { name: 'threads', type: 'number', required: false, description: 'Thread count', default: 40 },
    ],
  },

  // ─── Exploitation ─────────────────────────────────────────────────────────
  {
    id: 'searchsploit',
    name: 'SearchSploit',
    category: 'Exploitation',
    description: 'Search Exploit-DB for public exploits matching a product/version.',
    tags: ['exploitdb', 'cve', 'exploit'],
    parameters: [
      { name: 'query', type: 'string', required: true, description: 'Product name and version', placeholder: 'Apache 2.4.49' },
      { name: 'type', type: 'select', required: false, description: 'Exploit type filter', options: ['all', 'webapps', 'remote', 'local', 'dos'], default: 'all' },
    ],
  },
  {
    id: 'metasploit_run',
    name: 'Metasploit Runner',
    category: 'Exploitation',
    description: 'Execute Metasploit modules against a target with configurable payloads.',
    tags: ['metasploit', 'msf', 'exploit'],
    parameters: [
      { name: 'module', type: 'string', required: true, description: 'Metasploit module path', placeholder: 'exploit/multi/handler' },
      { name: 'target', type: 'string', required: true, description: 'Target host', placeholder: '192.168.1.100' },
      { name: 'port', type: 'number', required: false, description: 'Target port', default: 80 },
      { name: 'payload', type: 'string', required: false, description: 'Payload', default: 'linux/x64/meterpreter/reverse_tcp' },
      { name: 'lhost', type: 'string', required: false, description: 'LHOST for reverse shells' },
      { name: 'lport', type: 'number', required: false, description: 'LPORT', default: 4444 },
    ],
  },
  {
    id: 'webshell_deploy',
    name: 'Webshell Deployer',
    category: 'Exploitation',
    description: 'Deploy and manage webshells (PHP, JSP, ASPX) on compromised web servers.',
    tags: ['webshell', 'rce', 'post-exploit'],
    parameters: [
      { name: 'url', type: 'string', required: true, description: 'Upload endpoint or shell URL', placeholder: 'https://example.com/shell.php' },
      { name: 'shell_type', type: 'select', required: true, description: 'Webshell type', options: ['php', 'jsp', 'aspx', 'python'], default: 'php' },
    ],
  },
  {
    id: 'deserialization_exploit',
    name: 'Deserialization Exploiter',
    category: 'Exploitation',
    description: 'Generate and test deserialization payloads for Java, PHP, and .NET.',
    tags: ['deserialization', 'java', 'dotnet'],
    parameters: [
      { name: 'platform', type: 'select', required: true, description: 'Target platform', options: ['java', 'php', 'dotnet'], default: 'java' },
      { name: 'gadget_chain', type: 'string', required: true, description: 'Gadget chain name', placeholder: 'CommonsCollections1' },
      { name: 'command', type: 'string', required: true, description: 'Command to execute', placeholder: 'id' },
    ],
  },
  {
    id: 'injection_attack',
    name: 'Injection Attack Suite',
    category: 'Exploitation',
    description: 'Multi-vector injection testing: command injection, LDAP, NoSQL, XPath, template injection.',
    tags: ['injection', 'rce', 'ssti'],
    parameters: [
      { name: 'url', type: 'string', required: true, description: 'Target URL', placeholder: 'https://example.com/api' },
      { name: 'param', type: 'string', required: true, description: 'Parameter name to inject', placeholder: 'search' },
      { name: 'type', type: 'select', required: true, description: 'Injection type', options: ['command', 'ldap', 'nosql', 'xpath', 'ssti', 'all'], default: 'all' },
    ],
  },
  {
    id: 'network_service_exploit',
    name: 'Network Service Exploiter',
    category: 'Exploitation',
    description: 'Exploit common network services: FTP, SSH, SMB, RDP, Telnet.',
    tags: ['network', 'services', 'exploit'],
    parameters: [
      { name: 'target', type: 'string', required: true, description: 'Target host', placeholder: '192.168.1.100' },
      { name: 'service', type: 'select', required: true, description: 'Service to target', options: ['ftp', 'ssh', 'smb', 'rdp', 'telnet', 'vnc'], default: 'smb' },
      { name: 'credentials_file', type: 'string', required: false, description: 'Credential wordlist path' },
    ],
  },

  // ─── Post-Exploitation ────────────────────────────────────────────────────
  {
    id: 'post_enum',
    name: 'System Enumeration',
    category: 'Post-Exploitation',
    description: 'Enumerate OS, users, processes, network, and installed software post-compromise.',
    tags: ['enum', 'post-exploit', 'privesc'],
    parameters: [
      { name: 'session_type', type: 'select', required: true, description: 'Session type', options: ['meterpreter', 'shell', 'ssh'], default: 'meterpreter' },
      { name: 'target', type: 'string', required: true, description: 'Target host or session ID', placeholder: '192.168.1.100' },
    ],
  },
  {
    id: 'priv_esc',
    name: 'Privilege Escalation',
    category: 'Post-Exploitation',
    description: 'Automated privilege escalation: SUID, sudo misconfiguration, kernel exploits, token impersonation.',
    tags: ['privesc', 'linux', 'windows'],
    parameters: [
      { name: 'os', type: 'select', required: true, description: 'Target OS', options: ['linux', 'windows', 'macos'], default: 'linux' },
      { name: 'session', type: 'string', required: true, description: 'Active session identifier', placeholder: 'session-1' },
    ],
  },
  {
    id: 'lateral_movement',
    name: 'Lateral Movement',
    category: 'Post-Exploitation',
    description: 'Move laterally using pass-the-hash, pass-the-ticket, and WMI exec.',
    tags: ['lateral', 'movement', 'pth'],
    parameters: [
      { name: 'target', type: 'string', required: true, description: 'Target host', placeholder: '192.168.1.100' },
      { name: 'technique', type: 'select', required: true, description: 'Technique', options: ['pth', 'ptt', 'wmi', 'psexec', 'winrm'], default: 'pth' },
      { name: 'credential', type: 'string', required: true, description: 'NTLM hash or password', placeholder: 'aad3...' },
    ],
  },
  {
    id: 'persistence_install',
    name: 'Persistence Installer',
    category: 'Post-Exploitation',
    description: 'Install persistence mechanisms: cron jobs, registry keys, services, startup items.',
    tags: ['persistence', 'backdoor', 'post-exploit'],
    parameters: [
      { name: 'os', type: 'select', required: true, description: 'Target OS', options: ['linux', 'windows'], default: 'linux' },
      { name: 'method', type: 'select', required: true, description: 'Persistence method', options: ['cron', 'registry', 'service', 'startup'], default: 'cron' },
      { name: 'payload', type: 'string', required: true, description: 'Command/payload to persist', placeholder: 'bash -c "..."' },
    ],
  },
  {
    id: 'data_exfiltration',
    name: 'Data Exfiltration',
    category: 'Post-Exploitation',
    description: 'Exfiltrate sensitive files over DNS, HTTP, ICMP, and encrypted channels.',
    tags: ['exfil', 'data', 'post-exploit'],
    parameters: [
      { name: 'channel', type: 'select', required: true, description: 'Exfil channel', options: ['dns', 'http', 'icmp', 'smtp', 'slack'], default: 'dns' },
      { name: 'target_files', type: 'string', required: true, description: 'Files/paths to exfiltrate', placeholder: '/etc/passwd,/etc/shadow' },
      { name: 'receiver', type: 'string', required: true, description: 'Receiver address/domain', placeholder: 'attacker.com' },
    ],
  },
  {
    id: 'oob_listener',
    name: 'OOB Listener',
    category: 'Post-Exploitation',
    description: 'Out-of-band HTTP/DNS/SMTP listener for blind vulnerability detection.',
    tags: ['oob', 'callback', 'blind'],
    parameters: [
      { name: 'protocol', type: 'select', required: true, description: 'Listener protocol', options: ['http', 'dns', 'smtp'], default: 'http' },
      { name: 'port', type: 'number', required: false, description: 'Listener port', default: 8080 },
      { name: 'timeout', type: 'number', required: false, description: 'Timeout (seconds)', default: 60 },
    ],
  },

  // ─── Active Directory ─────────────────────────────────────────────────────
  {
    id: 'bloodhound_collect',
    name: 'BloodHound Collector',
    category: 'Active Directory',
    description: 'Collect BloodHound data using SharpHound/BloodHound.py for AD graph analysis.',
    tags: ['bloodhound', 'ad', 'recon'],
    parameters: [
      { name: 'domain', type: 'string', required: true, description: 'Active Directory domain', placeholder: 'corp.local' },
      { name: 'dc_ip', type: 'string', required: true, description: 'Domain Controller IP', placeholder: '10.0.0.1' },
      { name: 'username', type: 'string', required: false, description: 'Domain username' },
      { name: 'password', type: 'string', required: false, description: 'Password or NT hash' },
      { name: 'collection_method', type: 'select', required: false, description: 'Collection method', options: ['All', 'DCOnly', 'LoggedOn', 'Session', 'Trusts'], default: 'All' },
    ],
  },
  {
    id: 'bloodhound_query',
    name: 'BloodHound Query',
    category: 'Active Directory',
    description: 'Execute pre-built or custom Cypher queries against the BloodHound Neo4j graph.',
    tags: ['bloodhound', 'neo4j', 'cypher'],
    parameters: [
      { name: 'query_name', type: 'string', required: false, description: 'Pre-built query name (leave blank for custom)', placeholder: 'shortest_path_to_da' },
      { name: 'custom_query', type: 'string', required: false, description: 'Custom Cypher query', placeholder: 'MATCH (n:User) RETURN n LIMIT 10' },
    ],
  },
  {
    id: 'responder',
    name: 'Responder (LLMNR/NBT-NS)',
    category: 'Active Directory',
    description: 'Poison LLMNR/NBT-NS/mDNS responses to capture NTLMv2 challenge hashes.',
    tags: ['responder', 'llmnr', 'ntlm'],
    parameters: [
      { name: 'interface', type: 'string', required: true, description: 'Network interface', placeholder: 'eth0' },
      { name: 'timeout', type: 'number', required: false, description: 'Run duration (seconds)', default: 300 },
    ],
  },
  {
    id: 'ntlm_relay',
    name: 'NTLM Relay',
    category: 'Active Directory',
    description: 'Relay captured NTLM credentials to execute commands on target hosts.',
    tags: ['ntlm', 'relay', 'smb'],
    parameters: [
      { name: 'target', type: 'string', required: true, description: 'Relay target (IP or CIDR)', placeholder: '10.0.0.0/24' },
      { name: 'interface', type: 'string', required: true, description: 'Listening interface', placeholder: 'eth0' },
      { name: 'command', type: 'string', required: false, description: 'Command to execute', placeholder: 'whoami' },
    ],
  },
  {
    id: 'secretsdump',
    name: 'Secrets Dump (DCSync)',
    category: 'Active Directory',
    description: 'Dump domain secrets, NTDS hashes, and LSA secrets remotely.',
    tags: ['secretsdump', 'dcsync', 'hashes'],
    parameters: [
      { name: 'target', type: 'string', required: true, description: 'Target DC or host', placeholder: '10.0.0.1' },
      { name: 'username', type: 'string', required: true, description: 'Domain\\username', placeholder: 'CORP\\Administrator' },
      { name: 'credential', type: 'string', required: true, description: 'Password or NTLM hash', placeholder: 'Password123! or aad3...' },
    ],
  },
  {
    id: 'mimikatz_exec',
    name: 'Mimikatz Executor',
    category: 'Active Directory',
    description: 'Execute Mimikatz commands: sekurlsa::logonpasswords, lsadump::sam, dpapi.',
    tags: ['mimikatz', 'credentials', 'lsass'],
    parameters: [
      { name: 'command', type: 'select', required: true, description: 'Mimikatz command', options: ['sekurlsa::logonpasswords', 'lsadump::sam', 'lsadump::dcsync', 'dpapi::cred', 'kerberos::list'], default: 'sekurlsa::logonpasswords' },
      { name: 'target', type: 'string', required: true, description: 'Target session or host', placeholder: '10.0.0.100' },
    ],
  },
  {
    id: 'golden_ticket',
    name: 'Golden Ticket Forge',
    category: 'Active Directory',
    description: 'Forge Kerberos Golden Tickets for persistent domain admin access.',
    tags: ['kerberos', 'golden-ticket', 'persistence'],
    parameters: [
      { name: 'domain', type: 'string', required: true, description: 'AD Domain', placeholder: 'corp.local' },
      { name: 'domain_sid', type: 'string', required: true, description: 'Domain SID', placeholder: 'S-1-5-21-...' },
      { name: 'krbtgt_hash', type: 'string', required: true, description: 'KRBTGT NTLM hash', placeholder: 'aad3b435...' },
      { name: 'username', type: 'string', required: false, description: 'Username to impersonate', default: 'Administrator' },
    ],
  },
  {
    id: 'silver_ticket',
    name: 'Silver Ticket Forge',
    category: 'Active Directory',
    description: 'Forge Kerberos Silver Tickets for service-level access.',
    tags: ['kerberos', 'silver-ticket', 'service'],
    parameters: [
      { name: 'service', type: 'string', required: true, description: 'Target service SPN', placeholder: 'cifs/fileserver.corp.local' },
      { name: 'domain_sid', type: 'string', required: true, description: 'Domain SID', placeholder: 'S-1-5-21-...' },
      { name: 'service_hash', type: 'string', required: true, description: 'Service account NTLM hash', placeholder: 'aad3b435...' },
    ],
  },
  {
    id: 'hash_crack',
    name: 'Hash Cracker',
    category: 'Active Directory',
    description: 'Crack NTLM, Net-NTLMv2, Kerberoast hashes with wordlists and rules.',
    tags: ['hashcat', 'cracking', 'password'],
    parameters: [
      { name: 'hash_type', type: 'select', required: true, description: 'Hash type', options: ['ntlm', 'ntlmv2', 'kerberoast', 'asreproast', 'md5', 'sha1', 'bcrypt'], default: 'ntlm' },
      { name: 'hashes', type: 'string', required: true, description: 'Hashes to crack (one per line)', placeholder: 'aad3b435...' },
      { name: 'wordlist', type: 'string', required: false, description: 'Wordlist path', default: '/usr/share/wordlists/rockyou.txt' },
    ],
  },

  // ─── Cloud ────────────────────────────────────────────────────────────────
  {
    id: 'aws_enum',
    name: 'AWS Enumerator',
    category: 'Cloud',
    description: 'Enumerate AWS resources: IAM, S3, EC2, Lambda, RDS, and more.',
    tags: ['aws', 'cloud', 'iam'],
    parameters: [
      { name: 'access_key', type: 'string', required: true, description: 'AWS Access Key ID', placeholder: 'AKIA...' },
      { name: 'secret_key', type: 'string', required: true, description: 'AWS Secret Access Key', placeholder: '...' },
      { name: 'region', type: 'string', required: false, description: 'AWS Region', default: 'us-east-1' },
      { name: 'services', type: 'string', required: false, description: 'Services to enumerate (comma-separated)', default: 'iam,s3,ec2' },
    ],
  },
  {
    id: 'azure_enum',
    name: 'Azure Enumerator',
    category: 'Cloud',
    description: 'Enumerate Azure resources: Subscriptions, VMs, Storage, AAD, Key Vaults.',
    tags: ['azure', 'cloud', 'aad'],
    parameters: [
      { name: 'tenant_id', type: 'string', required: true, description: 'Azure Tenant ID', placeholder: 'xxxxxxxx-xxxx-...' },
      { name: 'client_id', type: 'string', required: true, description: 'Client ID / App ID', placeholder: 'xxxxxxxx-xxxx-...' },
      { name: 'client_secret', type: 'string', required: false, description: 'Client Secret' },
    ],
  },
  {
    id: 'gcp_enum',
    name: 'GCP Enumerator',
    category: 'Cloud',
    description: 'Enumerate GCP resources: Projects, GCE, GCS, IAM, Cloud Functions.',
    tags: ['gcp', 'cloud', 'iam'],
    parameters: [
      { name: 'project_id', type: 'string', required: true, description: 'GCP Project ID', placeholder: 'my-project-123' },
      { name: 'key_file', type: 'string', required: false, description: 'Service account key JSON path' },
    ],
  },
  {
    id: 'container_escape',
    name: 'Container Escape',
    category: 'Cloud',
    description: 'Test container escape techniques: privileged mode, host path mounts, cgroup escape.',
    tags: ['docker', 'container', 'escape'],
    parameters: [
      { name: 'container_id', type: 'string', required: true, description: 'Container ID or name', placeholder: 'abc123def456' },
      { name: 'technique', type: 'select', required: false, description: 'Escape technique', options: ['auto', 'privileged', 'hostpath', 'cgroup', 'runc'], default: 'auto' },
    ],
  },
  {
    id: 'k8s_audit',
    name: 'Kubernetes Security Audit',
    category: 'Cloud',
    description: 'Audit Kubernetes cluster: RBAC misconfigs, exposed APIs, privilege escalation paths.',
    tags: ['kubernetes', 'k8s', 'rbac'],
    parameters: [
      { name: 'kubeconfig', type: 'string', required: false, description: 'Kubeconfig path (uses default if blank)', placeholder: '~/.kube/config' },
      { name: 'namespace', type: 'string', required: false, description: 'Namespace to audit (all if blank)', default: 'default' },
    ],
  },

  // ─── Proxy ────────────────────────────────────────────────────────────────
  {
    id: 'http_intercept',
    name: 'HTTP Interceptor',
    category: 'Proxy',
    description: 'Capture and modify HTTP/HTTPS traffic through the built-in mitmproxy engine.',
    tags: ['proxy', 'intercept', 'mitm'],
    parameters: [
      { name: 'port', type: 'number', required: false, description: 'Proxy listen port', default: 8080 },
      { name: 'scope', type: 'string', required: false, description: 'Scope filter (domain pattern)', placeholder: '*.example.com' },
      { name: 'intercept_requests', type: 'boolean', required: false, description: 'Intercept requests', default: true },
      { name: 'intercept_responses', type: 'boolean', required: false, description: 'Intercept responses', default: false },
    ],
  },
  {
    id: 'request_replay',
    name: 'Request Replay',
    category: 'Proxy',
    description: 'Replay captured HTTP requests with optional modifications.',
    tags: ['proxy', 'replay', 'testing'],
    parameters: [
      { name: 'request_id', type: 'string', required: true, description: 'Captured request ID', placeholder: 'req-abc123' },
      { name: 'modifications', type: 'string', required: false, description: 'JSON modifications to apply', placeholder: '{"headers": {"X-Custom": "value"}}' },
      { name: 'count', type: 'number', required: false, description: 'Replay count', default: 1 },
    ],
  },
  {
    id: 'request_intruder',
    name: 'Request Intruder',
    category: 'Proxy',
    description: 'Fuzz request parameters with customizable attack payloads (Burp Intruder-style).',
    tags: ['proxy', 'intruder', 'fuzzing'],
    parameters: [
      { name: 'request_id', type: 'string', required: true, description: 'Base request ID', placeholder: 'req-abc123' },
      { name: 'attack_type', type: 'select', required: true, description: 'Attack type', options: ['sniper', 'battering_ram', 'pitchfork', 'cluster_bomb'], default: 'sniper' },
      { name: 'payload_set', type: 'string', required: true, description: 'Payload list (one per line)' },
    ],
  },
  {
    id: 'traffic_logger',
    name: 'Traffic Logger',
    category: 'Proxy',
    description: 'Log and export all HTTP traffic to HAR, JSON, or CSV format.',
    tags: ['proxy', 'logging', 'export'],
    parameters: [
      { name: 'format', type: 'select', required: true, description: 'Export format', options: ['har', 'json', 'csv'], default: 'har' },
      { name: 'filter_domain', type: 'string', required: false, description: 'Domain filter', placeholder: 'example.com' },
      { name: 'include_bodies', type: 'boolean', required: false, description: 'Include response bodies', default: true },
    ],
  },
  {
    id: 'scope_manager',
    name: 'Scope Manager',
    category: 'Proxy',
    description: 'Define and manage proxy scope to filter traffic to authorized targets only.',
    tags: ['proxy', 'scope', 'filter'],
    parameters: [
      { name: 'include_patterns', type: 'string', required: true, description: 'Include patterns (comma-separated)', placeholder: '*.example.com, api.example.com' },
      { name: 'exclude_patterns', type: 'string', required: false, description: 'Exclude patterns (comma-separated)' },
    ],
  },
  {
    id: 'websocket_intercept',
    name: 'WebSocket Interceptor',
    category: 'Proxy',
    description: 'Capture, replay, and mutate WebSocket messages for security testing.',
    tags: ['websocket', 'proxy', 'intercept'],
    parameters: [
      { name: 'url', type: 'string', required: true, description: 'WebSocket URL', placeholder: 'wss://example.com/ws' },
      { name: 'replay_delay_ms', type: 'number', required: false, description: 'Replay message delay (ms)', default: 100 },
    ],
  },

  // ─── Network ──────────────────────────────────────────────────────────────
  {
    id: 'port_scan',
    name: 'Port Scanner (Naabu)',
    category: 'Network',
    description: 'Fast port scanning with Naabu — SYN, CONNECT, and UDP scans.',
    tags: ['naabu', 'ports', 'scan'],
    parameters: [
      { name: 'target', type: 'string', required: true, description: 'Target host/CIDR', placeholder: '192.168.1.0/24' },
      { name: 'ports', type: 'string', required: false, description: 'Port range', default: 'top-1000' },
      { name: 'scan_type', type: 'select', required: false, description: 'Scan type', options: ['syn', 'connect', 'udp'], default: 'syn' },
      { name: 'rate', type: 'number', required: false, description: 'Packets per second', default: 1000 },
    ],
  },
  {
    id: 'nuclei_scan',
    name: 'Nuclei Vulnerability Scanner',
    category: 'Network',
    description: 'Template-based vulnerability scanning with 8000+ Nuclei templates.',
    tags: ['nuclei', 'cve', 'scan'],
    parameters: [
      { name: 'target', type: 'string', required: true, description: 'Target URL or host', placeholder: 'https://example.com' },
      { name: 'templates', type: 'string', required: false, description: 'Template tags/paths', default: 'cves,exposures,misconfigs' },
      { name: 'severity', type: 'select', required: false, description: 'Minimum severity', options: ['info', 'low', 'medium', 'high', 'critical'], default: 'medium' },
      { name: 'rate_limit', type: 'number', required: false, description: 'Request rate limit', default: 150 },
    ],
  },
  {
    id: 'packet_capture',
    name: 'Packet Capture',
    category: 'Network',
    description: 'Capture and analyse network packets with protocol dissection.',
    tags: ['pcap', 'traffic', 'capture'],
    parameters: [
      { name: 'interface', type: 'string', required: true, description: 'Network interface', placeholder: 'eth0' },
      { name: 'filter', type: 'string', required: false, description: 'BPF filter', placeholder: 'tcp port 80' },
      { name: 'count', type: 'number', required: false, description: 'Max packets to capture', default: 1000 },
      { name: 'timeout', type: 'number', required: false, description: 'Capture timeout (seconds)', default: 60 },
    ],
  },
  {
    id: 'socks_proxy',
    name: 'SOCKS Proxy Tunnel',
    category: 'Network',
    description: 'Create SOCKS5 proxy tunnels through compromised hosts for network pivoting.',
    tags: ['socks', 'pivot', 'tunnel'],
    parameters: [
      { name: 'host', type: 'string', required: true, description: 'Jump host', placeholder: '10.0.0.100' },
      { name: 'local_port', type: 'number', required: false, description: 'Local SOCKS5 port', default: 1080 },
      { name: 'method', type: 'select', required: false, description: 'Tunnel method', options: ['ssh', 'chisel', 'ligolo'], default: 'ssh' },
    ],
  },
  {
    id: 'port_forward',
    name: 'Port Forwarder',
    category: 'Network',
    description: 'Forward ports through compromised hosts to access internal services.',
    tags: ['portforward', 'pivot', 'tunnel'],
    parameters: [
      { name: 'local_port', type: 'number', required: true, description: 'Local port', default: 8080 },
      { name: 'remote_host', type: 'string', required: true, description: 'Remote host', placeholder: '172.16.0.100' },
      { name: 'remote_port', type: 'number', required: true, description: 'Remote port', default: 80 },
      { name: 'jump_host', type: 'string', required: true, description: 'Jump host (SSH)', placeholder: 'user@10.0.0.100' },
    ],
  },
  {
    id: 'network_pivot_map',
    name: 'Network Pivot Map',
    category: 'Network',
    description: 'Build a visual map of the network pivot chain and accessible subnets.',
    tags: ['pivot', 'mapping', 'network'],
    parameters: [
      { name: 'initial_host', type: 'string', required: true, description: 'Initial pivot host', placeholder: '10.0.0.100' },
      { name: 'depth', type: 'number', required: false, description: 'Pivot depth', default: 3 },
    ],
  },
  {
    id: 'browser_tool',
    name: 'Headless Browser',
    category: 'Network',
    description: 'Automate browser-based testing with Playwright: screenshots, JavaScript execution, form submission.',
    tags: ['browser', 'playwright', 'automation'],
    parameters: [
      { name: 'url', type: 'string', required: true, description: 'Target URL', placeholder: 'https://example.com' },
      { name: 'action', type: 'select', required: true, description: 'Action to perform', options: ['screenshot', 'get_content', 'execute_js', 'fill_form', 'click'], default: 'screenshot' },
      { name: 'script', type: 'string', required: false, description: 'JavaScript to execute (for execute_js action)' },
    ],
  },
];

/** Get all unique categories */
export const TOOL_CATEGORIES: ToolCategory[] = [
  'Recon',
  'Web',
  'Exploitation',
  'Post-Exploitation',
  'Active Directory',
  'Cloud',
  'Proxy',
  'Network',
];

/** Color class for each category badge */
export const CATEGORY_COLORS: Record<ToolCategory, string> = {
  Recon: 'bg-blue-900/50 text-blue-300 border-blue-700',
  Web: 'bg-yellow-900/50 text-yellow-300 border-yellow-700',
  Exploitation: 'bg-red-900/50 text-red-300 border-red-700',
  'Post-Exploitation': 'bg-orange-900/50 text-orange-300 border-orange-700',
  'Active Directory': 'bg-purple-900/50 text-purple-300 border-purple-700',
  Cloud: 'bg-sky-900/50 text-sky-300 border-sky-700',
  Proxy: 'bg-teal-900/50 text-teal-300 border-teal-700',
  Network: 'bg-green-900/50 text-green-300 border-green-700',
};

/** Get tools by category */
export function getToolsByCategory(category: ToolCategory): ToolDefinition[] {
  return TOOL_CATALOG.filter((t) => t.category === category);
}

/** Search tools by name, description, or tags */
export function searchTools(query: string): ToolDefinition[] {
  const q = query.toLowerCase().trim();
  if (!q) return TOOL_CATALOG;
  return TOOL_CATALOG.filter(
    (t) =>
      t.name.toLowerCase().includes(q) ||
      t.description.toLowerCase().includes(q) ||
      t.tags.some((tag) => tag.includes(q))
  );
}
