<?php

/**
 * WAF (Web Application Firewall) Configuration
 * This file defines rules for the WAF middleware
 */

return [
    // Global settings
    'enabled' => true,
    'default_action' => 'allow',  // allow or block
    'blocked_response_code' => 403,
    'blocked_response_message' => 'Access Denied',

    // Rate limiting configuration
    'rate_limiting' => [
        'enabled' => false,
        'default_limit' => 3,  // requests per window
        'default_window' => 5,  // seconds
        'store' => 'memcached', // memcached or file
        'memcached_pool' => 'cache', // Only used if store is memcached
    ],

    // Whitelist rules - bypass all other checks if conditions match
    'whitelist' => [
        [
            'name' => 'Whitelist trusted IPs',
            'conditions' => [
                [
                    'type' => 'ip',
                    'operator' => 'in_list',
                    'values' => [
                        '127.0.0.1',
                        '::1',
                    ],
                ],
            ],
            'action' => 'allow',
        ],
        [
            'name' => 'Whitelist API keys',
            'conditions' => [
                [
                    'type' => 'header',
                    'key' => 'X-API-Key',
                    'operator' => 'in_list',
                    'values' => [
                        'trusted-key-1',
                        'trusted-key-2',
                    ],
                ],
            ],
            'action' => 'allow',
        ],
    ],

    // Blacklist rules - block if ALL conditions in a rule match
    // Each rule can optionally specify 'response_code' and 'response_message' to override defaults
    'blacklist' => [
        // ============================================
        // OWASP TOP 10 SECURITY RULES
        // ============================================

        // OWASP A01:2021 - Broken Access Control
        [
            'name' => 'OWASP A01: Path Traversal Attack',
            'conditions' => [
                [
                    'type' => 'path',
                    'operator' => 'regex',
                    'value' => '/\\.\\.\\/|\\.\\.\\\\|%2e%2e%2f|%2e%2e%5c/i',
                ],
            ],
            'action' => 'block',
            'response_code' => 403,
            'response_message' => 'Path traversal attempt detected',
        ],

        // OWASP A03:2021 - Injection
        [
            'name' => 'OWASP A03: SQL Injection in Query Params',
            'conditions' => [
                [
                    'type' => 'path',
                    'operator' => 'regex',
                    'value' => '/(union.*select|select.*from|insert.*into|delete.*from|drop.*table|update.*set|exec.*xp_|execute.*sp_)/i',
                ],
            ],
            'action' => 'block',
            'response_code' => 403,
            'response_message' => 'SQL injection attempt detected',
        ],
        [
            'name' => 'OWASP A03: Command Injection',
            'conditions' => [
                [
                    'type' => 'path',
                    'operator' => 'regex',
                    'value' => '/(\||;|`|\$\(|<\(|>\(|&&|\\n|\\r)/i',
                ],
            ],
            'action' => 'block',
            'response_code' => 403,
            'response_message' => 'Command injection attempt detected',
        ],
        [
            'name' => 'OWASP A03: LDAP Injection',
            'conditions' => [
                [
                    'type' => 'path',
                    'operator' => 'regex',
                    'value' => '/(\*\)|\(\||\)\(|%2a%29|%28%7c|%29%28)/i',
                ],
            ],
            'action' => 'block',
            'response_code' => 403,
            'response_message' => 'LDAP injection attempt detected',
        ],
        [
            'name' => 'OWASP A03: XPath Injection',
            'conditions' => [
                [
                    'type' => 'path',
                    'operator' => 'regex',
                    'value' => '/(\\[|\\]|or\\s+|and\\s+|node\\(\\)|text\\(\\)|parent::|child::)/i',
                ],
            ],
            'action' => 'block',
            'response_code' => 403,
            'response_message' => 'XPath injection attempt detected',
        ],

        // OWASP A03:2021 - Cross-Site Scripting (XSS)
        [
            'name' => 'OWASP A03: XSS in Query Parameters',
            'conditions' => [
                [
                    'type' => 'path',
                    'operator' => 'regex',
                    'value' => '/(<script|javascript:|onerror=|onload=|<iframe|<object|<embed|eval\\()/i',
                ],
            ],
            'action' => 'block',
            'response_code' => 403,
            'response_message' => 'XSS attempt detected',
        ],

        // OWASP A05:2021 - Security Misconfiguration
        [
            'name' => 'OWASP A05: Sensitive File Access',
            'conditions' => [
                [
                    'type' => 'path',
                    'operator' => 'regex',
                    'value' => '/(\\.env|\\.git|\\.ssh|wp-config\\.php|config\\.php|web\\.config|\\.htaccess|\\.htpasswd|passwd|shadow)/i',
                ],
            ],
            'action' => 'block',
            'response_code' => 404,
            'response_message' => 'Not Found',
        ],

        // OWASP A06:2021 - Vulnerable and Outdated Components
        [
            'name' => 'OWASP A06: Known Vulnerability Scanner',
            'conditions' => [
                [
                    'type' => 'header',
                    'key' => 'User-Agent',
                    'operator' => 'regex',
                    'value' => '/(nikto|sqlmap|nmap|masscan|acunetix|nessus|openvas|metasploit)/i',
                ],
            ],
            'action' => 'block',
            'response_code' => 403,
            'response_message' => 'Security scanner detected',
        ],

        // OWASP A08:2021 - Software and Data Integrity Failures
        [
            'name' => 'OWASP A08: Null Byte Injection',
            'conditions' => [
                [
                    'type' => 'path',
                    'operator' => 'regex',
                    'value' => '/(%00|\\x00|\\0)/i',
                ],
            ],
            'action' => 'block',
            'response_code' => 400,
            'response_message' => 'Null byte injection detected',
        ],

        // OWASP A09:2021 - Security Logging and Monitoring Failures
        [
            'name' => 'OWASP A09: Log Forging Attempt',
            'conditions' => [
                [
                    'type' => 'path',
                    'operator' => 'regex',
                    'value' => '/(%0d|%0a|\\r|\\n|%5cn|%5cr)/i',
                ],
            ],
            'action' => 'block',
            'response_code' => 400,
            'response_message' => 'Log injection attempt detected',
        ],

        // OWASP A10:2021 - Server-Side Request Forgery (SSRF)
        [
            'name' => 'OWASP A10: SSRF via URL Parameters',
            'conditions' => [
                [
                    'type' => 'path',
                    'operator' => 'regex',
                    'value' => '/(localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0|\\[::1\\]|169\\.254\\.|file:\/\/|dict:\/\/|gopher:\/\/)/i',
                ],
            ],
            'action' => 'block',
            'response_code' => 400,
            'response_message' => 'SSRF attempt detected',
        ],

        // Additional Common Attack Patterns
        [
            'name' => 'Remote File Inclusion (RFI)',
            'conditions' => [
                [
                    'type' => 'path',
                    'operator' => 'regex',
                    'value' => '/(http:\/\/|https:\/\/|ftp:\/\/|php:\/\/|data:\/\/|expect:\/\/|input:\/\/)/i',
                ],
            ],
            'action' => 'block',
            'response_code' => 400,
            'response_message' => 'Remote file inclusion detected',
        ],
        [
            'name' => 'XXE (XML External Entity) Attack',
            'conditions' => [
                [
                    'type' => 'path',
                    'operator' => 'regex',
                    'value' => '/(<!DOCTYPE|<!ENTITY|SYSTEM|PUBLIC)/i',
                ],
            ],
            'action' => 'block',
            'response_code' => 400,
            'response_message' => 'XXE attack detected',
        ],

        // ============================================
        // CUSTOM APPLICATION RULES
        // ============================================

        [
            'name' => 'Block Subang Indonesia',
            'conditions' => [
                [
                    'type' => 'query_param',
                    'key' => 'city',
                    'operator' => 'equals',
                    'value' => 'SomeCity',
                ],
                [
                    'type' => 'query_param',
                    'key' => 'country',
                    'operator' => 'equals',
                    'value' => 'SomeCountry',
                ],
            ],
            'action' => 'block',
            // Uses default response_code and response_message
        ],
        [
            'name' => 'Block Dart Client',
            'conditions' => [
                [
                    'type' => 'header',
                    'key' => 'User-Agent',
                    'operator' => 'equals',
                    'value' => 'Dart/3.5 (dart:io)',
                ],
            ],
            'action' => 'block',
            'response_code' => 418,
            'response_message' => 'Unsupported client',
        ],
        [
            'name' => 'Block suspicious user agents',
            'conditions' => [
                [
                    'type' => 'header',
                    'key' => 'User-Agent',
                    'operator' => 'regex',
                    'value' => '/(bot|crawler|scraper|scanner)/i',
                ],
            ],
            'action' => 'block',
        ],
        [
            'name' => 'Block malicious IPs',
            'conditions' => [
                [
                    'type' => 'ip',
                    'operator' => 'in_list',
                    'values' => [
                        '192.168.1.1',
                        '10.0.0.1',
                    ],
                ],
            ],
            'action' => 'block',
        ],
    ],

    // Rate limit rules - apply specific rate limits based on conditions
    'rate_limit_rules' => [
//        [
//            'name' => 'Strict limit for unauthenticated',
//            'conditions' => [
//                [
//                    'type' => 'header',
//                    'key' => 'Authorization',
//                    'operator' => 'not_exists',
//                ],
//            ],
//            'rate_limit' => [
//                'limit' => 20,
//                'window' => 60,
//                'key_prefix' => 'unauthenticated',
//            ],
//        ],
        [
            'name' => 'Per IP rate limit',
            'conditions' => [],  // applies to all
            'rate_limit' => [
                'limit' => 1,
                'window' => 3,
                'key_prefix' => 'ip',
                'key_source' => 'ip',  // Use IP address as the rate limit key
            ],
        ],
//        [
//            'name' => 'Per API key rate limit',
//            'conditions' => [
//                [
//                    'type' => 'header',
//                    'key' => 'apikey',
//                    'operator' => 'exists',
//                ],
//            ],
//            'rate_limit' => [
//                'limit' => 1000,
//                'window' => 60,
//                'key_prefix' => 'kipchak_apikey', // Key for building rate limit key in the cache store
//                'key_source' => 'header:apikey',  // Use API key value as the rate limit key
//            ],
//        ],
    ],

    /*
     * Supported operators:
     * - equals: exact match
     * - not_equals: not equal
     * - contains: string contains
     * - not_contains: string does not contain
     * - regex: regular expression match
     * - in_list: value is in the provided list
     * - not_in_list: value is not in the provided list
     * - exists: header/param exists
     * - not_exists: header/param does not exist
     * - gt: greater than (numeric)
     * - lt: less than (numeric)
     * - gte: greater than or equal (numeric)
     * - lte: less than or equal (numeric)
     *
     * Supported condition types:
     * - header: HTTP header
     * - query_param: URL query parameter
     * - ip: Client IP address
     * - method: HTTP method
     * - path: URL path
     * - body: Request body (JSON)
     */
];
