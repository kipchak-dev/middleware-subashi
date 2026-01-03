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
    'blacklist' => [
        [
            'name' => 'Block Subang Indonesia',
            'conditions' => [
                [
                    'type' => 'query_param',
                    'key' => 'city',
                    'operator' => 'equals',
                    'value' => 'Subang',
                ],
                [
                    'type' => 'query_param',
                    'key' => 'country',
                    'operator' => 'equals',
                    'value' => 'Indonesia',
                ],
            ],
            'action' => 'block',
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
