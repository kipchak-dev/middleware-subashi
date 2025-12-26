<?php

namespace Kipchak\Middleware\Subashi\Handlers;

use Kipchak\Core\Components\Http;
use Kipchak\Driver\Config\Config;
use Kipchak\Driver\Filecache\Filecache;
use Kipchak\Driver\Memcached\Memcached;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Response;
use Symfony\Component\Cache\Adapter\AdapterInterface;
use Kipchak\Driver\Logger\Logger;
use Monolog\Logger as MonoLogger;

class Firewall
{
    private array $config;
    private ?AdapterInterface $cache = null;

    private MonoLogger $logger;

    public function __construct()
    {
        // Load configuration from container
        $this->config = Config::get('kipchak.subashi') ?? [];
        $this->logger = Logger::get();

        // Initialize cache if rate limiting is enabled
        if ($this->config['rate_limiting']['enabled']) {
            $this->logger->debug('Rate limiting is enabled.');
            if ($this->config['rate_limiting']['store'] === 'memcached') {
                $this->logger->debug('Using Memcached as rate limiting cache store.');
                $this->cache = Memcached::get($this->config['rate_limiting']['memcached_pool']);
            } else {
                $this->logger->debug('Using Filecache as rate limiting cache store.');
                $this->cache = Filecache::get();
            }
        }
    }

    /**
     * WAF middleware invokable class
     *
     * @param ServerRequestInterface $request PSR-7 request
     * @param RequestHandlerInterface $handler PSR-15 request handler
     *
     * @return ResponseInterface
     */
    public function __invoke(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        // Return early if WAF is disabled
        if (!($this->config['enabled'] ?? true)) {
            return $handler->handle($request);
        }

        // Check whitelist first - if matched, bypass all other checks
        if ($this->checkWhitelist($request)) {
            return $handler->handle($request);
        }

        // Check blacklist - if matched, block the request
        if ($this->checkBlacklist($request)) {
            return $this->blockRequest();
        }

        // Check rate limiting
        if ($this->isRateLimited($request)) {
            return $this->rateLimitResponse();
        }

        return $handler->handle($request);
    }

    /**
     * Check if request matches whitelist rules
     */
    private function checkWhitelist(ServerRequestInterface $request): bool
    {
        $rules = $this->config['whitelist'] ?? [];

        foreach ($rules as $rule) {
            if ($this->matchesRule($request, $rule)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if request matches blacklist rules
     */
    private function checkBlacklist(ServerRequestInterface $request): bool
    {
        $rules = $this->config['blacklist'] ?? [];

        foreach ($rules as $rule) {
            if ($this->matchesRule($request, $rule)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a request matches a rule (all conditions must match)
     */
    private function matchesRule(ServerRequestInterface $request, array $rule): bool
    {
        $conditions = $rule['conditions'] ?? [];

        // If no conditions, rule doesn't match
        if (empty($conditions)) {
            return false;
        }

        // All conditions must match for the rule to match
        foreach ($conditions as $condition) {
            if (!$this->matchesCondition($request, $condition)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if a request matches a single condition
     */
    private function matchesCondition(ServerRequestInterface $request, array $condition): bool
    {
        $type = $condition['type'] ?? '';
        $operator = $condition['operator'] ?? 'equals';

        $actualValue = $this->extractValue($request, $condition);

        return $this->compareValues($actualValue, $condition, $operator);
    }

    /**
     * Extract value from request based on condition type
     */
    private function extractValue(ServerRequestInterface $request, array $condition): mixed
    {
        $type = $condition['type'] ?? '';

        switch ($type) {
            case 'header':
                $key = $condition['key'] ?? '';
                $headers = $request->getHeader($key);
                return !empty($headers) ? $headers[0] : null;

            case 'query_param':
                $key = $condition['key'] ?? '';
                $params = $request->getQueryParams();
                return $params[$key] ?? null;

            case 'ip':
                $serverParams = $request->getServerParams();
                return $serverParams['REMOTE_ADDR'] ??
                    $serverParams['HTTP_X_FORWARDED_FOR'] ??
                    $serverParams['HTTP_CLIENT_IP'] ?? null;

            case 'method':
                return $request->getMethod();

            case 'path':
                return $request->getUri()->getPath();

            case 'body':
                $key = $condition['key'] ?? '';
                $body = json_decode($request->getBody()->getContents(), true);
                return $body[$key] ?? null;

            default:
                return null;
        }
    }

    /**
     * Compare values based on operator
     */
    private function compareValues(mixed $actualValue, array $condition, string $operator): bool
    {
        $expectedValue = $condition['value'] ?? null;
        $expectedValues = $condition['values'] ?? [];

        switch ($operator) {
            case 'equals':
                return $actualValue === $expectedValue;

            case 'not_equals':
                return $actualValue !== $expectedValue;

            case 'contains':
                return $actualValue && str_contains($actualValue, $expectedValue);

            case 'not_contains':
                return !$actualValue || !str_contains($actualValue, $expectedValue);

            case 'regex':
                return $actualValue && preg_match($expectedValue, $actualValue);

            case 'in_list':
                return in_array($actualValue, $expectedValues);

            case 'not_in_list':
                return !in_array($actualValue, $expectedValues);

            case 'exists':
                return $actualValue !== null;

            case 'not_exists':
                return $actualValue === null;

            case 'gt':
                return $actualValue > $expectedValue;

            case 'lt':
                return $actualValue < $expectedValue;

            case 'gte':
                return $actualValue >= $expectedValue;

            case 'lte':
                return $actualValue <= $expectedValue;

            default:
                return false;
        }
    }

    /**
     * Check if request is rate limited
     */
    private function isRateLimited(ServerRequestInterface $request): bool
    {
        if (!$this->cache || !($this->config['rate_limiting']['enabled'])) {
            return false;
        }

        $rules = $this->config['rate_limit_rules'] ?? [];

        // Find matching rate limit rule
        foreach ($rules as $rule) {
            $conditions = $rule['conditions'] ?? [];

            // If no conditions or all conditions match, apply this rate limit
            if (empty($conditions) || $this->matchesRule($request, $rule)) {
                $rateLimitConfig = $rule['rate_limit'] ?? [];
                $limit = $rateLimitConfig['limit'] ?? $this->config['rate_limiting']['default_limit'];
                $window = $rateLimitConfig['window'] ?? $this->config['rate_limiting']['default_window'];
                $keyPrefix = $rateLimitConfig['key_prefix'] ?? 'ratelimit';
                $keySource = $rateLimitConfig['key_source'] ?? 'ip';

                $key = $this->buildRateLimitKey($request, $keyPrefix, $keySource);
                $this->logger->debug("Checking rate limit for key: {$key}. Limit: {$limit}, Window: {$window}");

                if ($this->checkRateLimit($key, $limit, $window)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Build rate limit cache key
     */
    private function buildRateLimitKey(ServerRequestInterface $request, string $prefix, string $source): string
    {
        $identifier = '';

        if ($source === 'ip') {
            $serverParams = $request->getServerParams();
            $identifier = $serverParams['REMOTE_ADDR'] ??
                $serverParams['HTTP_X_FORWARDED_FOR'] ??
                $serverParams['HTTP_CLIENT_IP'] ?? 'unknown';
        } elseif (str_starts_with($source, 'header:')) {
            $headerName = substr($source, 7);
            $headers = $request->getHeader($headerName);
            $identifier = !empty($headers) ? $headers[0] : 'unknown';
        } elseif (str_starts_with($source, 'query:')) {
            $paramName = substr($source, 6);
            $params = $request->getQueryParams();
            $identifier = $params[$paramName] ?? 'unknown';
        }
        // MD5 so that we don't have to worry about collisions or spaces in identifiers like 'user id: 123'
        $identifier = md5($identifier);

        return "waf_ratelimit_{$prefix}_{$identifier}";
    }

    /**
     * Check rate limit using cache
     */
    private function checkRateLimit(string $key, int $limit, int $window): bool
    {
        try {
            $cacheItem = $this->cache->getItem($key);

            if ($cacheItem->isHit()) {
                $this->logger->debug("Rate limit cache hit for key: {$key}");
                $data = $cacheItem->get();
                $count = $data['count'] ?? 0;
                $windowStart = $data['window_start'] ?? time();
                $this->logger->debug("Current count: {$count}");

                // Check if we're still within the same window
                $currentTime = time();
                if (($currentTime - $windowStart) >= $window) {
                    // Window has expired, start a new one
                    $this->logger->debug("Rate limit window expired for key: {$key}, starting new window");
                    $cacheItem->set(['count' => 1, 'window_start' => $currentTime]);
                    $cacheItem->expiresAfter($window);
                    $this->cache->save($cacheItem);
                } else {
                    // Still within the same window
                    if ($count >= $limit) {
                        $this->logger->debug("Rate limit exceeded for key: {$key}");
                        return true; // Rate limited
                    }

                    $data['count'] = $count + 1;
                    $remainingTtl = $window - ($currentTime - $windowStart);
                    $cacheItem->set($data);
                    $cacheItem->expiresAfter($remainingTtl);
                    $this->cache->save($cacheItem);
                }
            } else {
                $this->logger->debug("Rate limit cache miss for key: {$key}");
                // First request in this window
                $cacheItem->set(['count' => 1, 'window_start' => time()]);
                $cacheItem->expiresAfter($window);
                $this->cache->save($cacheItem);
            }

            return false;
        } catch (\Exception $e) {
            // If cache fails, allow the request (fail open)
            return false;
        }
    }

    /**
     * Return blocked response
     */
    private function blockRequest(): ResponseInterface
    {
        $response = new Response();
        $response = $response->withAddedHeader('X-Protected-By', 'Subashi by Mamluk');
        $message = $this->config['blocked_response_message'] ?? 'Access Denied';
        $code = $this->config['blocked_response_code'] ?? 403;

        return Http\Response::json($response, $message, $code);
    }

    /**
     * Return rate limit response
     */
    private function rateLimitResponse(): ResponseInterface
    {
        $response = new Response();
        $response = $response->withAddedHeader('X-Protected-By', 'Subashi by Mamluk');
        return Http\Response::json($response, 'Rate limit exceeded', 429);
    }
}