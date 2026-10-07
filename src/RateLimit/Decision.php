<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Subashi\RateLimit;

/**
 * The outcome of counting one request against one limit.
 */
final readonly class Decision
{
    /**
     * @param int $remaining Requests still allowed in the current window.
     * @param int $resetAfter Seconds until the current window ends.
     * @param int $retryAfter Seconds until a refused client is likely to be allowed again; 0 when allowed.
     */
    public function __construct(
        public string $rule,
        public bool $allowed,
        public int $limit,
        public int $window,
        public int $remaining,
        public int $resetAfter,
        public int $retryAfter,
    ) {
    }
}
