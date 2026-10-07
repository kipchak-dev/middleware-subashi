<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Subashi\RateLimit;

use Kipchak\Middleware\Subashi\Network\ClientIp;
use Kipchak\Middleware\Subashi\Rules\RuleMatcher;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;

/**
 * Applies rate_limit_rules to a request.
 *
 * Every rule whose conditions match (or that has none) counts the request against its own limit, keyed by its
 * key_source. The first rule over its limit refuses the request. When the counter store fails, the request is
 * allowed (rate_limiting.fail_open, the default) or refused, and either way the failure is logged, at most once
 * a minute per worker so an outage does not flood the log.
 */
final class RateLimiter
{
    private const int FAILURE_LOG_INTERVAL = 60;

    private ?CounterStore $store = null;
    private ?SlidingWindow $window = null;
    private int $lastFailureLoggedAt = 0;

    /**
     * @param \Closure(): CounterStore $storeFactory Called on first use, so building the firewall never connects.
     */
    public function __construct(
        private readonly array $config,
        private readonly RuleMatcher $matcher,
        private readonly ClientIp $clientIp,
        private readonly \Closure $storeFactory,
        private readonly LoggerInterface $logger,
        private readonly string $product = 'Subashi',
        private readonly ?ClockInterface $clock = null,
    ) {
    }

    public function enabled(): bool
    {
        return (bool) ($this->config['rate_limiting']['enabled'] ?? false);
    }

    public function failsOpen(): bool
    {
        return (bool) ($this->config['rate_limiting']['fail_open'] ?? true);
    }

    public function sendsHeaders(): bool
    {
        return (bool) ($this->config['rate_limiting']['headers'] ?? false);
    }

    /**
     * Counts the request against every matching rule.
     *
     * @return Decision|null The refusal if any rule refused, otherwise the allowance with the fewest requests
     *                       remaining (for the RateLimit headers); null when no rule applied.
     *
     * @throws CounterStoreUnavailable Only when fail_open is false.
     */
    public function check(ServerRequestInterface $request): ?Decision
    {
        if (!$this->enabled()) {
            return null;
        }

        $tightest = null;
        foreach ($this->config['rate_limit_rules'] ?? [] as $rule) {
            if (!is_array($rule)) {
                continue;
            }
            $conditions = $rule['conditions'] ?? [];
            if (!empty($conditions) && !$this->matcher->matches($request, $rule)) {
                continue;
            }

            $settings = $rule['rate_limit'] ?? [];
            $limit = (int) ($settings['limit'] ?? $this->config['rate_limiting']['default_limit'] ?? 60);
            $window = (int) ($settings['window'] ?? $this->config['rate_limiting']['default_window'] ?? 60);
            $key = $this->key($request, (string) ($settings['key_prefix'] ?? 'ratelimit'), (string) ($settings['key_source'] ?? 'ip'));
            $name = (string) ($rule['name'] ?? 'unnamed');

            try {
                $decision = $this->window()->attempt($key, $name, $limit, $window, $this->now());
            } catch (CounterStoreUnavailable $exception) {
                $this->storeFailed($exception);
                if ($this->failsOpen()) {
                    continue;
                }
                throw $exception;
            }

            if (!$decision->allowed) {
                $this->logger->warning("{$this->product}: request rate limited.", [
                    'rule' => $name,
                    'ip' => $this->clientIp->resolve($request),
                    'path' => $request->getUri()->getPath(),
                    'limit' => $limit,
                    'window' => $window,
                ]);

                return $decision;
            }

            if ($tightest === null || $decision->remaining < $tightest->remaining) {
                $tightest = $decision;
            }
        }

        return $tightest;
    }

    /**
     * The counter key for a request: waf_ratelimit_<prefix>_<md5 of the identifier>. The identifier is hashed so
     * that secrets such as API keys never reach the cache, and so that any value makes a valid key.
     */
    public function key(ServerRequestInterface $request, string $prefix, string $source): string
    {
        $identifier = 'unknown';

        if ($source === 'ip') {
            $identifier = $this->clientIp->resolve($request) ?? 'unknown';
        } elseif (str_starts_with($source, 'header:')) {
            $identifier = $request->getHeader(substr($source, 7))[0] ?? 'unknown';
        } elseif (str_starts_with($source, 'query:')) {
            $value = $request->getQueryParams()[substr($source, 6)] ?? 'unknown';
            $identifier = is_string($value) ? $value : 'unknown';
        }

        // Memcached keys may not contain spaces or control characters, and PSR-6 reserves {}()/\@:
        $prefix = preg_replace('/[^A-Za-z0-9_\-]/', '_', $prefix) ?? 'ratelimit';

        return "waf_ratelimit_{$prefix}_" . md5($identifier);
    }

    private function window(): SlidingWindow
    {
        if ($this->window === null) {
            try {
                $this->store = ($this->storeFactory)();
            } catch (CounterStoreUnavailable $exception) {
                throw $exception;
            } catch (\Throwable $exception) {
                // e.g. the configured Memcached pool does not exist. Tried again on the next request.
                throw new CounterStoreUnavailable('Rate limit store could not be created: ' . $exception->getMessage(), 0, $exception);
            }
            $this->window = new SlidingWindow($this->store);
        }

        return $this->window;
    }

    private function now(): float
    {
        return $this->clock !== null
            ? (float) $this->clock->now()->format('U.u')
            : microtime(true);
    }

    private function storeFailed(CounterStoreUnavailable $exception): void
    {
        if (time() - $this->lastFailureLoggedAt < self::FAILURE_LOG_INTERVAL) {
            return;
        }
        $this->lastFailureLoggedAt = time();

        $this->logger->error(
            $this->failsOpen()
                ? "{$this->product}: rate limit store unavailable; allowing requests (rate_limiting.fail_open is true)."
                : "{$this->product}: rate limit store unavailable; refusing requests (rate_limiting.fail_open is false).",
            ['error' => $exception->getMessage()]
        );
    }
}
