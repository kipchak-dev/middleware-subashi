<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Subashi\RateLimit;

/**
 * Atomic counters on Valkey or Redis, through phpredis, Relay or Predis.
 *
 * INCR and the EXPIRE that gives a new counter its lifetime run in one Lua script, so a worker that dies
 * between them cannot leave a counter that never expires.
 *
 * A phpredis client that fails a command while the server is down stays broken after the server returns, which
 * in a long-lived worker would mean every request fails until the worker restarts. Given a $reconnect callback,
 * the store swaps in a fresh client and retries once after any failure.
 */
final class RedisCounterStore implements CounterStore
{
    // A counter that has no expiry yet (TTL -1) was just created by this INCRBY.
    private const string INCREMENT = <<<'LUA'
        local value = redis.call('INCRBY', KEYS[1], ARGV[2])
        if redis.call('TTL', KEYS[1]) == -1 then
            redis.call('EXPIRE', KEYS[1], ARGV[1])
        end
        return value
        LUA;

    // DECR on a key that has just expired would recreate it at -1 with no expiry.
    private const string DECREMENT = <<<'LUA'
        if redis.call('EXISTS', KEYS[1]) == 1 then
            return redis.call('DECR', KEYS[1])
        end
        return 0
        LUA;

    /**
     * @param (\Closure(): (\Redis|\RedisCluster|\Relay\Relay|\Relay\Cluster|\Predis\ClientInterface))|null $reconnect
     */
    public function __construct(
        private \Redis|\RedisCluster|\Relay\Relay|\Relay\Cluster|\Predis\ClientInterface $client,
        private readonly ?\Closure $reconnect = null,
    ) {
    }

    public function increment(string $key, int $ttl): int
    {
        return $this->add($key, 1, $ttl);
    }

    public function add(string $key, int $amount, int $ttl): int
    {
        return (int) $this->withRetry(fn () => $this->evaluate(self::INCREMENT, $key, (string) max(1, $ttl), (string) max(1, $amount)));
    }

    public function get(string $key): int
    {
        return (int) $this->withRetry(fn () => $this->client->get($key));
    }

    public function decrement(string $key): void
    {
        $this->withRetry(fn () => $this->evaluate(self::DECREMENT, $key));
    }

    private function evaluate(string $script, string $key, string ...$arguments): mixed
    {
        if ($this->client instanceof \Predis\ClientInterface) {
            return $this->client->eval($script, 1, $key, ...$arguments);
        }

        $result = $this->client->eval($script, [$key, ...$arguments], 1);
        if ($result === false && method_exists($this->client, 'getLastError') && $this->client->getLastError() !== null) {
            $error = $this->client->getLastError();
            $this->client->clearLastError();
            throw new \RuntimeException($error);
        }

        return $result;
    }

    private function withRetry(\Closure $operation): mixed
    {
        try {
            return $operation();
        } catch (\Throwable $exception) {
            if ($this->reconnect === null) {
                throw new CounterStoreUnavailable('Valkey counter failed: ' . $exception->getMessage(), 0, $exception);
            }
        }

        try {
            $this->client = ($this->reconnect)();

            return $operation();
        } catch (\Throwable $exception) {
            throw new CounterStoreUnavailable('Valkey counter failed after reconnecting: ' . $exception->getMessage(), 0, $exception);
        }
    }
}
