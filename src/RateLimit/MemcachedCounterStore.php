<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Subashi\RateLimit;

/**
 * Atomic counters on Memcached's increment and add.
 *
 * Works with both protocols. With the binary protocol, increment() can create a missing key itself, and is
 * always given the initial value and expiry when it does: the defaults (0, never expire) would leave a counter
 * that never resets. The text protocol does not support that (php-memcached warns and fails), so there
 * increment() fails on a missing key and add() creates it. add() is atomic, so when two workers race to create
 * a counter, one wins and the other increments.
 */
final readonly class MemcachedCounterStore implements CounterStore
{
    private bool $binary;

    public function __construct(private \Memcached $client)
    {
        $this->binary = (bool) $client->getOption(\Memcached::OPT_BINARY_PROTOCOL);
    }

    public function increment(string $key, int $ttl): int
    {
        return $this->add($key, 1, $ttl);
    }

    public function add(string $key, int $amount, int $ttl): int
    {
        $ttl = max(1, $ttl);
        $amount = max(1, $amount);

        for ($attempt = 0; $attempt < 3; $attempt++) {
            $value = $this->binary
                ? $this->client->increment($key, $amount, $amount, $ttl)
                : $this->client->increment($key, $amount);
            if ($value !== false) {
                return (int) $value;
            }
            $this->assertMissing('increment');

            if ($this->client->add($key, $amount, $ttl)) {
                return $amount;
            }
            $code = $this->client->getResultCode();
            if ($code !== \Memcached::RES_NOTSTORED && $code !== \Memcached::RES_DATA_EXISTS) {
                throw new CounterStoreUnavailable('Memcached add failed: ' . $this->client->getResultMessage());
            }
            // Another worker created it between our increment and add; increment again.
        }

        throw new CounterStoreUnavailable("Memcached counter '{$key}' could not be incremented");
    }

    public function get(string $key): int
    {
        $value = $this->client->get($key);
        if ($value === false) {
            $this->assertMissing('get');

            return 0;
        }

        return (int) $value;
    }

    public function decrement(string $key): void
    {
        if ($this->client->decrement($key, 1) === false) {
            $this->assertMissing('decrement');
        }
    }

    private function assertMissing(string $operation): void
    {
        if ($this->client->getResultCode() !== \Memcached::RES_NOTFOUND) {
            throw new CounterStoreUnavailable("Memcached {$operation} failed: " . $this->client->getResultMessage());
        }
    }
}
