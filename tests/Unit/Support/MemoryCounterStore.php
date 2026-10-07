<?php

namespace Kipchak\Middleware\Subashi\tests\Unit\Support;

use Kipchak\Middleware\Subashi\RateLimit\CounterStore;
use Kipchak\Middleware\Subashi\RateLimit\CounterStoreUnavailable;

/**
 * An in-process counter store with an explicit clock, so window arithmetic can be tested to the second.
 */
final class MemoryCounterStore implements CounterStore
{
    /** @var array<string, array{int, float}> key => [count, expires at] */
    public array $counters = [];
    public float $now = 0.0;
    public bool $down = false;
    public int $calls = 0;

    public function increment(string $key, int $ttl): int
    {
        return $this->add($key, 1, $ttl);
    }

    public function add(string $key, int $amount, int $ttl): int
    {
        $this->guard();
        if (!isset($this->counters[$key]) || $this->counters[$key][1] <= $this->now) {
            $this->counters[$key] = [0, $this->now + $ttl];
        }

        return $this->counters[$key][0] += $amount;
    }

    public function get(string $key): int
    {
        $this->guard();

        return isset($this->counters[$key]) && $this->counters[$key][1] > $this->now ? $this->counters[$key][0] : 0;
    }

    public function decrement(string $key): void
    {
        $this->guard();
        if (isset($this->counters[$key]) && $this->counters[$key][1] > $this->now && $this->counters[$key][0] > 0) {
            $this->counters[$key][0]--;
        }
    }

    private function guard(): void
    {
        $this->calls++;
        if ($this->down) {
            throw new CounterStoreUnavailable('store is down');
        }
    }
}
