<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Subashi\RateLimit;

/**
 * Shared counters for rate limiting.
 *
 * increment() must be atomic: many workers on many hosts count the same key at once, and a read followed by a
 * write loses increments, so a limit of 100 lets through however many requests arrive together.
 */
interface CounterStore
{
    /**
     * Adds one to the counter, creating it with a lifetime of $ttl seconds, and returns the new value.
     *
     * @throws CounterStoreUnavailable
     */
    public function increment(string $key, int $ttl): int;

    /**
     * Adds $amount (1 or more) to the counter, creating it with a lifetime of $ttl seconds, and returns the new
     * value. Atomic, like increment(). Used to count units such as tokens or credits.
     *
     * @throws CounterStoreUnavailable
     */
    public function add(string $key, int $amount, int $ttl): int;

    /**
     * The counter's value, or 0 when it does not exist.
     *
     * @throws CounterStoreUnavailable
     */
    public function get(string $key): int;

    /**
     * Takes one off the counter, if it still exists. Used to uncount a request that was refused.
     *
     * @throws CounterStoreUnavailable
     */
    public function decrement(string $key): void;
}
