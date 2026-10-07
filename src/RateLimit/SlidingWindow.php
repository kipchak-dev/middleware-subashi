<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Subashi\RateLimit;

/**
 * Sliding-window counter: "at most $limit requests in any $window seconds", approximated from two fixed windows.
 *
 * Each window has its own counter. A request in the current window is weighed against the current count plus
 * the previous window's count scaled by how much of the previous window still overlaps the last $window
 * seconds. A plain fixed window lets up to twice the limit through around a boundary (a full window's worth
 * at the end of one window, another at the start of the next); this does not.
 *
 * Refused requests are uncounted, so a client that keeps retrying while limited is let back in at the rate the
 * limit allows, as before.
 */
final readonly class SlidingWindow
{
    public function __construct(private CounterStore $store)
    {
    }

    /**
     * @throws CounterStoreUnavailable
     */
    public function attempt(string $key, string $rule, int $limit, int $window, float $now): Decision
    {
        $window = max(1, $window);
        $bucket = (int) floor($now / $window);
        $elapsed = $now - $bucket * $window;
        $overlap = ($window - $elapsed) / $window;
        $resetAfter = max(1, (int) ceil($window - $elapsed));

        $currentKey = "{$key}.{$bucket}";
        // Kept for two windows: one as the current window, one as the previous.
        $current = $this->store->increment($currentKey, 2 * $window);
        $previous = $this->store->get($key . '.' . ($bucket - 1));

        $estimate = $previous * $overlap + $current;
        if ($estimate <= $limit) {
            return new Decision($rule, true, $limit, $window, max(0, (int) floor($limit - $estimate)), $resetAfter, 0);
        }

        $this->store->decrement($currentKey);
        $counted = $current - 1;

        return new Decision(
            $rule,
            false,
            $limit,
            $window,
            0,
            $resetAfter,
            self::retryAfter($limit, $window, $elapsed, $previous, $counted),
        );
    }

    /**
     * Uncounts a request that attempt() allowed, for when another limit then refused it.
     *
     * @throws CounterStoreUnavailable
     */
    public function release(string $key, int $window, float $now): void
    {
        $window = max(1, $window);
        $this->store->decrement($key . '.' . (int) floor($now / $window));
    }

    /**
     * Seconds until one more request fits under the limit, assuming no other requests arrive meanwhile.
     */
    private static function retryAfter(int $limit, int $window, float $elapsed, int $previous, int $counted): int
    {
        $untilNextWindow = $window - $elapsed;

        if ($counted + 1 <= $limit && $previous > 0) {
            // Still in this window, once enough of the previous window has slid out of view.
            $wait = $untilNextWindow - ($limit - $counted - 1) * $window / $previous;

            return max(1, (int) ceil($wait));
        }

        // This window is full: wait for the next, and then for enough of this one to slide out of view.
        if ($counted <= 0 || $limit <= 0) {
            return max(1, (int) ceil($untilNextWindow + $window));
        }
        $intoNext = max(0.0, $window * (1 - ($limit - 1) / $counted));

        return max(1, (int) ceil($untilNextWindow + $intoNext));
    }
}
