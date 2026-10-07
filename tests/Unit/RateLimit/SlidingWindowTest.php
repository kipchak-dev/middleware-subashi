<?php

namespace Kipchak\Middleware\Subashi\tests\Unit\RateLimit;

use Kipchak\Middleware\Subashi\RateLimit\SlidingWindow;
use Kipchak\Middleware\Subashi\tests\Unit\Support\MemoryCounterStore;
use PHPUnit\Framework\TestCase;

class SlidingWindowTest extends TestCase
{
    private MemoryCounterStore $store;
    private SlidingWindow $window;

    protected function setUp(): void
    {
        $this->store = new MemoryCounterStore();
        $this->window = new SlidingWindow($this->store);
    }

    /** @return list<bool> */
    private function burst(int $requests, float $at, int $limit = 10, int $window = 60): array
    {
        $this->store->now = $at;
        $results = [];
        for ($i = 0; $i < $requests; $i++) {
            $results[] = $this->window->attempt('k', 'rule', $limit, $window, $at)->allowed;
        }

        return $results;
    }

    public function testAllowsUpToTheLimitInAWindow(): void
    {
        $this->assertSame([true, true, true, false], $this->burst(4, 6000.0, limit: 3));
    }

    public function testABoundaryDoesNotLetTwiceTheLimitThrough(): void
    {
        // A fixed window allows 10 at 59s and 10 more at 61s. Here, one second into the next window the
        // previous window still counts almost fully.
        $this->assertCount(10, array_filter($this->burst(10, 6059.0)));
        $this->assertSame([], array_filter($this->burst(10, 6061.0)), 'nothing more fits one second later');
    }

    public function testThePreviousWindowSlidesOutGradually(): void
    {
        $this->burst(10, 6000.0);                                   // window [6000, 6060) is full
        // Halfway into the next window, half of the previous one still overlaps: 5 fit.
        $this->assertCount(5, array_filter($this->burst(10, 6090.0)));
        // Once a whole window has passed with no traffic, the full limit is available again.
        $this->assertCount(10, array_filter($this->burst(12, 6185.0)));
    }

    public function testRefusedRequestsAreNotCounted(): void
    {
        $this->burst(3, 6000.0, limit: 3);
        $this->burst(50, 6001.0, limit: 3);                         // all refused

        $this->assertSame(3, $this->store->get('k.100'), 'only the three allowed requests are counted');
    }

    public function testRemainingAndReset(): void
    {
        $this->store->now = 6015.0;
        $decision = $this->window->attempt('k', 'per-ip', 10, 60, 6015.0);

        $this->assertTrue($decision->allowed);
        $this->assertSame('per-ip', $decision->rule);
        $this->assertSame(9, $decision->remaining);
        $this->assertSame(45, $decision->resetAfter);
        $this->assertSame(0, $decision->retryAfter);
    }

    public function testRetryAfterWhenTheCurrentWindowIsFull(): void
    {
        $this->burst(10, 6000.0);
        $this->store->now = 6050.0;
        $refused = $this->window->attempt('k', 'r', 10, 60, 6050.0);

        // 10s to the next window, then 6s more until 10 * (60 - s) / 60 + 1 <= 10.
        $this->assertFalse($refused->allowed);
        $this->assertSame(16, $refused->retryAfter);

        $this->assertFalse($this->burst(1, 6000.0 + 50 + 15, 10)[0], 'one second early is still refused');
        $this->assertTrue($this->burst(1, 6000.0 + 50 + 16, 10)[0], 'at Retry-After it is allowed');
    }

    public function testRetryAfterWhenThePreviousWindowStillOverlaps(): void
    {
        $this->burst(10, 6000.0);
        $this->assertCount(5, array_filter($this->burst(5, 6090.0)));
        $this->store->now = 6090.0;
        $refused = $this->window->attempt('k', 'r', 10, 60, 6090.0);

        // 5 counted now; another fits once 10 * (30 - t) / 60 + 6 <= 10, i.e. after 6s.
        $this->assertSame(6, $refused->retryAfter);
        $this->assertFalse($this->burst(1, 6095.0)[0]);
        $this->assertTrue($this->burst(1, 6096.0)[0]);
    }

    public function testReleaseUncountsAnAllowedRequest(): void
    {
        $this->burst(3, 6000.0, limit: 3);
        $this->window->release('k', 60, 6010.0);

        $this->assertSame([true, false], $this->burst(2, 6020.0, limit: 3));
    }

    public function testKeysAreIndependent(): void
    {
        $this->store->now = 6000.0;
        $this->window->attempt('a', 'r', 1, 60, 6000.0);

        $this->assertFalse($this->window->attempt('a', 'r', 1, 60, 6000.0)->allowed);
        $this->assertTrue($this->window->attempt('b', 'r', 1, 60, 6000.0)->allowed);
    }
}
