<?php

namespace Kipchak\Middleware\Subashi\tests\Unit\Support;

use Psr\Clock\ClockInterface;

final class FixedClock implements ClockInterface
{
    public function __construct(private readonly MemoryCounterStore $store)
    {
    }

    public function now(): \DateTimeImmutable
    {
        return \DateTimeImmutable::createFromFormat('U.u', sprintf('%.6F', $this->store->now));
    }
}
