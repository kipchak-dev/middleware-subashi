<?php

// Increments one counter many times, as one of several concurrent processes. Used by CounterStoresTest.
// Usage: php count-worker.php <store> <key> <increments>

declare(strict_types=1);

use Kipchak\Middleware\Subashi\tests\Integration\Stores;

require __DIR__ . '/../../vendor/autoload.php';

[, $store, $key, $increments] = $argv;

$counter = Stores::make($store);
for ($i = 0; $i < (int) $increments; $i++) {
    $counter->increment($key, 60);
}
