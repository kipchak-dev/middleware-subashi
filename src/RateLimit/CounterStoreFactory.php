<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Subashi\RateLimit;

use Kipchak\Driver\Filecache\Filecache;
use Kipchak\Driver\Memcached\Memcached;
use Kipchak\Driver\Valkey\Valkey;
use Psr\Log\LoggerInterface;

/**
 * Builds the counter store named by rate_limiting.store:
 *
 *   'memcached'  atomic, fleet-wide, through the Memcached driver's raw connection (memcached_pool)
 *   'valkey'     atomic, fleet-wide, through the Enterprise Valkey driver (valkey_pool)
 *   'file'       the Filecache driver, locked on one host (the default, and what any other value means)
 *
 * A Memcached driver too old to expose its connection still works, through its PSR-6 adapter with host-local
 * locking, and says so once in the log.
 */
final class CounterStoreFactory
{
    public static function create(array $rateLimiting, LoggerInterface $logger): CounterStore
    {
        $store = $rateLimiting['store'] ?? 'file';

        if ($store === 'valkey') {
            if (!class_exists(Valkey::class) || !method_exists(Valkey::class, 'connection')) {
                throw new CounterStoreUnavailable("rate_limiting.store is 'valkey', which needs kipchak/driver-valkey with connection() (Kipchak Enterprise)");
            }
            $pool = $rateLimiting['valkey_pool'] ?? 'cache';

            return new RedisCounterStore(
                Valkey::connection($pool),
                method_exists(Valkey::class, 'reconnect') ? static fn () => Valkey::reconnect($pool) : null,
            );
        }

        if ($store === 'memcached') {
            $pool = $rateLimiting['memcached_pool'] ?? 'cache';
            if (method_exists(Memcached::class, 'connection')) {
                return new MemcachedCounterStore(Memcached::connection($pool));
            }

            $logger->warning('Subashi: this kipchak/driver-memcached has no connection(), so rate limits are only exact on a single host. Update the driver for fleet-wide atomic counting.');

            return new LockedCacheCounterStore(Memcached::get($pool));
        }

        return new LockedCacheCounterStore(Filecache::get());
    }
}
