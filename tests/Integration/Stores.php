<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Subashi\tests\Integration;

use Kipchak\Middleware\Subashi\RateLimit\CounterStore;
use Kipchak\Middleware\Subashi\RateLimit\LockedCacheCounterStore;
use Kipchak\Middleware\Subashi\RateLimit\MemcachedCounterStore;
use Kipchak\Middleware\Subashi\RateLimit\RedisCounterStore;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Cache\Adapter\MemcachedAdapter;

/**
 * The stores under test, against the containers started by start-services.sh. 'unlocked-psr' is the
 * read-modify-write counting Subashi used before, kept here to show what it loses under concurrency.
 */
final class Stores
{
    public const array ATOMIC = ['memcached-text', 'memcached-binary', 'valkey', 'file'];

    public static function memcachedHost(): ?string
    {
        return getenv('SUBASHI_TEST_MEMCACHED') ?: null;
    }

    public static function valkeyHost(): ?string
    {
        return getenv('SUBASHI_TEST_VALKEY') ?: null;
    }

    public static function make(string $name): CounterStore
    {
        return match ($name) {
            'memcached-text' => new MemcachedCounterStore(self::memcached(false)),
            'memcached-binary' => new MemcachedCounterStore(self::memcached(true)),
            'valkey' => new RedisCounterStore(self::redis(), static fn () => self::redis()),
            'file' => new LockedCacheCounterStore(self::filesystem(), sys_get_temp_dir() . '/subashi-it-locks'),
            'unlocked-psr' => self::unlocked(),
        };
    }

    public static function memcached(bool $binary): \Memcached
    {
        [$host, $port] = explode(':', (string) self::memcachedHost());
        $client = new \Memcached();
        $client->setOption(\Memcached::OPT_BINARY_PROTOCOL, $binary);
        $client->addServer($host, (int) $port);

        return $client;
    }

    public static function redis(): \Redis
    {
        [$host, $port] = explode(':', (string) self::valkeyHost());
        $client = new \Redis();
        $client->connect($host, (int) $port, 2.0);

        return $client;
    }

    private static function filesystem(): FilesystemAdapter
    {
        return new FilesystemAdapter('subashi-it', 0, sys_get_temp_dir() . '/subashi-it-cache');
    }

    /**
     * The previous implementation's counting, over Memcached through PSR-6: read, add one, write back.
     */
    private static function unlocked(): CounterStore
    {
        $cache = new MemcachedAdapter(self::memcached(true), 'subashi-it');

        return new class ($cache) implements CounterStore {
            public function __construct(private MemcachedAdapter $cache)
            {
            }

            public function increment(string $key, int $ttl): int
            {
                $item = $this->cache->getItem($key);
                $count = ($item->isHit() ? (int) $item->get() : 0) + 1;
                $this->cache->save($item->set($count)->expiresAfter($ttl));

                return $count;
            }

            public function add(string $key, int $amount, int $ttl): int
            {
                return $this->increment($key, $ttl);
            }

            public function get(string $key): int
            {
                $item = $this->cache->getItem($key);

                return $item->isHit() ? (int) $item->get() : 0;
            }

            public function decrement(string $key): void
            {
            }
        };
    }
}
