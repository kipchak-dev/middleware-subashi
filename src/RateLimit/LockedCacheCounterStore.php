<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Subashi\RateLimit;

use Psr\Cache\CacheItemPoolInterface;

/**
 * Counters on any PSR-6 cache, made atomic on one host with file locks.
 *
 * A PSR-6 cache can only read a value and write it back, so concurrent workers lose increments. Each
 * read-modify-write here runs under an exclusive flock(), which serialises the worker threads and processes
 * of one host. It cannot serialise other hosts: across a fleet, use Memcached or Valkey, whose counters are
 * atomic on the server.
 *
 * Locks are striped over a fixed set of files so the lock directory does not grow with the number of keys.
 */
final class LockedCacheCounterStore implements CounterStore
{
    private const int STRIPES = 64;

    private readonly string $lockDirectory;

    public function __construct(
        private readonly CacheItemPoolInterface $cache,
        ?string $lockDirectory = null,
    ) {
        $this->lockDirectory = $lockDirectory ?? sys_get_temp_dir() . '/kipchak-subashi-locks';
    }

    public function increment(string $key, int $ttl): int
    {
        return $this->add($key, 1, $ttl);
    }

    public function add(string $key, int $amount, int $ttl): int
    {
        return $this->locked($key, function () use ($key, $amount, $ttl): int {
            $item = $this->cache->getItem($key);
            [$count, $expiresAt] = $this->read($item->isHit() ? $item->get() : null);
            // Sub-second expiry: with whole seconds, a 1-second counter created late in a second would expire
            // almost at once.
            $now = microtime(true);
            if ($expiresAt === null || $expiresAt <= $now) {
                $count = 0;
                $expiresAt = $now + max(1, $ttl);
            }

            $count += max(1, $amount);
            $item->set([$count, $expiresAt]);
            $item->expiresAt((new \DateTimeImmutable())->setTimestamp((int) ceil($expiresAt)));
            $this->cache->save($item);

            return $count;
        });
    }

    public function get(string $key): int
    {
        try {
            $item = $this->cache->getItem($key);
        } catch (\Throwable $exception) {
            throw new CounterStoreUnavailable('Cache read failed: ' . $exception->getMessage(), 0, $exception);
        }
        [$count, $expiresAt] = $this->read($item->isHit() ? $item->get() : null);

        return $expiresAt !== null && $expiresAt > microtime(true) ? $count : 0;
    }

    public function decrement(string $key): void
    {
        $this->locked($key, function () use ($key): void {
            $item = $this->cache->getItem($key);
            [$count, $expiresAt] = $this->read($item->isHit() ? $item->get() : null);
            if ($expiresAt === null || $expiresAt <= microtime(true) || $count <= 0) {
                return;
            }
            $item->set([$count - 1, $expiresAt]);
            $item->expiresAt((new \DateTimeImmutable())->setTimestamp((int) ceil($expiresAt)));
            $this->cache->save($item);
        });
    }

    /**
     * @return array{int, ?float}
     */
    private function read(mixed $value): array
    {
        return is_array($value) && isset($value[0], $value[1]) ? [(int) $value[0], (float) $value[1]] : [0, null];
    }

    private function locked(string $key, \Closure $operation): mixed
    {
        if (!is_dir($this->lockDirectory)) {
            @mkdir($this->lockDirectory, 0700, true);
        }
        $file = $this->lockDirectory . '/' . (crc32($key) % self::STRIPES) . '.lock';
        $handle = @fopen($file, 'c');
        if ($handle === false) {
            throw new CounterStoreUnavailable("Cannot open lock file {$file}");
        }

        try {
            if (!flock($handle, LOCK_EX)) {
                throw new CounterStoreUnavailable("Cannot lock {$file}");
            }

            return $operation();
        } catch (CounterStoreUnavailable $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            throw new CounterStoreUnavailable('Cache counter failed: ' . $exception->getMessage(), 0, $exception);
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }
}
