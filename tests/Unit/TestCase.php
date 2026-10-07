<?php

namespace Kipchak\Middleware\Subashi\tests\Unit;

use Kipchak\Middleware\Subashi\Handlers\Firewall;
use Kipchak\Middleware\Subashi\RateLimit\LockedCacheCounterStore;
use Kipchak\Middleware\Subashi\tests\Unit\Support\RequestFactoryTrait;
use Monolog\Handler\TestHandler;
use Monolog\Logger;
use PHPUnit\Framework\TestCase as BaseTestCase;
use Symfony\Component\Cache\Adapter\AdapterInterface;

/**
 * Builds a real Firewall with the config, logger and counter store injected, and reaches its protected steps
 * (checkBlacklist, isRateLimited, ...) by reflection, so each test pins one step of the real request path.
 */
abstract class TestCase extends BaseTestCase
{
    use RequestFactoryTrait;

    protected TestHandler $logHandler;

    protected function setUp(): void
    {
        $this->logHandler = new TestHandler();
    }

    protected function firewall(array $config = [], ?AdapterInterface $cache = null): Firewall
    {
        // With no cache, the store named in config is built on first use; outside an API that fails, and the
        // firewall fails open, as it does when a real store is down.
        return new Firewall(
            config: $config,
            logger: new Logger('test', [$this->logHandler]),
            store: $cache === null ? null : new LockedCacheCounterStore($cache, sys_get_temp_dir() . '/subashi-test-locks'),
        );
    }

    protected function call(Firewall $firewall, string $method, ...$args): mixed
    {
        return (new \ReflectionMethod(Firewall::class, $method))->invoke($firewall, ...$args);
    }

    /**
     * @return list<array{level: string, message: string, context: array}>
     */
    protected function logRecords(): array
    {
        return array_map(
            fn ($record) => [
                'level' => $record->level->getName(),
                'message' => $record->message,
                'context' => $record->context,
            ],
            $this->logHandler->getRecords()
        );
    }
}
