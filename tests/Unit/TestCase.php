<?php

namespace Kipchak\Middleware\Subashi\tests\Unit;

use Kipchak\Middleware\Subashi\Handlers\Firewall;
use Kipchak\Middleware\Subashi\tests\Unit\Support\RequestFactoryTrait;
use Monolog\Handler\TestHandler;
use Monolog\Logger;
use PHPUnit\Framework\TestCase as BaseTestCase;
use Symfony\Component\Cache\Adapter\AdapterInterface;

/**
 * The Firewall reads its config and logger from the container in its
 * constructor, and does all its work in private methods. Rather than stand up a
 * container for every test, these build the object without invoking the
 * constructor and inject what it needs, then reach the private methods by
 * reflection. It keeps the tests pointed at real behaviour instead of a
 * refactored-for-testing copy of it.
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
        $firewall = (new \ReflectionClass(Firewall::class))->newInstanceWithoutConstructor();

        $properties = [
            'config' => $config,
            'logger' => new Logger('test', [$this->logHandler]),
            'cache' => $cache,
        ];

        foreach ($properties as $name => $value) {
            (new \ReflectionProperty(Firewall::class, $name))->setValue($firewall, $value);
        }

        return $firewall;
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
