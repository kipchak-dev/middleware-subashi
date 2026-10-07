<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Subashi\tests\Integration;

use Kipchak\Middleware\Subashi\RateLimit\CounterStoreUnavailable;
use Kipchak\Middleware\Subashi\RateLimit\MemcachedCounterStore;
use Kipchak\Middleware\Subashi\RateLimit\RedisCounterStore;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The counter stores against real Memcached and Valkey. Start them with tests/Integration/start-services.sh:
 *
 *   SUBASHI_TEST_MEMCACHED=127.0.0.1:51211 SUBASHI_TEST_VALKEY=127.0.0.1:56379 ./vendor/bin/phpunit
 */
final class CounterStoresTest extends TestCase
{
    private const int PROCESSES = 16;
    private const int INCREMENTS = 200;

    protected function setUp(): void
    {
        if (Stores::memcachedHost() === null || Stores::valkeyHost() === null) {
            $this->markTestSkipped('Set SUBASHI_TEST_MEMCACHED and SUBASHI_TEST_VALKEY to run the store integration tests');
        }
    }

    /** @return iterable<string, array{string}> */
    public static function stores(): iterable
    {
        foreach (Stores::ATOMIC as $store) {
            yield $store => [$store];
        }
    }

    private function key(): string
    {
        return 'subashi-it-' . bin2hex(random_bytes(6));
    }

    #[DataProvider('stores')]
    public function testIncrementGetAndDecrement(string $name): void
    {
        $store = Stores::make($name);
        $key = $this->key();

        $this->assertSame(0, $store->get($key));
        $this->assertSame(1, $store->increment($key, 60));
        $this->assertSame(2, $store->increment($key, 60));
        $this->assertSame(3, $store->increment($key, 60));
        $this->assertSame(3, $store->get($key));
        $store->decrement($key);
        $this->assertSame(2, $store->get($key));
    }

    #[DataProvider('stores')]
    public function testAddCountsSeveralAtOnceAndSetsTheExpiryOnce(string $name): void
    {
        $store = Stores::make($name);
        $key = $this->key();

        $this->assertSame(250, $store->add($key, 250, 1));
        $this->assertSame(251, $store->increment($key, 60), 'a later, longer TTL does not extend the counter');
        sleep(2);
        $this->assertSame(0, $store->get($key));
        $this->assertSame(40, $store->add($key, 40, 60));
    }

    #[DataProvider('stores')]
    public function testCountersExpire(string $name): void
    {
        // The binary-protocol path matters most: increment() creates the key there, and without an explicit
        // expiry the counter would never reset.
        $store = Stores::make($name);
        $key = $this->key();
        $store->increment($key, 1);
        $store->increment($key, 1);

        sleep(2);

        $this->assertSame(0, $store->get($key));
        $this->assertSame(1, $store->increment($key, 1), 'a fresh window starts at 1');
    }

    #[DataProvider('stores')]
    public function testDecrementingAnExpiredCounterDoesNotRecreateIt(string $name): void
    {
        $store = Stores::make($name);
        $key = $this->key();

        $store->decrement($key);

        $this->assertSame(0, $store->get($key));
        $this->assertSame(1, $store->increment($key, 60));
    }

    #[DataProvider('stores')]
    public function testConcurrentProcessesLoseNoIncrements(string $name): void
    {
        $key = $this->key();
        $this->runWorkers($name, $key);

        $this->assertSame(self::PROCESSES * self::INCREMENTS, Stores::make($name)->get($key));
    }

    public function testThePreviousReadModifyWriteCountingLosesIncrements(): void
    {
        // What rate limits leaked before: the same load through PSR-6 read-then-write.
        $key = $this->key();
        $this->runWorkers('unlocked-psr', $key);

        $counted = Stores::make('unlocked-psr')->get($key);
        fwrite(STDERR, sprintf("\n  read-modify-write counted %d of %d increments\n", $counted, self::PROCESSES * self::INCREMENTS));
        $this->assertLessThan(self::PROCESSES * self::INCREMENTS, $counted);
    }

    /**
     * A phpredis client that runs a command while Valkey is down stays broken after Valkey returns ("went
     * away"), which in a long-lived worker would last until the worker restarts. Dropping the connection is not
     * enough to reproduce it (phpredis reconnects by itself), so this stops and starts the container.
     */
    public function testValkeyRecoversAfterAnOutageOnlyWithReconnect(): void
    {
        if (getenv('SUBASHI_TEST_VALKEY_CONTAINER') === false) {
            $this->markTestSkipped('Set SUBASHI_TEST_VALKEY_CONTAINER to the Valkey container name to run the outage test');
        }
        $container = getenv('SUBASHI_TEST_VALKEY_CONTAINER');
        $key = $this->key();
        $recovering = new RedisCounterStore(Stores::redis(), static fn () => Stores::redis());
        $plain = new RedisCounterStore(Stores::redis());
        $recovering->increment($key, 60);
        $plain->increment($key, 60);

        shell_exec('docker stop -t 0 ' . escapeshellarg($container));
        foreach ([$recovering, $plain] as $store) {
            try {
                $store->increment($key, 60);
                $this->fail('Valkey is down; increment should fail');
            } catch (CounterStoreUnavailable) {
            }
        }
        shell_exec('docker start ' . escapeshellarg($container));
        $this->waitForValkey();

        // Valkey restarted empty, so the counter starts again.
        $this->assertSame(1, $recovering->increment($key, 60), 'the store with reconnect recovers');

        $this->expectException(CounterStoreUnavailable::class);
        $plain->increment($key, 60);
    }

    private function waitForValkey(): void
    {
        for ($i = 0; $i < 50; $i++) {
            try {
                Stores::redis()->ping();

                return;
            } catch (\Throwable) {
                usleep(100_000);
            }
        }
        $this->fail('Valkey did not come back');
    }

    public function testMemcachedThatIsDownIsReportedNotTreatedAsZero(): void
    {
        $client = new \Memcached();
        $client->addServer('127.0.0.1', 1);
        $store = new MemcachedCounterStore($client);

        $this->expectException(CounterStoreUnavailable::class);
        $store->increment($this->key(), 60);
    }

    private function runWorkers(string $store, string $key): void
    {
        $processes = [];
        for ($i = 0; $i < self::PROCESSES; $i++) {
            $processes[] = proc_open(
                [PHP_BINARY, __DIR__ . '/count-worker.php', $store, $key, (string) self::INCREMENTS],
                [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
                $pipes,
                null,
                // Inherit the environment: the file store's directories come from TMPDIR.
                getenv() + ['SUBASHI_TEST_MEMCACHED' => Stores::memcachedHost(), 'SUBASHI_TEST_VALKEY' => Stores::valkeyHost()],
            );
            $streams[] = $pipes;
        }
        foreach ($processes as $index => $process) {
            $output = stream_get_contents($streams[$index][1]) . stream_get_contents($streams[$index][2]);
            $this->assertSame(0, proc_close($process), "worker {$index} failed: {$output}");
        }
    }
}
