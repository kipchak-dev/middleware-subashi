<?php

namespace Kipchak\Middleware\Subashi\tests\Unit\Handlers;

use Kipchak\Middleware\Subashi\tests\Unit\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

class RateLimitingTest extends TestCase
{
    private const LIMITED = [
        'rate_limiting' => ['enabled' => true, 'default_limit' => 3, 'default_window' => 60],
        'rate_limit_rules' => [[
            'name' => 'Per IP',
            'conditions' => [],
            'rate_limit' => ['limit' => 3, 'window' => 60, 'key_prefix' => 'ip', 'key_source' => 'ip'],
        ]],
    ];

    public function testCountsUpToTheLimitThenBlocks(): void
    {
        $firewall = $this->firewall(self::LIMITED, new ArrayAdapter());
        $request = $this->makeRequest(serverParams: ['REMOTE_ADDR' => '203.0.113.9']);

        $this->assertFalse($this->call($firewall, 'isRateLimited', $request), 'request 1');
        $this->assertFalse($this->call($firewall, 'isRateLimited', $request), 'request 2');
        $this->assertFalse($this->call($firewall, 'isRateLimited', $request), 'request 3');
        $this->assertTrue($this->call($firewall, 'isRateLimited', $request), 'request 4 exceeds a limit of 3');
    }

    public function testCountersAreSeparatePerIdentifier(): void
    {
        $firewall = $this->firewall(self::LIMITED, new ArrayAdapter());
        $one = $this->makeRequest(serverParams: ['REMOTE_ADDR' => '203.0.113.9']);
        $two = $this->makeRequest(serverParams: ['REMOTE_ADDR' => '198.51.100.20']);

        for ($i = 0; $i < 4; $i++) {
            $this->call($firewall, 'isRateLimited', $one);
        }

        $this->assertTrue($this->call($firewall, 'isRateLimited', $one));
        $this->assertFalse($this->call($firewall, 'isRateLimited', $two), 'a second address has its own counter');
    }

    public function testDisabledWhenRateLimitingIsOff(): void
    {
        $firewall = $this->firewall(['rate_limiting' => ['enabled' => false]], new ArrayAdapter());

        $this->assertFalse($this->call($firewall, 'isRateLimited', $this->makeRequest()));
    }

    public function testDisabledWhenThereIsNoCache(): void
    {
        $firewall = $this->firewall(self::LIMITED, null);

        $this->assertFalse($this->call($firewall, 'isRateLimited', $this->makeRequest()));
    }

    public function testThrottleIsLoggedWithTheRuleName(): void
    {
        $firewall = $this->firewall(self::LIMITED, new ArrayAdapter());
        $request = $this->makeRequest(uri: 'https://example.com/v1/x', serverParams: ['REMOTE_ADDR' => '203.0.113.9']);

        for ($i = 0; $i < 4; $i++) {
            $this->call($firewall, 'isRateLimited', $request);
        }

        $warnings = array_values(array_filter($this->logRecords(), fn ($r) => $r['level'] === 'WARNING'));
        $this->assertNotEmpty($warnings);
        $this->assertSame('Subashi: request rate limited.', $warnings[0]['message']);
        $this->assertSame('Per IP', $warnings[0]['context']['rule']);
        $this->assertSame('203.0.113.9', $warnings[0]['context']['ip']);
        $this->assertSame('/v1/x', $warnings[0]['context']['path']);
        $this->assertSame(3, $warnings[0]['context']['limit']);
    }

    public function testFailsOpenWhenTheCacheThrows(): void
    {
        // A Memcached outage should not become an outage of the API.
        $cache = new class extends ArrayAdapter {
            public function getItem($key): \Symfony\Component\Cache\CacheItem
            {
                throw new \RuntimeException('cache is down');
            }
        };

        $firewall = $this->firewall(self::LIMITED, $cache);

        $this->assertFalse($this->call($firewall, 'isRateLimited', $this->makeRequest()));
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('keySources')]
    public function testKeyIsDerivedFromTheConfiguredSource(string $source, array $requestArgs, string $identifier): void
    {
        $firewall = $this->firewall([]);
        $request = $this->makeRequest(...$requestArgs);

        $this->assertSame(
            'waf_ratelimit_test_' . md5($identifier),
            $this->call($firewall, 'buildRateLimitKey', $request, 'test', $source)
        );
    }

    public static function keySources(): array
    {
        return [
            'ip' => ['ip', ['serverParams' => ['REMOTE_ADDR' => '203.0.113.9']], '203.0.113.9'],
            'ip when absent' => ['ip', [], 'unknown'],
            'header' => ['header:apikey', ['headers' => ['apikey' => 'secret-key']], 'secret-key'],
            'header when absent' => ['header:apikey', [], 'unknown'],
            'query' => ['query:token', ['queryParams' => ['token' => 'abc']], 'abc'],
            'query when absent' => ['query:token', [], 'unknown'],
        ];
    }

    public function testIdentifiersAreHashedSoSecretsDoNotReachTheCacheKey(): void
    {
        $firewall = $this->firewall([]);
        $request = $this->makeRequest(headers: ['apikey' => 'a-real-api-key']);

        $key = $this->call($firewall, 'buildRateLimitKey', $request, 'apikey', 'header:apikey');

        $this->assertStringNotContainsString('a-real-api-key', $key);
    }
}
