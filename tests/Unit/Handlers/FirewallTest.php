<?php

namespace Kipchak\Middleware\Subashi\tests\Unit\Handlers;

use Kipchak\Middleware\Subashi\Handlers\Firewall;
use Kipchak\Middleware\Subashi\tests\Unit\Support\FixedClock;
use Kipchak\Middleware\Subashi\tests\Unit\Support\MemoryCounterStore;
use Kipchak\Middleware\Subashi\tests\Unit\TestCase;
use Monolog\Logger;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Factory\ResponseFactory;

/**
 * The firewall through its real entry point, process(), as Slim calls it.
 */
class FirewallTest extends TestCase
{
    private MemoryCounterStore $store;
    private int $handled = 0;

    protected function setUp(): void
    {
        parent::setUp();
        $this->store = new MemoryCounterStore();
        $this->store->now = 6000.0;
    }

    private function make(array $config): Firewall
    {
        return new Firewall(
            config: $config,
            logger: new Logger('test', [$this->logHandler]),
            store: $this->store,
            clock: new FixedClock($this->store),
        );
    }

    private function handle(Firewall $firewall, ServerRequestInterface $request): ResponseInterface
    {
        $handler = new class ($this->handled) implements RequestHandlerInterface {
            public function __construct(private int &$handled)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->handled++;

                return (new ResponseFactory())->createResponse(200);
            }
        };

        return $firewall->process($request, $handler);
    }

    private static function limited(array $rateLimiting = [], array $ruleLimit = []): array
    {
        return [
            'rate_limiting' => $rateLimiting + ['enabled' => true, 'default_limit' => 2, 'default_window' => 60],
            'rate_limit_rules' => [[
                'name' => 'Per IP',
                'conditions' => [],
                'rate_limit' => $ruleLimit + ['key_prefix' => 'ip', 'key_source' => 'ip'],
            ]],
        ];
    }

    public function testAnArrayQueryParameterNoLongerCrashesStringRules(): void
    {
        // ?q[]=x arrives as an array; contains and regex used to throw a TypeError, i.e. a 500.
        $firewall = $this->make(['blacklist' => [
            ['name' => 'SQLi', 'conditions' => [['type' => 'query_param', 'key' => 'q', 'operator' => 'contains', 'value' => 'union']]],
            ['name' => 'XSS', 'conditions' => [['type' => 'query_param', 'key' => 'q', 'operator' => 'regex', 'value' => '/<script/i']]],
        ]]);

        $response = $this->handle($firewall, $this->makeRequest(uri: 'https://example.com/?q[]=x', queryParams: ['q' => ['union']]));

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame(403, $this->handle($firewall, $this->makeRequest(queryParams: ['q' => '1 union select']))->getStatusCode());
    }

    public function testAnArrayQueryParameterAsARateLimitKeyDoesNotCrash(): void
    {
        $firewall = $this->make(self::limited(ruleLimit: ['key_source' => 'query:apikey']));

        $this->assertSame(200, $this->handle($firewall, $this->makeRequest(queryParams: ['apikey' => ['a', 'b']]))->getStatusCode());
    }

    public function testAMissingRateLimitingBlockRaisesNoWarnings(): void
    {
        set_error_handler(function (int $level, string $message): never {
            throw new \ErrorException($message, 0, $level);
        });
        try {
            $firewall = new Firewall(config: ['blacklist' => []], logger: new Logger('test', [$this->logHandler]));
            $response = $this->handle($firewall, $this->makeRequest());
        } finally {
            restore_error_handler();
        }

        $this->assertSame(200, $response->getStatusCode());
    }

    public function testRefusalsCarryTheStatusesMiddlewareErrorUses(): void
    {
        $status = static fn (ResponseInterface $response): array => [$response->getStatusCode(), json_decode((string) $response->getBody(), true)['status']];

        $firewall = $this->make(self::limited());
        $request = $this->makeRequest(serverParams: ['REMOTE_ADDR' => '203.0.113.9']);
        $this->handle($firewall, $request);
        $this->handle($firewall, $request);
        $this->assertSame([429, 'TOO_MANY_REQUESTS'], $status($this->handle($firewall, $request)));

        $blocked = $this->make(['blacklist' => [
            ['name' => 'SQLi', 'conditions' => [['type' => 'query_param', 'key' => 'q', 'operator' => 'contains', 'value' => 'union']]],
        ]]);
        $this->assertSame([403, 'INSUFFICIENT_PRIVILEGES'], $status($this->handle($blocked, $this->makeRequest(queryParams: ['q' => '1 union select']))));

        // Control: what 1.38 and earlier wrote, through Response::json().
        $label = static fn (int $code): string => json_decode((string) \Kipchak\Core\Components\Http\Response::json(new \Slim\Psr7\Response(), '', $code)->getBody(), true)['status'];
        $this->assertSame(['TOO MANY REQUESTS', 'FORBIDDEN'], [$label(429), $label(403)]);
    }

    public function testRateLimitedResponseCarriesRetryAfter(): void
    {
        $firewall = $this->make(self::limited());
        $request = $this->makeRequest(serverParams: ['REMOTE_ADDR' => '203.0.113.9']);

        $this->handle($firewall, $request);
        $this->handle($firewall, $request);
        $response = $this->handle($firewall, $request);

        $this->assertSame(429, $response->getStatusCode());
        // 60s to the next window, then 30s until 2 * (60 - s) / 60 + 1 <= 2.
        $this->assertSame('90', $response->getHeaderLine('Retry-After'));
        $this->assertSame('Subashi by Mamluk', $response->getHeaderLine('X-Protected-By'));
        $this->assertSame('', $response->getHeaderLine('RateLimit'), 'RateLimit headers are opt-in');
        $this->assertSame(2, $this->handled);
    }

    public function testRateLimitHeadersWhenEnabled(): void
    {
        $firewall = $this->make(self::limited(['headers' => true]));
        $request = $this->makeRequest(serverParams: ['REMOTE_ADDR' => '203.0.113.9']);

        $first = $this->handle($firewall, $request);
        $this->assertSame('"Per IP";q=2;w=60', $first->getHeaderLine('RateLimit-Policy'));
        $this->assertSame('"Per IP";r=1;t=60', $first->getHeaderLine('RateLimit'));

        $this->handle($firewall, $request);
        $refused = $this->handle($firewall, $request);
        $this->assertSame('"Per IP";r=0;t=60', $refused->getHeaderLine('RateLimit'));
    }

    public function testHeadersDescribeTheRuleWithTheFewestRequestsRemaining(): void
    {
        $config = self::limited(['headers' => true]);
        $config['rate_limit_rules'][] = [
            'name' => 'Per key',
            'conditions' => [],
            'rate_limit' => ['limit' => 100, 'window' => 3600, 'key_prefix' => 'key', 'key_source' => 'header:apikey'],
        ];

        $response = $this->handle($this->make($config), $this->makeRequest(headers: ['apikey' => 'k']));

        $this->assertStringStartsWith('"Per IP"', $response->getHeaderLine('RateLimit'));
    }

    public function testWhitelistedRequestsAreNotCounted(): void
    {
        $config = self::limited();
        $config['whitelist'] = [['name' => 'Health', 'conditions' => [['type' => 'path', 'operator' => 'equals', 'value' => '/status']]]];
        $firewall = $this->make($config);

        for ($i = 0; $i < 5; $i++) {
            $this->assertSame(200, $this->handle($firewall, $this->makeRequest(uri: 'https://example.com/status'))->getStatusCode());
        }
        $this->assertSame(0, $this->store->calls);
    }

    public function testAStoreOutageFailsOpenByDefaultAndIsLoggedOncePerMinute(): void
    {
        $this->store->down = true;
        $firewall = $this->make(self::limited());

        for ($i = 0; $i < 5; $i++) {
            $this->assertSame(200, $this->handle($firewall, $this->makeRequest())->getStatusCode());
        }

        $errors = array_values(array_filter($this->logRecords(), fn ($r) => $r['level'] === 'ERROR'));
        $this->assertCount(1, $errors);
        $this->assertStringContainsString('allowing requests', $errors[0]['message']);
        $this->assertSame('store is down', $errors[0]['context']['error']);
    }

    public function testAStoreOutageCanFailClosed(): void
    {
        $this->store->down = true;
        $firewall = $this->make(self::limited(['fail_open' => false]));

        $response = $this->handle($firewall, $this->makeRequest());

        $this->assertSame(503, $response->getStatusCode());
        $this->assertSame(0, $this->handled);
        $this->assertStringContainsString('refusing requests', $this->logRecords()[0]['message']);
    }

    public function testAnUnbuildableStoreFailsOpenRatherThanErroring(): void
    {
        // No store injected: the configured one is built on first use, which outside an API cannot work.
        $firewall = new Firewall(config: self::limited(['store' => 'memcached']), logger: new Logger('test', [$this->logHandler]));

        $this->assertSame(200, $this->handle($firewall, $this->makeRequest())->getStatusCode());
        $this->assertStringContainsString('could not be created', $this->logRecords()[0]['context']['error']);
    }

    public function testKeyPrefixesAreMadeSafeForEveryStore(): void
    {
        $firewall = $this->make([]);

        $key = $this->call($firewall, 'buildRateLimitKey', $this->makeRequest(), 'my api: keys', 'ip');

        $this->assertMatchesRegularExpression('/^waf_ratelimit_my_api__keys_[0-9a-f]{32}$/', $key);
    }

    public function testTheContainerArgumentIsStillAccepted(): void
    {
        $container = $this->createStub(\Psr\Container\ContainerInterface::class);
        $firewall = new Firewall($container, ['enabled' => false], new Logger('test'));

        $this->assertSame(200, $this->handle($firewall, $this->makeRequest())->getStatusCode());
    }
}
