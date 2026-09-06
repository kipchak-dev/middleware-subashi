<?php

namespace Kipchak\Middleware\Subashi\tests\Unit\Handlers;

use Kipchak\Middleware\Subashi\tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Every condition type the firewall understands, and what it actually reads.
 */
class ConditionsTest extends TestCase
{
    public function testHeaderReadsTheFirstValueOfANamedHeader(): void
    {
        $firewall = $this->firewall();
        $request = $this->makeRequest(headers: ['X-Api-Key' => 'abc123']);

        $this->assertSame('abc123', $this->call($firewall, 'extractValue', $request, ['type' => 'header', 'key' => 'X-Api-Key']));
        $this->assertNull($this->call($firewall, 'extractValue', $request, ['type' => 'header', 'key' => 'X-Absent']));
    }

    public function testQueryParamReadsOneNamedParameter(): void
    {
        $firewall = $this->firewall();
        $request = $this->makeRequest(uri: 'https://example.com/x?city=Dubai&page=2');

        $this->assertSame('Dubai', $this->call($firewall, 'extractValue', $request, ['type' => 'query_param', 'key' => 'city']));
        $this->assertNull($this->call($firewall, 'extractValue', $request, ['type' => 'query_param', 'key' => 'absent']));
    }

    public function testPathReadsThePathAndNotTheQueryString(): void
    {
        $firewall = $this->firewall();
        $request = $this->makeRequest(uri: 'https://example.com/v1/items?id=1');

        $this->assertSame('/v1/items', $this->call($firewall, 'extractValue', $request, ['type' => 'path']));
    }

    public function testMethodReadsTheHttpMethod(): void
    {
        $firewall = $this->firewall();
        $request = $this->makeRequest(method: 'DELETE');

        $this->assertSame('DELETE', $this->call($firewall, 'extractValue', $request, ['type' => 'method']));
    }

    public function testIpPrefersRemoteAddr(): void
    {
        $firewall = $this->firewall();
        $request = $this->makeRequest(serverParams: [
            'REMOTE_ADDR' => '198.51.100.20',
            'HTTP_X_FORWARDED_FOR' => '203.0.113.9',
        ]);

        $this->assertSame('198.51.100.20', $this->call($firewall, 'extractValue', $request, ['type' => 'ip']));
    }

    public function testUnknownConditionTypeYieldsNull(): void
    {
        $firewall = $this->firewall();

        $this->assertNull($this->call($firewall, 'extractValue', $this->makeRequest(), ['type' => 'nonsense']));
    }

    #[DataProvider('queryStrings')]
    public function testQueryReadsTheWholeQueryStringDecodedOnce(string $uri, ?string $expected): void
    {
        $firewall = $this->firewall();

        $this->assertSame($expected, $this->call($firewall, 'extractValue', $this->makeRequest(uri: $uri), ['type' => 'query']));
    }

    public static function queryStrings(): array
    {
        return [
            'plain' => ['https://example.com/x?page=2&sort=name', 'page=2&sort=name'],
            'percent-encoded spaces' => ['https://example.com/x?id=1%20UNION%20SELECT', 'id=1 UNION SELECT'],
            'plus-encoded spaces' => ['https://example.com/x?id=1+UNION+SELECT', 'id=1 UNION SELECT'],
            'encoded angle brackets' => ['https://example.com/x?q=%3Cscript%3E', 'q=<script>'],
            'no query string' => ['https://example.com/x', null],
            'double-encoded is not decoded twice' => ['https://example.com/x?id=1%2520UNION', 'id=1%20UNION'],
        ];
    }

    public function testBodyReadsANamedTopLevelJsonKey(): void
    {
        $firewall = $this->firewall();
        $request = $this->makeRequest(body: json_encode(['token' => 'abc123', 'n' => 1]));

        $this->assertSame('abc123', $this->call($firewall, 'extractValue', $request, ['type' => 'body', 'key' => 'token']));
        $this->assertNull($this->call($firewall, 'extractValue', $request, ['type' => 'body', 'key' => 'absent']));
    }

    public function testBodyLeavesTheStreamReadableForTheApplication(): void
    {
        // The firewall runs before the controller. If it consumes the stream,
        // the application receives an empty request body.
        $json = json_encode(['token' => 'abc123']);
        $firewall = $this->firewall();
        $request = $this->makeRequest(body: $json);

        $this->call($firewall, 'extractValue', $request, ['type' => 'body', 'key' => 'token']);

        $this->assertSame($json, $request->getBody()->getContents());
    }

    public function testBodyReadsEvenWhenTheStreamWasAlreadyConsumed(): void
    {
        $firewall = $this->firewall();
        $request = $this->makeRequest(body: json_encode(['token' => 'abc123']));
        $request->getBody()->getContents();

        $this->assertSame('abc123', $this->call($firewall, 'extractValue', $request, ['type' => 'body', 'key' => 'token']));
    }

    #[DataProvider('unusableBodies')]
    public function testBodyYieldsNullForAnythingThatIsNotAJsonObject(string $body): void
    {
        $firewall = $this->firewall();
        $request = $this->makeRequest(body: $body);

        $this->assertNull($this->call($firewall, 'extractValue', $request, ['type' => 'body', 'key' => 'token']));
    }

    public static function unusableBodies(): array
    {
        return [
            'not json' => ['this is not json'],
            'json scalar' => ['"a string"'],
            'json null' => ['null'],
            'empty' => [''],
        ];
    }
}
