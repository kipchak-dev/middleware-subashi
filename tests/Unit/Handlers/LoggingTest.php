<?php

namespace Kipchak\Middleware\Subashi\tests\Unit\Handlers;

use Kipchak\Middleware\Subashi\tests\Unit\TestCase;

/**
 * A rule's `name` decides nothing — the list it sits in does that — but it is
 * what identifies the rule afterwards. Blocks used to be silent, which made the
 * firewall impossible to reason about from logs.
 */
class LoggingTest extends TestCase
{
    public function testBlockIsLoggedAtWarningWithTheRuleName(): void
    {
        $firewall = $this->firewall(['blocked_response_code' => 403]);
        $request = $this->makeRequest(
            method: 'POST',
            uri: 'https://example.com/.env',
            serverParams: ['REMOTE_ADDR' => '203.0.113.9'],
            headers: ['User-Agent' => 'sqlmap/1.7']
        );

        $this->call($firewall, 'blockRequest', ['matched' => true, 'name' => 'Sensitive File Access'], $request);

        $records = $this->logRecords();
        $this->assertCount(1, $records);
        $this->assertSame('WARNING', $records[0]['level']);
        $this->assertSame('Subashi: request blocked.', $records[0]['message']);
        $this->assertSame([
            'rule' => 'Sensitive File Access',
            'ip' => '203.0.113.9',
            'method' => 'POST',
            'path' => '/.env',
            'user_agent' => 'sqlmap/1.7',
            'response_code' => 403,
        ], $records[0]['context']);
    }

    public function testAnUnnamedRuleLogsRatherThanErroring(): void
    {
        $firewall = $this->firewall([]);

        $this->call($firewall, 'blockRequest', ['matched' => true], $this->makeRequest());

        $this->assertSame('unnamed', $this->logRecords()[0]['context']['rule']);
    }

    public function testBlockLogsEvenWithoutARequest(): void
    {
        // blockRequest's request argument is optional; the log line should
        // still appear rather than fataling on a null.
        $firewall = $this->firewall([]);

        $this->call($firewall, 'blockRequest', false);

        $records = $this->logRecords();
        $this->assertCount(1, $records);
        $this->assertNull($records[0]['context']['ip']);
    }

    public function testWhitelistMatchIsLoggedAtDebug(): void
    {
        // Routine traffic, so debug rather than warning — but still attributable.
        $firewall = $this->firewall(['whitelist' => [[
            'name' => 'Internal health checks',
            'conditions' => [['type' => 'path', 'operator' => 'equals', 'value' => '/status']],
        ]]]);

        $this->call($firewall, 'checkWhitelist', $this->makeRequest(
            uri: 'https://example.com/status',
            serverParams: ['REMOTE_ADDR' => '10.1.2.3']
        ));

        $records = $this->logRecords();
        $this->assertCount(1, $records);
        $this->assertSame('DEBUG', $records[0]['level']);
        $this->assertSame('Internal health checks', $records[0]['context']['rule']);
        $this->assertSame('10.1.2.3', $records[0]['context']['ip']);
    }

    public function testNothingIsLoggedWhenNoRuleMatches(): void
    {
        $firewall = $this->firewall(['whitelist' => [[
            'name' => 'Health checks',
            'conditions' => [['type' => 'path', 'operator' => 'equals', 'value' => '/status']],
        ]]]);

        $this->call($firewall, 'checkWhitelist', $this->makeRequest(uri: 'https://example.com/other'));

        $this->assertSame([], $this->logRecords());
    }
}
