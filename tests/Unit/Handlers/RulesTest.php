<?php

namespace Kipchak\Middleware\Subashi\tests\Unit\Handlers;

use Kipchak\Middleware\Subashi\tests\Unit\TestCase;

/**
 * How rules combine, and how the list a rule sits in decides the outcome.
 */
class RulesTest extends TestCase
{
    public function testAllConditionsMustMatch(): void
    {
        $firewall = $this->firewall();
        $rule = [
            'name' => 'Scripted clients on the admin path',
            'conditions' => [
                ['type' => 'path', 'operator' => 'contains', 'value' => '/admin'],
                ['type' => 'header', 'key' => 'User-Agent', 'operator' => 'regex', 'value' => '/curl/i'],
            ],
        ];

        $both = $this->makeRequest(uri: 'https://example.com/admin/x', headers: ['User-Agent' => 'curl/8.0']);
        $onlyPath = $this->makeRequest(uri: 'https://example.com/admin/x', headers: ['User-Agent' => 'Mozilla/5.0']);
        $onlyAgent = $this->makeRequest(uri: 'https://example.com/public', headers: ['User-Agent' => 'curl/8.0']);

        $this->assertTrue($this->call($firewall, 'matchesRule', $both, $rule));
        $this->assertFalse($this->call($firewall, 'matchesRule', $onlyPath, $rule));
        $this->assertFalse($this->call($firewall, 'matchesRule', $onlyAgent, $rule));
    }

    public function testARuleWithNoConditionsNeverMatches(): void
    {
        // Otherwise an empty conditions array would block everything.
        $firewall = $this->firewall();

        $this->assertFalse($this->call($firewall, 'matchesRule', $this->makeRequest(), ['conditions' => []]));
        $this->assertFalse($this->call($firewall, 'matchesRule', $this->makeRequest(), ['name' => 'No conditions']));
    }

    public function testWhitelistMatchesOnAnyRule(): void
    {
        $firewall = $this->firewall(['whitelist' => [
            ['name' => 'Health checks', 'conditions' => [['type' => 'path', 'operator' => 'equals', 'value' => '/status']]],
            ['name' => 'Metrics', 'conditions' => [['type' => 'path', 'operator' => 'equals', 'value' => '/metrics']]],
        ]]);

        $this->assertTrue($this->call($firewall, 'checkWhitelist', $this->makeRequest(uri: 'https://example.com/metrics')));
        $this->assertFalse($this->call($firewall, 'checkWhitelist', $this->makeRequest(uri: 'https://example.com/other')));
    }

    public function testBlacklistReturnsTheMatchedRuleDetails(): void
    {
        $firewall = $this->firewall(['blacklist' => [[
            'name' => 'Sensitive file probes',
            'conditions' => [['type' => 'path', 'operator' => 'contains', 'value' => '.env']],
            'response_code' => 404,
            'response_message' => 'Not Found',
        ]]]);

        $result = $this->call($firewall, 'checkBlacklist', $this->makeRequest(uri: 'https://example.com/.env'));

        $this->assertSame('Sensitive file probes', $result['name']);
        $this->assertSame(404, $result['response_code']);
        $this->assertSame('Not Found', $result['response_message']);
    }

    public function testBlacklistReturnsFalseWhenNothingMatches(): void
    {
        $firewall = $this->firewall(['blacklist' => [[
            'name' => 'Sensitive file probes',
            'conditions' => [['type' => 'path', 'operator' => 'contains', 'value' => '.env']],
        ]]]);

        $this->assertFalse($this->call($firewall, 'checkBlacklist', $this->makeRequest(uri: 'https://example.com/ok')));
    }

    public function testAnEmptyRuleListMatchesNothing(): void
    {
        $firewall = $this->firewall([]);

        $this->assertFalse($this->call($firewall, 'checkWhitelist', $this->makeRequest()));
        $this->assertFalse($this->call($firewall, 'checkBlacklist', $this->makeRequest()));
    }

    public function testThereIsNoPerRuleActionOverride(): void
    {
        // The list decides the outcome. A blacklist rule carrying
        // 'action' => 'allow' still blocks; the key is not read at all.
        $firewall = $this->firewall(['blacklist' => [[
            'name' => 'Still blocks',
            'action' => 'allow',
            'conditions' => [['type' => 'path', 'operator' => 'equals', 'value' => '/x']],
        ]]]);

        $result = $this->call($firewall, 'checkBlacklist', $this->makeRequest(uri: 'https://example.com/x'));

        $this->assertIsArray($result);
        $this->assertTrue($result['matched']);
    }

    public function testBlockedResponseUsesRuleOverridesThenDefaults(): void
    {
        $firewall = $this->firewall(['blocked_response_code' => 403, 'blocked_response_message' => 'Access Denied']);

        $withOverride = $this->call(
            $firewall,
            'blockRequest',
            ['matched' => true, 'name' => 'x', 'response_code' => 418, 'response_message' => 'Teapot'],
            $this->makeRequest()
        );
        $this->assertSame(418, $withOverride->getStatusCode());

        $withDefaults = $this->call($firewall, 'blockRequest', ['matched' => true, 'name' => 'x'], $this->makeRequest());
        $this->assertSame(403, $withDefaults->getStatusCode());
    }

    public function testBlockedResponseCarriesTheProtectedByHeader(): void
    {
        $firewall = $this->firewall([]);

        $response = $this->call($firewall, 'blockRequest', false, $this->makeRequest());

        $this->assertSame('Subashi by Mamluk', $response->getHeaderLine('X-Protected-By'));
        $this->assertSame(403, $response->getStatusCode());
    }
}
