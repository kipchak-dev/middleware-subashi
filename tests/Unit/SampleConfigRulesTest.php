<?php

namespace Kipchak\Middleware\Subashi\tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Exercises the rules that actually ship in sample.config.php against realistic
 * attack requests.
 *
 * These rules are the first thing anyone turns on, and they were previously
 * named for query-string attacks while only ever inspecting the path - so a
 * rule called "SQL Injection in Query Params" could not match a query string.
 * This locks the shipped set to the traffic it claims to stop.
 */
class SampleConfigRulesTest extends TestCase
{
    private static array $rules;

    public static function setUpBeforeClass(): void
    {
        $config = self::loadSampleConfig();
        self::$rules = [];
        foreach ($config['blacklist'] as $rule) {
            self::$rules[$rule['name']] = $rule;
        }
    }

    /**
     * Config files call env() unqualified. Core declares it inside the
     * Kipchak\Core namespace, so in a real project the global comes from
     * whichever dependency provides a helpers file. Standing one up here keeps
     * the test independent of that.
     */
    private static function loadSampleConfig(): array
    {
        if (!function_exists('env')) {
            eval('function env(string $name, string $default = "") { return getenv($name) ?: $default; }');
        }

        return require __DIR__ . '/../../sample.config.php';
    }

    public function testTheDeadDefaultActionKeyIsGone(): void
    {
        $config = self::loadSampleConfig();

        // It was never read by the Firewall; documenting it implied a
        // deny-by-default mode that did not exist.
        $this->assertArrayNotHasKey('default_action', $config);
    }

    #[DataProvider('attacks')]
    public function testShippedRuleBlocksTheAttack(string $ruleName, string $uri, string $conditionType): void
    {
        $rule = self::$rules[$ruleName] ?? null;
        $this->assertNotNull($rule, "sample.config.php no longer has a rule named '{$ruleName}'");

        $condition = $rule['conditions'][0];
        $this->assertSame($conditionType, $condition['type'], "'{$ruleName}' should inspect {$conditionType}");

        $value = $this->extract($condition['type'], $this->makeRequest(uri: $uri));
        $this->assertNotNull($value, "'{$ruleName}' extracted nothing from {$uri}");
        $this->assertSame(1, preg_match($condition['value'], $value), "'{$ruleName}' did not match {$uri}");
    }

    public static function attacks(): array
    {
        return [
            // The three that used to be misnamed, now matching real query strings.
            'sqli in query' => [
                'OWASP A03: SQL Injection in Query String',
                'https://example.com/v1/items?id=1%20UNION%20SELECT%20password%20FROM%20users',
                'query',
            ],
            'sqli in query, plus-encoded' => [
                'OWASP A03: SQL Injection in Query String',
                'https://example.com/v1/items?id=1+union+select+1',
                'query',
            ],
            'xss in query' => [
                'OWASP A03: XSS in Query String',
                'https://example.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E',
                'query',
            ],
            'ssrf in query' => [
                'OWASP A10: SSRF in Query String',
                'https://example.com/fetch?url=http://169.254.169.254/latest/meta-data/',
                'query',
            ],
            // Path rules, now honestly named.
            'traversal in path' => [
                'OWASP A01: Path Traversal Attack',
                'https://example.com/static/../../etc/passwd',
                'path',
            ],
            'sqli in path' => [
                'OWASP A03: SQL Injection in Path',
                'https://example.com/items/union%20select%201',
                'path',
            ],
            'sensitive file' => [
                'OWASP A05: Sensitive File Access',
                'https://example.com/.env',
                'path',
            ],
        ];
    }

    public function testScannerUserAgentIsBlocked(): void
    {
        $rule = self::$rules['OWASP A06: Known Vulnerability Scanner'];
        $condition = $rule['conditions'][0];
        $request = $this->makeRequest(headers: ['User-Agent' => 'sqlmap/1.7#stable']);

        $value = $this->call($this->firewall(), 'extractValue', $request, $condition);

        $this->assertSame(1, preg_match($condition['value'], $value));
    }

    public function testSensitiveFileAccessAnswers404NotForbidden(): void
    {
        // A 403 confirms the file is there. A 404 tells a scanner nothing.
        $this->assertSame(404, self::$rules['OWASP A05: Sensitive File Access']['response_code']);
    }

    #[DataProvider('benignRequests')]
    public function testOrdinaryTrafficIsNotCaught(string $uri): void
    {
        foreach (self::$rules as $name => $rule) {
            foreach ($rule['conditions'] as $condition) {
                if (!in_array($condition['type'], ['path', 'query'], true)) {
                    continue;
                }
                if (($condition['operator'] ?? '') !== 'regex') {
                    continue;
                }

                $value = $this->extract($condition['type'], $this->makeRequest(uri: $uri));
                if ($value === null) {
                    continue;
                }

                $this->assertSame(0, preg_match($condition['value'], $value), "'{$name}' false-positives on {$uri}");
            }
        }
    }

    public static function benignRequests(): array
    {
        return [
            'listing with paging' => ['https://example.com/v1/timings?page=2&per_page=50'],
            'iso date filter' => ['https://example.com/v1/timings?date=2026-09-07&city=Dubai'],
            'nested resource' => ['https://example.com/v1/users/42/preferences'],
        ];
    }

    private function extract(string $type, $request): mixed
    {
        return $this->call($this->firewall(), 'extractValue', $request, ['type' => $type]);
    }
}
