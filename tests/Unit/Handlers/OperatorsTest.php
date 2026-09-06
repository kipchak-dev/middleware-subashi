<?php

namespace Kipchak\Middleware\Subashi\tests\Unit\Handlers;

use Kipchak\Middleware\Subashi\tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Every operator, including how each behaves when the condition extracted
 * nothing — which is the case that decides whether an absent header opens a
 * hole or closes one.
 */
class OperatorsTest extends TestCase
{
    #[DataProvider('comparisons')]
    public function testOperator(mixed $actual, string $operator, array $condition, bool $expected): void
    {
        $firewall = $this->firewall();

        $this->assertSame($expected, $this->call($firewall, 'compareValues', $actual, $condition, $operator));
    }

    public static function comparisons(): array
    {
        return [
            'equals matches' => ['GET', 'equals', ['value' => 'GET'], true],
            'equals is strict about type' => ['403', 'equals', ['value' => 403], false],
            'equals misses' => ['GET', 'equals', ['value' => 'POST'], false],
            'not_equals matches' => ['GET', 'not_equals', ['value' => 'POST'], true],

            'contains matches' => ['/admin/panel', 'contains', ['value' => 'admin'], true],
            'contains misses' => ['/public', 'contains', ['value' => 'admin'], false],
            'contains on null is false' => [null, 'contains', ['value' => 'admin'], false],
            'not_contains on null is true' => [null, 'not_contains', ['value' => 'admin'], true],

            'regex matches' => ['sqlmap/1.7', 'regex', ['value' => '/sqlmap/i'], true],
            'regex misses' => ['curl/8.0', 'regex', ['value' => '/sqlmap/i'], false],
            'regex on null is false' => [null, 'regex', ['value' => '/sqlmap/i'], false],

            'in_list matches' => ['192.0.2.1', 'in_list', ['values' => ['192.0.2.1', '198.51.100.20']], true],
            'in_list misses' => ['203.0.113.9', 'in_list', ['values' => ['192.0.2.1', '198.51.100.20']], false],
            'not_in_list matches' => ['203.0.113.9', 'not_in_list', ['values' => ['192.0.2.1', '198.51.100.20']], true],

            'exists on a value' => ['anything', 'exists', [], true],
            'exists on null' => [null, 'exists', [], false],
            'not_exists on null' => [null, 'not_exists', [], true],
            'not_exists on a value' => ['anything', 'not_exists', [], false],

            'gt' => [10, 'gt', ['value' => 5], true],
            'lt' => [3, 'lt', ['value' => 5], true],
            'gte on equal' => [5, 'gte', ['value' => 5], true],
            'lte on equal' => [5, 'lte', ['value' => 5], true],

            'unknown operator never matches' => ['x', 'nonsense', ['value' => 'x'], false],
        ];
    }

    public function testAnAbsentValueDoesNotSatisfyInList(): void
    {
        // in_list uses a loose in_array, so this pins the behaviour that a
        // condition which extracted nothing - an absent header, an IP the
        // firewall could not determine - cannot match a list of values.
        $firewall = $this->firewall();

        $this->assertFalse($this->call($firewall, 'compareValues', null, ['values' => ['192.0.2.1']], 'in_list'));
    }

    public function testNotInListIsTrueForAnAbsentValue(): void
    {
        // The corollary: a "not in list" rule matches when the value is absent.
        // A blacklist rule of the form "block anything whose API key is not in
        // this list" therefore also blocks requests that sent no key at all -
        // usually what you want, but worth knowing before you write one.
        $firewall = $this->firewall();

        $this->assertTrue($this->call($firewall, 'compareValues', null, ['values' => ['192.0.2.1']], 'not_in_list'));
    }
}
