<?php

namespace Kipchak\Middleware\Subashi\tests\Unit\Conditions;

use Kipchak\Middleware\Subashi\Conditions\QueryCondition;
use Kipchak\Middleware\Subashi\tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

class QueryConditionTest extends TestCase
{
    public function testTypeIsQuery(): void
    {
        $this->assertSame('query', (new QueryCondition())->getType());
    }

    public function testExtractsTheWholeQueryString(): void
    {
        $request = $this->makeRequest(uri: 'https://example.com/v1/items?page=2&sort=name');

        $this->assertSame('page=2&sort=name', (new QueryCondition())->extract($request, []));
    }

    public function testReturnsNullWhenThereIsNoQueryString(): void
    {
        $request = $this->makeRequest(uri: 'https://example.com/v1/items');

        $this->assertNull((new QueryCondition())->extract($request, []));
    }

    #[DataProvider('encodedPayloads')]
    public function testDecodesOnceSoRulesCanBeWrittenInPlainForm(string $query, string $expected): void
    {
        $request = $this->makeRequest(uri: 'https://example.com/v1/items?' . $query);

        $this->assertSame($expected, (new QueryCondition())->extract($request, []));
    }

    public static function encodedPayloads(): array
    {
        return [
            'percent-encoded spaces' => ['id=1%20UNION%20SELECT', 'id=1 UNION SELECT'],
            'plus-encoded spaces' => ['id=1+UNION+SELECT', 'id=1 UNION SELECT'],
            'encoded angle brackets' => ['q=%3Cscript%3E', 'q=<script>'],
            'encoded quote' => ['name=O%27Brien', "name=O'Brien"],
            'already plain' => ['id=1 UNION SELECT', 'id=1 UNION SELECT'],
        ];
    }

    public function testDoubleEncodingIsNotDefeated(): void
    {
        // One decode pass by design. %2520 becomes %20, not a space.
        $request = $this->makeRequest(uri: 'https://example.com/v1/items?id=1%2520UNION');

        $this->assertSame('id=1%20UNION', (new QueryCondition())->extract($request, []));
    }
}
