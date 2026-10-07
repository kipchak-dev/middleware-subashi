<?php

namespace Kipchak\Middleware\Subashi\tests\Unit\Conditions;

use Kipchak\Middleware\Subashi\Conditions\QueryParamCondition;
use Kipchak\Middleware\Subashi\tests\Unit\TestCase;

class QueryParamConditionTest extends TestCase
{
    public function testExtractsQueryParamValue(): void
    {
        $request = $this->makeRequest(queryParams: ['foo' => 'bar']);

        $condition = new QueryParamCondition();
        $value = $condition->extract($request, ['key' => 'foo']);

        $this->assertSame('bar', $value);
    }
}
