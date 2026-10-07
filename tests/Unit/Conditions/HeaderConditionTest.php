<?php

namespace Kipchak\Middleware\Subashi\tests\Unit\Conditions;

use Kipchak\Middleware\Subashi\Conditions\HeaderCondition;
use Kipchak\Middleware\Subashi\tests\Unit\TestCase;

class HeaderConditionTest extends TestCase
{
    public function testExtractsHeaderValue(): void
    {
        $request = $this->makeRequest(headers: ['X-Test' => 'alpha']);

        $condition = new HeaderCondition();
        $value = $condition->extract($request, ['key' => 'X-Test']);

        $this->assertSame('alpha', $value);
    }
}
