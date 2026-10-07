<?php

namespace Kipchak\Middleware\Subashi\tests\Unit\Conditions;

use Kipchak\Middleware\Subashi\Conditions\MethodCondition;
use Kipchak\Middleware\Subashi\tests\Unit\TestCase;

class MethodConditionTest extends TestCase
{
    public function testExtractsMethod(): void
    {
        $request = $this->makeRequest(method: 'POST');

        $condition = new MethodCondition();
        $value = $condition->extract($request, []);

        $this->assertSame('POST', $value);
    }
}
