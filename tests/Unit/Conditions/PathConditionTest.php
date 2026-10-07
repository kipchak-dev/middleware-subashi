<?php

namespace Kipchak\Middleware\Subashi\tests\Unit\Conditions;

use Kipchak\Middleware\Subashi\Conditions\PathCondition;
use Kipchak\Middleware\Subashi\tests\Unit\TestCase;

class PathConditionTest extends TestCase
{
    public function testExtractsPath(): void
    {
        $request = $this->makeRequest(uri: 'https://example.com/foo/bar');

        $condition = new PathCondition();
        $value = $condition->extract($request, []);

        $this->assertSame('/foo/bar', $value);
    }
}
