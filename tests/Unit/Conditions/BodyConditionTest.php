<?php

namespace Kipchak\Middleware\Subashi\tests\Unit\Conditions;

use Kipchak\Middleware\Subashi\Conditions\BodyCondition;
use Kipchak\Middleware\Subashi\tests\Unit\TestCase;

class BodyConditionTest extends TestCase
{
    public function testExtractsJsonBodyValue(): void
    {
        $request = $this->makeRequest(body: json_encode(['token' => 'abc123']));

        $condition = new BodyCondition();
        $value = $condition->extract($request, ['key' => 'token']);

        $this->assertSame('abc123', $value);
    }

    public function testLeavesTheBodyReadableForTheApplication(): void
    {
        // The firewall runs before the controller. If it consumes the stream,
        // the application receives an empty request body.
        $json = json_encode(['token' => 'abc123', 'amount' => 42]);
        $request = $this->makeRequest(body: $json);

        (new BodyCondition())->extract($request, ['key' => 'token']);

        $this->assertSame($json, $request->getBody()->getContents());
    }

    public function testReadsTheBodyEvenIfSomethingElseAlreadyConsumedIt(): void
    {
        $json = json_encode(['token' => 'abc123']);
        $request = $this->makeRequest(body: $json);
        $request->getBody()->getContents(); // leave the pointer at the end

        $this->assertSame('abc123', (new BodyCondition())->extract($request, ['key' => 'token']));
    }

    public function testRepeatedExtractionIsStable(): void
    {
        $request = $this->makeRequest(body: json_encode(['token' => 'abc123']));
        $condition = new BodyCondition();

        $this->assertSame('abc123', $condition->extract($request, ['key' => 'token']));
        $this->assertSame('abc123', $condition->extract($request, ['key' => 'token']));
    }

    public function testReturnsNullForAMissingKey(): void
    {
        $request = $this->makeRequest(body: json_encode(['token' => 'abc123']));

        $this->assertNull((new BodyCondition())->extract($request, ['key' => 'nope']));
    }

    public function testReturnsNullForANonJsonBody(): void
    {
        $request = $this->makeRequest(body: 'not json at all');

        $this->assertNull((new BodyCondition())->extract($request, ['key' => 'token']));
    }

    public function testReturnsNullForAJsonScalarBody(): void
    {
        // json_decode('"a string"') returns a string, not an array.
        $request = $this->makeRequest(body: '"a string"');

        $this->assertNull((new BodyCondition())->extract($request, ['key' => 'token']));
    }

    public function testReturnsNullForAnEmptyBody(): void
    {
        $request = $this->makeRequest();

        $this->assertNull((new BodyCondition())->extract($request, ['key' => 'token']));
    }
}
