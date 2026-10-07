<?php

namespace Kipchak\Middleware\Subashi\Conditions;

use Psr\Http\Message\ServerRequestInterface;

class MethodCondition implements ConditionTypeHandler
{
    public function getType(): string
    {
        return 'method';
    }

    public function extract(ServerRequestInterface $request, array $condition): mixed
    {
        return $request->getMethod();
    }
}
