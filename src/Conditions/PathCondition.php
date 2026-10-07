<?php

namespace Kipchak\Middleware\Subashi\Conditions;

use Psr\Http\Message\ServerRequestInterface;

class PathCondition implements ConditionTypeHandler
{
    public function getType(): string
    {
        return 'path';
    }

    public function extract(ServerRequestInterface $request, array $condition): mixed
    {
        return $request->getUri()->getPath();
    }
}
