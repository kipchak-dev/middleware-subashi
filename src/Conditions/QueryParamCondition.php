<?php

namespace Kipchak\Middleware\Subashi\Conditions;

use Psr\Http\Message\ServerRequestInterface;

class QueryParamCondition implements ConditionTypeHandler
{
    public function getType(): string
    {
        return 'query_param';
    }

    public function extract(ServerRequestInterface $request, array $condition): mixed
    {
        $key = $condition['key'] ?? '';
        $params = $request->getQueryParams();
        return $params[$key] ?? null;
    }
}
