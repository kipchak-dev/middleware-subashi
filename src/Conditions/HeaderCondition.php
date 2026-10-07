<?php

namespace Kipchak\Middleware\Subashi\Conditions;

use Psr\Http\Message\ServerRequestInterface;

class HeaderCondition implements ConditionTypeHandler
{
    public function getType(): string
    {
        return 'header';
    }

    public function extract(ServerRequestInterface $request, array $condition): mixed
    {
        $key = $condition['key'] ?? '';
        $headers = $request->getHeader($key);
        return !empty($headers) ? $headers[0] : null;
    }
}
