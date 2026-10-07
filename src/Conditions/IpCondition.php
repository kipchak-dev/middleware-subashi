<?php

namespace Kipchak\Middleware\Subashi\Conditions;

use Kipchak\Middleware\Subashi\Network\ClientIp;
use Psr\Http\Message\ServerRequestInterface;

class IpCondition implements ConditionTypeHandler
{
    public function __construct(private readonly ClientIp $clientIp)
    {
    }

    public function getType(): string
    {
        return 'ip';
    }

    public function extract(ServerRequestInterface $request, array $condition): mixed
    {
        return $this->clientIp->resolve($request);
    }
}
