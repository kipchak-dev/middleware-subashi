<?php

namespace Kipchak\Middleware\Subashi\Conditions;

use Psr\Http\Message\ServerRequestInterface;

interface ConditionTypeHandler
{
    public function getType(): string;

    public function extract(ServerRequestInterface $request, array $condition): mixed;
}
