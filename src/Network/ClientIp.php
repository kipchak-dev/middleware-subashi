<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Subashi\Network;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Decides which address is the client's. The `ip` condition, per-IP rate limiting and the logs all use it.
 */
interface ClientIp
{
    public function resolve(ServerRequestInterface $request): ?string;
}
