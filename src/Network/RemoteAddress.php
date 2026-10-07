<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Subashi\Network;

use Psr\Http\Message\ServerRequestInterface;

/**
 * The connecting address. Subashi Pro replaces this with a resolver that reads forwarding headers from
 * configured trusted proxies.
 *
 * The X-Forwarded-For and Client-IP server params are only consulted when REMOTE_ADDR is absent, which does not
 * happen behind a web server; they are kept so existing behaviour is unchanged.
 */
final class RemoteAddress implements ClientIp
{
    public function resolve(ServerRequestInterface $request): ?string
    {
        $serverParams = $request->getServerParams();

        return $serverParams['REMOTE_ADDR']
            ?? $serverParams['HTTP_X_FORWARDED_FOR']
            ?? $serverParams['HTTP_CLIENT_IP']
            ?? null;
    }
}
