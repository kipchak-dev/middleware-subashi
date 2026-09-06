<?php

namespace Kipchak\Middleware\Subashi\tests\Unit\Support;

use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Factory\StreamFactory;

trait RequestFactoryTrait
{
    protected function makeRequest(
        string $method = 'GET',
        string $uri = 'https://example.com/',
        array $serverParams = [],
        array $headers = [],
        ?array $queryParams = null,
        ?string $body = null
    ): ServerRequestInterface {
        $request = (new ServerRequestFactory())->createServerRequest($method, $uri, $serverParams);

        foreach ($headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        if ($queryParams !== null) {
            $request = $request->withQueryParams($queryParams);
        }

        if ($body !== null) {
            $request = $request->withBody((new StreamFactory())->createStream($body));
        }

        return $request;
    }
}
