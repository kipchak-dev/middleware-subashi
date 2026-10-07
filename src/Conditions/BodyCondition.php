<?php

namespace Kipchak\Middleware\Subashi\Conditions;

use Psr\Http\Message\ServerRequestInterface;

class BodyCondition implements ConditionTypeHandler
{
    public function getType(): string
    {
        return 'body';
    }

    public function extract(ServerRequestInterface $request, array $condition): mixed
    {
        $key = $condition['key'] ?? '';
        $stream = $request->getBody();

        // The firewall runs before the application, so it must leave the body
        // exactly as it found it. getContents() reads from the current position
        // and does not rewind, so without this a `body` rule would hand the
        // controller an empty request body.
        if (!$stream->isSeekable()) {
            return null;
        }

        $stream->rewind();
        $contents = $stream->getContents();
        $stream->rewind();

        $body = json_decode($contents, true);

        return is_array($body) ? ($body[$key] ?? null) : null;
    }
}
