<?php

namespace Kipchak\Middleware\Subashi\Conditions;

use Psr\Http\Message\ServerRequestInterface;

/**
 * The whole query string, decoded, as one value.
 *
 * `query_param` inspects a single named parameter, which is what you want for a
 * targeted rule. This is the counterpart for scanning: it matches a pattern
 * anywhere in the query string without having to know the parameter names in
 * advance, which is the only workable approach against automated probing.
 *
 * The value is URL-decoded once before matching, so a rule can be written
 * against `union select` rather than having to also spell `union%20select`,
 * `union+select` and the rest. Note that this is a single decode pass: it does
 * not defeat deliberate double-encoding, and it is not meant to.
 */
class QueryCondition implements ConditionTypeHandler
{
    public function getType(): string
    {
        return 'query';
    }

    public function extract(ServerRequestInterface $request, array $condition): mixed
    {
        $query = $request->getUri()->getQuery();

        return $query === '' ? null : urldecode($query);
    }
}
