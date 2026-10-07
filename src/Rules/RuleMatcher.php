<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Subashi\Rules;

use Kipchak\Middleware\Subashi\Conditions\ConditionTypeHandler;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Evaluates rules: a rule matches when every one of its conditions matches, and a rule with no conditions
 * never matches (otherwise an empty rule would block everything).
 */
final class RuleMatcher
{
    /** @var array<string, ConditionTypeHandler> */
    private array $handlers = [];

    /**
     * @param iterable<ConditionTypeHandler> $handlers
     */
    public function __construct(iterable $handlers)
    {
        foreach ($handlers as $handler) {
            $this->handlers[$handler->getType()] = $handler;
        }
    }

    public function matches(ServerRequestInterface $request, array $rule): bool
    {
        $conditions = $rule['conditions'] ?? [];
        if (!is_array($conditions) || $conditions === []) {
            return false;
        }

        foreach ($conditions as $condition) {
            if (!is_array($condition) || !$this->matchesCondition($request, $condition)) {
                return false;
            }
        }

        return true;
    }

    /**
     * The first rule in the list that matches, or null.
     */
    public function firstMatch(ServerRequestInterface $request, array $rules): ?array
    {
        foreach ($rules as $rule) {
            if (is_array($rule) && $this->matches($request, $rule)) {
                return $rule;
            }
        }

        return null;
    }

    public function extract(ServerRequestInterface $request, array $condition): mixed
    {
        $handler = $this->handlers[$condition['type'] ?? ''] ?? null;

        return $handler?->extract($request, $condition);
    }

    private function matchesCondition(ServerRequestInterface $request, array $condition): bool
    {
        return Operators::compare(
            $this->extract($request, $condition),
            $condition,
            (string) ($condition['operator'] ?? 'equals')
        );
    }
}
