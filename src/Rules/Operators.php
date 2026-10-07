<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Subashi\Rules;

/**
 * Compares the value a condition extracted with the value a rule expects.
 *
 * Request values are not always strings: a query parameter sent as `?q[]=x` arrives as an array. String
 * operators therefore only match strings (and numbers, compared as their string form); anything else never
 * satisfies `contains` or `regex`, and always satisfies `not_contains`. An invalid regular expression in config
 * never matches rather than raising a warning on every request.
 */
final class Operators
{
    public static function compare(mixed $actualValue, array $condition, string $operator): bool
    {
        $expectedValue = $condition['value'] ?? null;
        $expectedValues = $condition['values'] ?? [];

        return match ($operator) {
            'equals' => $actualValue === $expectedValue,
            'not_equals' => $actualValue !== $expectedValue,
            'contains' => self::contains($actualValue, $expectedValue),
            'not_contains' => !self::contains($actualValue, $expectedValue),
            'regex' => self::regex($actualValue, $expectedValue),
            // An absent value is in no list, even one containing '' or 0, which a loose comparison would match.
            'in_list' => $actualValue !== null && is_array($expectedValues) && in_array($actualValue, $expectedValues),
            'not_in_list' => $actualValue === null || !is_array($expectedValues) || !in_array($actualValue, $expectedValues),
            'exists' => $actualValue !== null,
            'not_exists' => $actualValue === null,
            'gt' => $actualValue > $expectedValue,
            'lt' => $actualValue < $expectedValue,
            'gte' => $actualValue >= $expectedValue,
            'lte' => $actualValue <= $expectedValue,
            default => false,
        };
    }

    private static function contains(mixed $actualValue, mixed $expectedValue): bool
    {
        $haystack = self::text($actualValue);
        $needle = self::text($expectedValue);

        return $haystack !== null && $haystack !== '' && $needle !== null && str_contains($haystack, $needle);
    }

    private static function regex(mixed $actualValue, mixed $pattern): bool
    {
        $subject = self::text($actualValue);
        if ($subject === null || $subject === '' || !is_string($pattern)) {
            return false;
        }

        set_error_handler(static fn (): bool => true);
        try {
            return preg_match($pattern, $subject) === 1;
        } finally {
            restore_error_handler();
        }
    }

    private static function text(mixed $value): ?string
    {
        return is_string($value) || is_int($value) || is_float($value) ? (string) $value : null;
    }
}
