<?php

namespace Kipchak\Middleware\Subashi\Handlers;

use Kipchak\Core\Components\Http;
use Kipchak\Driver\Config\Config;
use Kipchak\Driver\Logger\Logger;
use Kipchak\Middleware\Subashi\Conditions\BodyCondition;
use Kipchak\Middleware\Subashi\Conditions\ConditionTypeHandler;
use Kipchak\Middleware\Subashi\Conditions\HeaderCondition;
use Kipchak\Middleware\Subashi\Conditions\IpCondition;
use Kipchak\Middleware\Subashi\Conditions\MethodCondition;
use Kipchak\Middleware\Subashi\Conditions\PathCondition;
use Kipchak\Middleware\Subashi\Conditions\QueryCondition;
use Kipchak\Middleware\Subashi\Conditions\QueryParamCondition;
use Kipchak\Middleware\Subashi\Network\ClientIp;
use Kipchak\Middleware\Subashi\Network\RemoteAddress;
use Kipchak\Middleware\Subashi\RateLimit\CounterStore;
use Kipchak\Middleware\Subashi\RateLimit\CounterStoreFactory;
use Kipchak\Middleware\Subashi\RateLimit\CounterStoreUnavailable;
use Kipchak\Middleware\Subashi\RateLimit\Decision;
use Kipchak\Middleware\Subashi\RateLimit\RateLimiter;
use Kipchak\Middleware\Subashi\Rules\Operators;
use Kipchak\Middleware\Subashi\Rules\RuleMatcher;
use Psr\Clock\ClockInterface;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Slim\Psr7\Response;

/**
 * The Subashi web application firewall: whitelist, then blacklist, then rate limits.
 *
 * Subashi Pro extends this class, overriding the config file, the client IP resolution, the condition types and
 * the request interception hook, so both editions share one rules engine and one rate limiter.
 *
 * Safe in FrankenPHP worker mode: everything held here is built once from config and never changes per request.
 */
class Firewall implements MiddlewareInterface
{
    /** The config file this edition reads. */
    protected const CONFIG_KEY = 'kipchak.subashi';

    /** Used in log messages and the X-Protected-By header. */
    protected const PRODUCT = 'Subashi';

    protected array $config;
    protected LoggerInterface $logger;
    protected ClientIp $clientIp;
    protected RuleMatcher $rules;
    protected RateLimiter $rateLimiter;

    /**
     * @param ContainerInterface|null $container Accepted for compatibility with `new Firewall($container)`; unused.
     * @param array|null $config Defaults to this edition's config file.
     * @param CounterStore|null $store Defaults to the store named by rate_limiting.store, built on first use.
     */
    public function __construct(
        ?ContainerInterface $container = null,
        ?array $config = null,
        ?LoggerInterface $logger = null,
        ?CounterStore $store = null,
        ?ClockInterface $clock = null,
    ) {
        $this->config = $config ?? Config::get(static::CONFIG_KEY);
        $this->logger = $logger ?? Logger::get();
        $this->clientIp = $this->createClientIp();
        $this->rules = new RuleMatcher($this->conditionHandlers());
        $this->rateLimiter = new RateLimiter(
            $this->config,
            $this->rules,
            $this->clientIp,
            $store !== null
                ? static fn (): CounterStore => $store
                : fn (): CounterStore => CounterStoreFactory::create($this->config['rate_limiting'] ?? [], $this->logger),
            $this->logger,
            static::PRODUCT,
            $clock,
        );
    }

    protected function createClientIp(): ClientIp
    {
        return new RemoteAddress();
    }

    /**
     * @return list<ConditionTypeHandler>
     */
    protected function conditionHandlers(): array
    {
        return [
            new HeaderCondition(),
            new QueryParamCondition(),
            new QueryCondition(),
            new IpCondition($this->clientIp),
            new MethodCondition(),
            new PathCondition(),
            new BodyCondition(),
        ];
    }

    /**
     * Answers a request before any rule runs, even when the firewall is disabled. Subashi Pro uses it for its
     * diagnostics endpoint.
     */
    protected function intercept(ServerRequestInterface $request): ?ResponseInterface
    {
        return null;
    }

    public function __invoke(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        return $this->process($request, $handler);
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $intercepted = $this->intercept($request);
        if ($intercepted !== null) {
            return $intercepted;
        }

        if (!($this->config['enabled'] ?? true)) {
            return $handler->handle($request);
        }

        // Whitelisted requests bypass every other check, rate limits included.
        if ($this->checkWhitelist($request)) {
            return $handler->handle($request);
        }

        $blacklistResult = $this->checkBlacklist($request);
        if ($blacklistResult) {
            return $this->blockRequest($blacklistResult, $request);
        }

        try {
            $decision = $this->rateLimiter->check($request);
        } catch (CounterStoreUnavailable) {
            return $this->unavailableResponse();
        }

        if ($decision !== null && !$decision->allowed) {
            return $this->rateLimitResponse($decision);
        }

        $response = $handler->handle($request);

        return $decision !== null && $this->rateLimiter->sendsHeaders()
            ? $this->withRateLimitHeaders($response, $decision)
            : $response;
    }

    /**
     * Check if request matches whitelist rules
     */
    protected function checkWhitelist(ServerRequestInterface $request): bool
    {
        $rule = $this->rules->firstMatch($request, $this->config['whitelist'] ?? []);
        if ($rule === null) {
            return false;
        }

        $this->logger->debug(static::PRODUCT . ': request whitelisted.', [
            'rule' => $rule['name'] ?? 'unnamed',
            'ip' => $this->clientIp->resolve($request),
            'path' => $request->getUri()->getPath(),
        ]);

        return true;
    }

    /**
     * Check if request matches blacklist rules
     */
    protected function checkBlacklist(ServerRequestInterface $request): bool|array
    {
        $rule = $this->rules->firstMatch($request, $this->config['blacklist'] ?? []);
        if ($rule === null) {
            return false;
        }

        // Rule details for a custom response
        return [
            'matched' => true,
            'name' => $rule['name'] ?? 'unnamed',
            'response_code' => $rule['response_code'] ?? null,
            'response_message' => $rule['response_message'] ?? null,
        ];
    }

    /**
     * Check if a request matches a rule (all conditions must match)
     */
    protected function matchesRule(ServerRequestInterface $request, array $rule): bool
    {
        return $this->rules->matches($request, $rule);
    }

    /**
     * Extract value from request based on condition type
     */
    protected function extractValue(ServerRequestInterface $request, array $condition): mixed
    {
        return $this->rules->extract($request, $condition);
    }

    /**
     * Compare values based on operator
     */
    protected function compareValues(mixed $actualValue, array $condition, string $operator): bool
    {
        return Operators::compare($actualValue, $condition, $operator);
    }

    /**
     * Check if request is rate limited
     */
    protected function isRateLimited(ServerRequestInterface $request): bool
    {
        try {
            $decision = $this->rateLimiter->check($request);
        } catch (CounterStoreUnavailable) {
            return true;
        }

        return $decision !== null && !$decision->allowed;
    }

    /**
     * Build rate limit cache key
     */
    protected function buildRateLimitKey(ServerRequestInterface $request, string $prefix, string $source): string
    {
        return $this->rateLimiter->key($request, $prefix, $source);
    }

    /**
     * Return blocked response
     */
    protected function blockRequest(array|bool $ruleData = false, ?ServerRequestInterface $request = null): ResponseInterface
    {
        // Use rule-specific response code/message if provided, otherwise use defaults
        if (is_array($ruleData)) {
            $code = $ruleData['response_code'] ?? $this->config['blocked_response_code'] ?? 403;
            $message = $ruleData['response_message'] ?? $this->config['blocked_response_message'] ?? 'Access Denied';
        } else {
            $code = $this->config['blocked_response_code'] ?? 403;
            $message = $this->config['blocked_response_message'] ?? 'Access Denied';
        }

        // A firewall that blocks silently is not much use after the fact. This
        // is the one log line that says which rule fired and against whom.
        $this->logger->warning(static::PRODUCT . ': request blocked.', [
            'rule' => is_array($ruleData) ? ($ruleData['name'] ?? 'unnamed') : 'unnamed',
            'ip' => $request ? $this->clientIp->resolve($request) : null,
            'method' => $request?->getMethod(),
            'path' => $request?->getUri()->getPath(),
            'user_agent' => $request ? ($request->getHeader('User-Agent')[0] ?? null) : null,
            'response_code' => $code,
        ]);

        return Http\Response::error($this->protectedResponse(), $message, $code);
    }

    /**
     * Return rate limit response
     */
    protected function rateLimitResponse(?Decision $decision = null): ResponseInterface
    {
        $response = Http\Response::error($this->protectedResponse(), 'Rate limit exceeded', 429);
        if ($decision === null) {
            return $response;
        }

        $response = $response->withHeader('Retry-After', (string) $decision->retryAfter);

        return $this->rateLimiter->sendsHeaders() ? $this->withRateLimitHeaders($response, $decision) : $response;
    }

    /**
     * Returned when the rate limit store is down and rate_limiting.fail_open is false.
     */
    protected function unavailableResponse(): ResponseInterface
    {
        return Http\Response::error($this->protectedResponse(), 'Service temporarily unavailable', 503)
            ->withHeader('Retry-After', '5');
    }

    /**
     * The RateLimit-Policy and RateLimit fields of the IETF draft (draft-ietf-httpapi-ratelimit-headers), for the
     * matching rule with the fewest requests remaining.
     */
    protected function withRateLimitHeaders(ResponseInterface $response, Decision $decision): ResponseInterface
    {
        $name = '"' . addcslashes($decision->rule, '"\\') . '"';

        return $response
            ->withHeader('RateLimit-Policy', "{$name};q={$decision->limit};w={$decision->window}")
            ->withHeader('RateLimit', "{$name};r={$decision->remaining};t={$decision->resetAfter}");
    }

    protected function protectedResponse(): ResponseInterface
    {
        return (new Response())->withAddedHeader('X-Protected-By', static::PRODUCT . ' by Mamluk');
    }
}
