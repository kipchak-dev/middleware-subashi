# Subashi - A WAF Middleware for Kipchak

This Middleware package adds WAF capabilities to your Kipchak API.

The name is inspired by the Arabic word "Subashi" which means "shield" or "protection", reflecting the purpose of the middleware to protect your API from malicious attacks.

It's actually taken from the Ottoman Turkish word *subaşı*, which was the title given to the police chief of a city / town in the Ottoman Empire.

#### Composer Package

`kipchak/middleware-subashi`

## How to use it?

Install it via composer: `composer require kipchak/middleware-subashi`.

Then just ensure you have appropriate settings configured in `kipchak.subashi.php` config file in the root of your project.

For a sample, please see: https://github.com/kipchak-dev/examples/blob/master/config/kipchak.subashi.php.

Full documentation, including rate limiting with each authentication middleware:
<https://kipchak.dev/docs/mw-subashi>

Subashi Pro (Kipchak Enterprise) builds on this package: it uses the same rules engine and rate limiter and
adds trusted-proxy client IP resolution, geolocation and ASN conditions, and diagnostics.

## Upgrading to 1.39

1.39 requires kipchak/core 3.18. Its refusals carry the `status` kipchak/middleware-error gives their code, from
kipchak/core's `ErrorStatus`: a blocked request `INSUFFICIENT_PRIVILEGES` (403, the default `blocked_response_code`), a
rate-limited one `TOO_MANY_REQUESTS` (429) and a counter store outage `SERVER_ERROR` (503), instead of `FORBIDDEN`,
`TOO MANY REQUESTS` and `SERVICE UNAVAILABLE`. A different `blocked_response_code` is named the same way (404 is
`RESOURCE_NOT_FOUND`). Subashi Pro inherits this.

## Upgrading to 1.31

Configuration is unchanged; existing config files work as they are. Behaviour changes:

* **Rate limits hold under concurrency.** Counters used to be read and written back through the cache, so
  simultaneous requests overwrote each other's increments. Under a test load of 3,200 increments from 16
  processes, the old counting kept 450. Counters are now atomic in Memcached (`increment`/`add`) and Valkey
  (Lua), and locked on one host with `file`. Expect limits to bite at the configured number for the first
  time.
* **Sliding windows.** A window is now the last `window` seconds rather than a block starting with the first
  request, so a client can no longer make `limit` requests at the end of one window and `limit` more at the
  start of the next. Counters use new keys, so existing counts start again at zero after the upgrade.
* **`Retry-After`** on every 429. **`RateLimit-Policy` / `RateLimit`** headers with `'headers' => true`.
* **`fail_open`** (default `true`, the previous behaviour) and an `error` log line, at most once a minute per
  worker, when the store cannot be reached. Previously failures were silent.
* **`valkey`** is accepted as a store when the Enterprise Valkey driver is installed (`valkey_pool`).
* **Array query parameters no longer crash rules.** `?q[]=x` made `contains`/`regex` rules on `q`, and a
  `query:q` rate-limit key, throw a `TypeError` (a 500 response). Non-string values now never satisfy
  `contains` or `regex`.
* **`in_list` and absent values.** A header or parameter that is absent is in no list, even one containing
  `''` or `0` (for example a list built from an unset `env()`). Previously the loose comparison matched.
* **`contains` finds `"0"`**, which the previous truthiness check missed. An invalid `regex` pattern never
  matches instead of emitting a warning on every request.
* **No warnings when `rate_limiting` is omitted** from the config.

## Tests

```bash
composer install
./vendor/bin/phpunit
```

The unit tests build a real `Firewall` with its config, logger and counter store injected, and reach its
protected steps (`checkBlacklist`, `isRateLimited`, ...) by reflection (see `tests/Unit/TestCase.php`).

The integration tests run the counter stores against real Memcached (both protocols) and Valkey, including
16 processes counting the same key at once and a Valkey restart:

```bash
tests/Integration/start-services.sh
SUBASHI_TEST_MEMCACHED=127.0.0.1:51211 SUBASHI_TEST_VALKEY=127.0.0.1:56379 \
  SUBASHI_TEST_VALKEY_CONTAINER=subashi-vk ./vendor/bin/phpunit
```

`SampleConfigRulesTest` is the one worth knowing about: it loads the rules that actually ship in
`sample.config.php` and fires realistic attack requests at them, then checks the same rules do **not** match
ordinary API traffic. If a shipped rule stops covering what its name claims, that test fails.

## What is a Kipchak Middleware?

Kipchak Middleware is a standard PHP PSR-15 middleware.

Middleware is a component that sits between the request and response of a web application, allowing for interception
and modification of the request and response data. In the context of Kipchak, middleware can be used to handle errors,
authentication, and other cross-cutting concerns that are common across one or more API endpoints.
