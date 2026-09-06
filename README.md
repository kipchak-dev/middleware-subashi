# Subashi - A WAF Middleware for Kipchak

This Middleware package adds WAF capabilities to your Kipchak API.

The name is inspired by the Arabic word "Subashi" which means "shield" or "protection", reflecting the purpose of the middleware to protect your API from malicious attacks.

It's actually taken from the Ottoman Turkish word *subaşı*, which was the title given to the police chief of a city / town in the Ottoman Empire.

#### Composer Package

`kipchak/middleware-subashi`

## How to use it?

Install it via composer: `composer require kipchak/middleware-subashi`.

Then just ensure you have appropriate settings configured in `kipchak.subashi.php` config file in the root of your project.

For a sample, please see: https://1x.ax/mamluk/kipchak/starter/~files/master/config/kipchak.subashi.php.

## Tests

```bash
composer install
./vendor/bin/phpunit
```

The `Firewall` reads its config and logger from the container in its constructor and does its work in private
methods, so the tests build one without invoking the constructor and reach the internals by reflection
(see `tests/Unit/TestCase.php`). That keeps them pointed at the real code rather than a
refactored-for-testing copy of it.

`SampleConfigRulesTest` is the one worth knowing about: it loads the rules that actually ship in
`sample.config.php` and fires realistic attack requests at them, then checks the same rules do **not** match
ordinary API traffic. If a shipped rule stops covering what its name claims, that test fails.

## What is a Kipchak Middleware?

Kipchak Middleware is a standard PHP PSR-15 middleware.

Middleware is a component that sits between the request and response of a web application, allowing for interception
and modification of the request and response data. In the context of Kipchak, middleware can be used to handle errors,
authentication, and other cross-cutting concerns that are common across one or more API endpoints.
